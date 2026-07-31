/*++

Module Name:

    system_time_resolver.c

Abstract:

    独立解析 Windows HAL 性能计数器描述符及活动函数槽。

Environment:

    Kernel-mode Driver Framework.

--*/

#include "system_time_internal.h"

#include <ntstrsafe.h>

/* 只检查导出函数开头的有限窗口，避免参考实现中的无界特征搜索。 */
#define KSW_SYSTEM_TIME_SCAN_BYTES             0x500UL
#define KSW_SYSTEM_TIME_SECONDARY_SLOT_OFFSET  0x48UL
#define KSW_SYSTEM_TIME_LEGACY_SLOT_OFFSET     0x70UL
#define KSW_SYSTEM_TIME_HANDLER_INDEX_OFFSET   0xBCUL
#define KSW_SYSTEM_TIME_INTERNAL_FLAGS_OFFSET  0xE0UL
#define KSW_SYSTEM_TIME_HANDLER_ROW_BYTES      16UL
#define KSW_SYSTEM_TIME_HANDLER_BUILD_MINIMUM  28000UL

NTSYSAPI
PVOID
NTAPI
RtlPcToFileHeader(
    _In_ PVOID PcValue,
    _Outptr_ PVOID* BaseOfImage
    );

/* 安全读取一个指针值；异常或用户地址一律按候选无效处理。 */
static
BOOLEAN
KswordARKSystemTimeReadPointer(
    _In_ const VOID* Address,
    _Out_ PVOID* Value
    )
{
    if (Address == NULL ||
        Value == NULL ||
        (ULONG_PTR)Address < (ULONG_PTR)MmSystemRangeStart) {
        return FALSE;
    }

    __try {
        RtlCopyMemory(Value, Address, sizeof(*Value));
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        *Value = NULL;
        return FALSE;
    }
    return TRUE;
}

/* 安全读取一个 ULONG 字段，供描述符索引和内部标志验证使用。 */
static
BOOLEAN
KswordARKSystemTimeReadUlong(
    _In_ const VOID* Address,
    _Out_ ULONG* Value
    )
{
    if (Address == NULL ||
        Value == NULL ||
        (ULONG_PTR)Address < (ULONG_PTR)MmSystemRangeStart) {
        return FALSE;
    }

    __try {
        RtlCopyMemory(Value, Address, sizeof(*Value));
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        *Value = 0UL;
        return FALSE;
    }
    return TRUE;
}

/* 仅接受属于已加载内核映像且当前可读的函数地址。 */
static
BOOLEAN
KswordARKSystemTimeIsKernelCodePointer(
    _In_opt_ PVOID Address
    )
{
    PVOID imageBase = NULL;

    if (Address == NULL ||
        (ULONG_PTR)Address < (ULONG_PTR)MmSystemRangeStart ||
        !MmIsAddressValid(Address)) {
        return FALSE;
    }

    return RtlPcToFileHeader(Address, &imageBase) != NULL &&
        imageBase != NULL;
}

/*
 * 读取一条 7 字节 RIP 相对指令的 disp32，并计算其目标地址。
 * 调用者已经验证 opcode 和 ModRM，返回值只负责地址运算。
 */
static
PVOID
KswordARKSystemTimeRipTarget(
    _In_ ULONG_PTR InstructionAddress,
    _In_reads_bytes_(7) const UCHAR* InstructionBytes
    )
{
    LONG displacement = 0L;
    ULONG_PTR nextInstruction = 0U;

    RtlCopyMemory(
        &displacement,
        InstructionBytes + 3,
        sizeof(displacement));
    nextInstruction = InstructionAddress + 7U;
    return (PVOID)(nextInstruction + (LONG_PTR)displacement);
}

/*
 * 验证一个可能的 HAL 计数器描述符。
 * 两个固定槽均指向内核代码时得分最高，可显著降低误识别概率。
 */
static
ULONG
KswordARKSystemTimeScoreDescriptor(
    _In_ PVOID Descriptor
    )
{
    PVOID secondaryFunction = NULL;
    PVOID legacyFunction = NULL;
    ULONG handlerIndex = 0UL;
    ULONG internalFlags = 0UL;
    ULONG score = 0UL;

    if (Descriptor == NULL ||
        (ULONG_PTR)Descriptor < (ULONG_PTR)MmSystemRangeStart) {
        return 0UL;
    }

    if (KswordARKSystemTimeReadPointer(
            (const UCHAR*)Descriptor +
                KSW_SYSTEM_TIME_SECONDARY_SLOT_OFFSET,
            &secondaryFunction) &&
        KswordARKSystemTimeIsKernelCodePointer(secondaryFunction)) {
        score += 4UL;
    }

    if (KswordARKSystemTimeReadPointer(
            (const UCHAR*)Descriptor +
                KSW_SYSTEM_TIME_LEGACY_SLOT_OFFSET,
            &legacyFunction) &&
        KswordARKSystemTimeIsKernelCodePointer(legacyFunction)) {
        score += 4UL;
    }

    if (KswordARKSystemTimeReadUlong(
            (const UCHAR*)Descriptor +
                KSW_SYSTEM_TIME_HANDLER_INDEX_OFFSET,
            &handlerIndex) &&
        handlerIndex < 256UL) {
        score += 1UL;
    }

    if (KswordARKSystemTimeReadUlong(
            (const UCHAR*)Descriptor +
                KSW_SYSTEM_TIME_INTERNAL_FLAGS_OFFSET,
            &internalFlags)) {
        UNREFERENCED_PARAMETER(internalFlags);
        score += 1UL;
    }

    return score;
}

/*
 * 从 KeQueryPerformanceCounter 中找出引用计数器描述符指针的 MOV。
 * 这里按指令语义枚举全部 RIP 相对 MOV，而不是硬编码目标寄存器。
 */
static
NTSTATUS
KswordARKSystemTimeFindDescriptor(
    _In_reads_bytes_(KSW_SYSTEM_TIME_SCAN_BYTES) const UCHAR* Code,
    _In_ ULONG_PTR CodeAddress,
    _Out_ PVOID* Descriptor
    )
{
    ULONG offset = 0UL;
    ULONG bestScore = 0UL;
    PVOID bestDescriptor = NULL;

    if (Code == NULL || Descriptor == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    for (offset = 0UL;
         offset + 7UL <= KSW_SYSTEM_TIME_SCAN_BYTES;
         ++offset) {
        PVOID storageAddress = NULL;
        PVOID candidateDescriptor = NULL;
        ULONG candidateScore = 0UL;

        /* REX.W + MOV r64,[RIP+disp32] 的 ModRM 低三位固定为 101。 */
        if (Code[offset] != 0x48U ||
            Code[offset + 1UL] != 0x8BU ||
            (Code[offset + 2UL] & 0xC7U) != 0x05U) {
            continue;
        }

        storageAddress = KswordARKSystemTimeRipTarget(
            CodeAddress + offset,
            Code + offset);
        if (!KswordARKSystemTimeReadPointer(
                storageAddress,
                &candidateDescriptor)) {
            continue;
        }

        candidateScore =
            KswordARKSystemTimeScoreDescriptor(candidateDescriptor);
        if (candidateScore > bestScore) {
            bestScore = candidateScore;
            bestDescriptor = candidateDescriptor;
        }
    }

    /* 两个函数槽和两个辅助字段全部验证通过时分数为 10。 */
    if (bestScore < 9UL || bestDescriptor == NULL) {
        *Descriptor = NULL;
        return STATUS_NOT_FOUND;
    }

    *Descriptor = bestDescriptor;
    return STATUS_SUCCESS;
}

/*
 * 新版 Windows 将活动计数器入口放进按时钟源索引的处理器表。
 * 枚举 LEA RCX,[RIP+disp32] 候选，并用表内函数指针反向验证。
 */
static
NTSTATUS
KswordARKSystemTimeFindHandlerSlot(
    _In_reads_bytes_(KSW_SYSTEM_TIME_SCAN_BYTES) const UCHAR* Code,
    _In_ ULONG_PTR CodeAddress,
    _In_ PVOID Descriptor,
    _Out_ volatile PVOID** HandlerSlot
    )
{
    ULONG handlerIndex = 0UL;
    ULONG offset = 0UL;

    if (Code == NULL ||
        Descriptor == NULL ||
        HandlerSlot == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (!KswordARKSystemTimeReadUlong(
            (const UCHAR*)Descriptor +
                KSW_SYSTEM_TIME_HANDLER_INDEX_OFFSET,
            &handlerIndex) ||
        handlerIndex >= 256UL) {
        return STATUS_DATA_ERROR;
    }

    for (offset = 0UL;
         offset + 7UL <= KSW_SYSTEM_TIME_SCAN_BYTES;
         ++offset) {
        PVOID tableAddress = NULL;
        volatile PVOID* candidateSlot = NULL;
        PVOID candidateFunction = NULL;

        /*
         * 新版路径先用 ADD RAX,RAX 形成 16 字节行偏移，随后才加载表基址。
         * 同时验证两条相邻指令，避免把同一函数中的无关 LEA 表误判成处理器表。
         */
        if (offset < 3UL ||
            Code[offset - 3UL] != 0x48U ||
            Code[offset - 2UL] != 0x03U ||
            Code[offset - 1UL] != 0xC0U ||
            Code[offset] != 0x48U ||
            Code[offset + 1UL] != 0x8DU ||
            Code[offset + 2UL] != 0x0DU) {
            continue;
        }

        tableAddress = KswordARKSystemTimeRipTarget(
            CodeAddress + offset,
            Code + offset);
        candidateSlot = (volatile PVOID*)(
            (UCHAR*)tableAddress +
            ((SIZE_T)handlerIndex *
                KSW_SYSTEM_TIME_HANDLER_ROW_BYTES));
        if (!KswordARKSystemTimeReadPointer(
                (const VOID*)candidateSlot,
                &candidateFunction) ||
            !KswordARKSystemTimeIsKernelCodePointer(
                candidateFunction)) {
            continue;
        }

        *HandlerSlot = candidateSlot;
        return STATUS_SUCCESS;
    }

    *HandlerSlot = NULL;
    return STATUS_NOT_FOUND;
}

/*
 * 公共解析入口只返回经过结构与函数归属验证的槽地址。
 * 当前不支持 x86，避免将 x64 RIP 相对规则错误套用到其它架构。
 */
NTSTATUS
KswordARKSystemTimeResolve(
    _Out_ KSWORD_ARK_SYSTEM_TIME_RESOLUTION* Resolution
    )
{
#if defined(_M_AMD64) || defined(_M_X64)
    UNICODE_STRING routineName = { 0 };
    PVOID queryCounterRoutine = NULL;
    UCHAR code[KSW_SYSTEM_TIME_SCAN_BYTES] = { 0 };
    RTL_OSVERSIONINFOW versionInfo = { 0 };
    PVOID descriptor = NULL;
    volatile PVOID* primarySlot = NULL;
    NTSTATUS status = STATUS_SUCCESS;

    if (Resolution == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    RtlZeroMemory(Resolution, sizeof(*Resolution));

    RtlInitUnicodeString(
        &routineName,
        L"KeQueryPerformanceCounter");
    queryCounterRoutine =
        MmGetSystemRoutineAddress(&routineName);
    if (queryCounterRoutine == NULL) {
        return STATUS_PROCEDURE_NOT_FOUND;
    }

    /* 内核映像代码页应常驻；SEH 仍防止异常映像状态穿透 IOCTL。 */
    __try {
        RtlCopyMemory(
            code,
            queryCounterRoutine,
            sizeof(code));
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return GetExceptionCode();
    }

    versionInfo.dwOSVersionInfoSize = sizeof(versionInfo);
    status = RtlGetVersion(&versionInfo);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    if (versionInfo.dwBuildNumber < 9200UL) {
        return STATUS_NOT_SUPPORTED;
    }

    status = KswordARKSystemTimeFindDescriptor(
        code,
        (ULONG_PTR)queryCounterRoutine,
        &descriptor);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    primarySlot = (volatile PVOID*)(
        (UCHAR*)descriptor +
        KSW_SYSTEM_TIME_LEGACY_SLOT_OFFSET);
    if (versionInfo.dwBuildNumber >=
        KSW_SYSTEM_TIME_HANDLER_BUILD_MINIMUM) {
        status = KswordARKSystemTimeFindHandlerSlot(
            code,
            (ULONG_PTR)queryCounterRoutine,
            descriptor,
            &primarySlot);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        Resolution->UsesHandlerTable = TRUE;
    }

    Resolution->PrimarySlot = primarySlot;
    Resolution->SecondarySlot = (volatile PVOID*)(
        (UCHAR*)descriptor +
        KSW_SYSTEM_TIME_SECONDARY_SLOT_OFFSET);
    Resolution->InternalFlags = (volatile LONG*)(
        (UCHAR*)descriptor +
        KSW_SYSTEM_TIME_INTERNAL_FLAGS_OFFSET);
    Resolution->CounterDescriptor = descriptor;
    Resolution->OsBuildNumber =
        versionInfo.dwBuildNumber;
    return STATUS_SUCCESS;
#else
    UNREFERENCED_PARAMETER(Resolution);
    return STATUS_NOT_SUPPORTED;
#endif
}
