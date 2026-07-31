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
#define KSW_SYSTEM_TIME_WINDOWS_10_BUILD_MAX   19045UL
#define KSW_SYSTEM_TIME_HANDLER_BUILD_MINIMUM  28000UL

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

/*
 * HAL 计数器入口在部分配置中可能落在运行时生成的内核代码区，
 * 因此不能用 RtlPcToFileHeader 是否命中映像作为必要条件。
 */
static
BOOLEAN
KswordARKSystemTimeIsKernelCodePointer(
    _In_opt_ PVOID Address
    )
{
    return Address != NULL &&
        (ULONG_PTR)Address >= (ULONG_PTR)MmSystemRangeStart &&
        MmIsAddressValid(Address);
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
 * 验证由版本对应的 KeQueryPerformanceCounter 特征直接引用的描述符。
 * 精确特征已经提供结构语义，这里只验证后续会读写的字段，不再要求
 * 函数入口必须属于可由 RtlPcToFileHeader 反查的已加载映像。
 */
static
BOOLEAN
KswordARKSystemTimeValidateDescriptor(
    _In_ PVOID Descriptor,
    _In_ ULONG OsBuildNumber
    )
{
    PVOID secondaryFunction = NULL;
    PVOID legacyFunction = NULL;
    ULONG handlerIndex = 0UL;
    ULONG internalFlags = 0UL;

    if (Descriptor == NULL ||
        (ULONG_PTR)Descriptor < (ULONG_PTR)MmSystemRangeStart ||
        ((ULONG_PTR)Descriptor & (sizeof(PVOID) - 1U)) != 0U) {
        return FALSE;
    }

    if (!KswordARKSystemTimeReadPointer(
            (const UCHAR*)Descriptor +
                KSW_SYSTEM_TIME_SECONDARY_SLOT_OFFSET,
            &secondaryFunction) ||
        !KswordARKSystemTimeReadPointer(
            (const UCHAR*)Descriptor +
                KSW_SYSTEM_TIME_LEGACY_SLOT_OFFSET,
            &legacyFunction) ||
        !KswordARKSystemTimeIsKernelCodePointer(secondaryFunction) ||
        !KswordARKSystemTimeIsKernelCodePointer(legacyFunction)) {
        return FALSE;
    }

    if (!KswordARKSystemTimeReadUlong(
            (const UCHAR*)Descriptor +
                KSW_SYSTEM_TIME_INTERNAL_FLAGS_OFFSET,
            &internalFlags)) {
        return FALSE;
    }
    UNREFERENCED_PARAMETER(internalFlags);

    if (OsBuildNumber >= KSW_SYSTEM_TIME_HANDLER_BUILD_MINIMUM &&
        (!KswordARKSystemTimeReadUlong(
            (const UCHAR*)Descriptor +
                KSW_SYSTEM_TIME_HANDLER_INDEX_OFFSET,
            &handlerIndex) ||
         handlerIndex >= 256UL)) {
        return FALSE;
    }

    return TRUE;
}

/*
 * 按原始机制的系统版本分支定位描述符引用：
 * Windows 8/10 使用 MOV RDI,[RIP+disp32]，Windows 11 使用
 * MOV RSI,[RIP+disp32]。扫描保持有界，并验证实际会访问的字段。
 */
static
NTSTATUS
KswordARKSystemTimeFindDescriptor(
    _In_reads_bytes_(KSW_SYSTEM_TIME_SCAN_BYTES) const UCHAR* Code,
    _In_ ULONG_PTR CodeAddress,
    _In_ ULONG OsBuildNumber,
    _Out_ PVOID* Descriptor
    )
{
    ULONG offset = 0UL;
    const UCHAR expectedModRm =
        OsBuildNumber <= KSW_SYSTEM_TIME_WINDOWS_10_BUILD_MAX
        ? 0x3DU
        : 0x35U;

    if (Code == NULL || Descriptor == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *Descriptor = NULL;

    for (offset = 0UL;
         offset + 7UL <= KSW_SYSTEM_TIME_SCAN_BYTES;
         ++offset) {
        PVOID storageAddress = NULL;
        PVOID candidateDescriptor = NULL;

        /* 仅接受当前系统版本对应的完整三字节指令前缀。 */
        if (Code[offset] != 0x48U ||
            Code[offset + 1UL] != 0x8BU ||
            Code[offset + 2UL] != expectedModRm) {
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

        if (KswordARKSystemTimeValidateDescriptor(
                candidateDescriptor,
                OsBuildNumber)) {
            *Descriptor = candidateDescriptor;
            return STATUS_SUCCESS;
        }
    }

    return STATUS_NOT_FOUND;
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
    Resolution->OsBuildNumber = versionInfo.dwBuildNumber;

    status = KswordARKSystemTimeFindDescriptor(
        code,
        (ULONG_PTR)queryCounterRoutine,
        versionInfo.dwBuildNumber,
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
    return STATUS_SUCCESS;
#else
    UNREFERENCED_PARAMETER(Resolution);
    return STATUS_NOT_SUPPORTED;
#endif
}
