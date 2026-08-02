/*++

Module Name:

    system_time_hyperv.c

Abstract:

    通过 Hyper-V 用户共享 QPC 页与现有 HAL 钩子共同实现系统全局变速。

Third-Party Notice:

    参考机制的许可证与归档说明位于：
    third_party/SystemWideTransmission/LICENSE.txt
    third_party/SystemWideTransmission/NOTICE.md

Environment:

    Kernel-mode Driver Framework.

--*/

#include "system_time_hyperv.h"

#include <intrin.h>

/*
 * MmMapIoSpace must not be used to create an alias for ordinary RAM. Keep the
 * experimental Hyper-V reference-page strategy fail-closed until it can use a
 * documented writable mapping contract without risking an uncorrectable MCE.
 */
#define KSW_SYSTEM_TIME_HYPERV_DIRECT_PAGE_MAPPING_ENABLED 0

/* SystemHypervisorSharedPageInformation 在当前 Windows ABI 中的编号为 197。 */
#define KSW_SYSTEM_TIME_HYPERV_SHARED_PAGE_INFORMATION 197UL

/* KUSER_SHARED_DATA 同时提供 QPC 快速路径标志和最终全局偏置。 */
#define KSW_SYSTEM_TIME_SHARED_DATA_KERNEL_BASE 0xFFFFF78000000000ULL
#define KSW_SYSTEM_TIME_QPC_BYPASS_OFFSET        0x3C6ULL
#define KSW_SYSTEM_TIME_QPC_BIAS_OFFSET          0x3B8ULL
#define KSW_SYSTEM_TIME_QPC_BYPASS_ENABLED_BIT   0x01U
#define KSW_SYSTEM_TIME_QPC_HYPERV_PAGE_BIT      0x02U

/* Hyper-V 共享页结构与本机 ntdll 快速路径使用的三个字段保持一致。 */
typedef struct _KSW_SYSTEM_TIME_HYPERV_SHARED_DATA
{
    volatile LONG64 TimeUpdateLock;
    volatile LONG64 QpcMultiplier;
    volatile LONG64 QpcBias;
} KSW_SYSTEM_TIME_HYPERV_SHARED_DATA;

/* 系统信息响应只返回每个进程中只读映射的共享页用户地址。 */
typedef struct _KSW_SYSTEM_TIME_HYPERV_PAGE_INFORMATION
{
    PVOID HypervisorSharedUserVa;
} KSW_SYSTEM_TIME_HYPERV_PAGE_INFORMATION;

/* 动态解析 ZwQuerySystemInformation，避免依赖未公开到 WDK 的枚举声明。 */
typedef NTSTATUS
(NTAPI* KSW_ZW_QUERY_SYSTEM_INFORMATION_ROUTINE)(
    _In_ ULONG SystemInformationClass,
    _Out_writes_bytes_opt_(SystemInformationLength) PVOID SystemInformation,
    _In_ ULONG SystemInformationLength,
    _Out_opt_ PULONG ReturnLength
    );

/* 一个稳定快照对应 ntdll 的“序列号前后相等”读取规则。 */
typedef struct _KSW_SYSTEM_TIME_HYPERV_SNAPSHOT
{
    ULONGLONG TimeUpdateLock;
    ULONGLONG Multiplier;
    ULONGLONG Bias;
} KSW_SYSTEM_TIME_HYPERV_SNAPSHOT;

/* 映射对象把用户地址、整页内核映射和字段地址绑定为一个释放单元。 */
typedef struct _KSW_SYSTEM_TIME_HYPERV_MAPPING
{
    PVOID MappedPage;
    volatile KSW_SYSTEM_TIME_HYPERV_SHARED_DATA* SharedData;
    PVOID SharedUserVa;
} KSW_SYSTEM_TIME_HYPERV_MAPPING;

/* 模块状态由自旋锁保护，以便控制线程与维护 DPC 安全交叉。 */
typedef struct _KSW_SYSTEM_TIME_HYPERV_STATE
{
    KSPIN_LOCK Lock;
    KSW_SYSTEM_TIME_HYPERV_MAPPING Mapping;
    KSW_SYSTEM_TIME_HYPERV_SNAPSHOT Original;
    KSW_SYSTEM_TIME_HYPERV_SNAPSHOT ActiveValue;
    ULONG Command;
    ULONG Factor;
    BOOLEAN Initialized;
    BOOLEAN Prepared;
    BOOLEAN Active;
    BOOLEAN Reserved;
} KSW_SYSTEM_TIME_HYPERV_STATE;

static KSW_SYSTEM_TIME_HYPERV_STATE g_KswordArkSystemTimeHypervState;

#if defined(_M_AMD64) || defined(_M_X64)
#pragma intrinsic(__cpuid)
#pragma intrinsic(__rdtsc)
#pragma intrinsic(__umulh)
#endif

/* 识别 Microsoft Hv 与 Hv#1 接口，拒绝把其它 hypervisor 当作 Hyper-V。 */
static
BOOLEAN
KswordARKSystemTimeHypervIsMicrosoftHypervisor(
    VOID
    )
{
#if defined(_M_AMD64) || defined(_M_X64)
    int registers[4] = { 0, 0, 0, 0 };

    __cpuid(registers, 1);
    if ((((ULONG)registers[2]) & 0x80000000UL) == 0UL) {
        return FALSE;
    }

    __cpuid(registers, (int)0x40000000UL);
    if ((ULONG)registers[0] < 0x40000001UL ||
        (ULONG)registers[1] != 0x7263694DUL ||
        (ULONG)registers[2] != 0x666F736FUL ||
        (ULONG)registers[3] != 0x76482074UL) {
        return FALSE;
    }

    __cpuid(registers, (int)0x40000001UL);
    return (ULONG)registers[0] == 0x31237648UL;
#else
    return FALSE;
#endif
}

/* 动态获取系统信息查询入口，缺少入口时按平台不支持处理。 */
static
KSW_ZW_QUERY_SYSTEM_INFORMATION_ROUTINE
KswordARKSystemTimeHypervResolveQueryRoutine(
    VOID
    )
{
    UNICODE_STRING routineName = { 0 };

    RtlInitUnicodeString(
        &routineName,
        L"ZwQuerySystemInformation");
    return (KSW_ZW_QUERY_SYSTEM_INFORMATION_ROUTINE)
        MmGetSystemRoutineAddress(&routineName);
}

/* 按 ntdll 的读取顺序取得稳定的锁、倍率和偏置组合。 */
static
NTSTATUS
KswordARKSystemTimeHypervReadSnapshot(
    _In_ volatile KSW_SYSTEM_TIME_HYPERV_SHARED_DATA* SharedData,
    _Out_ KSW_SYSTEM_TIME_HYPERV_SNAPSHOT* Snapshot
    )
{
    ULONG retryIndex = 0UL;

    if (SharedData == NULL || Snapshot == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    for (retryIndex = 0UL; retryIndex < 16UL; ++retryIndex) {
        const ULONGLONG firstLock = (ULONGLONG)
            InterlockedCompareExchange64(
                &SharedData->TimeUpdateLock,
                0LL,
                0LL);
        ULONGLONG multiplier = 0ULL;
        ULONGLONG bias = 0ULL;
        ULONGLONG secondLock = 0ULL;

        if ((ULONG)firstLock == 0UL) {
            continue;
        }

        multiplier = (ULONGLONG)
            InterlockedCompareExchange64(
                &SharedData->QpcMultiplier,
                0LL,
                0LL);
        bias = (ULONGLONG)
            InterlockedCompareExchange64(
                &SharedData->QpcBias,
                0LL,
                0LL);
        KeMemoryBarrier();
        secondLock = (ULONGLONG)
            InterlockedCompareExchange64(
                &SharedData->TimeUpdateLock,
                0LL,
                0LL);
        if (firstLock == secondLock && multiplier != 0ULL) {
            Snapshot->TimeUpdateLock = firstLock;
            Snapshot->Multiplier = multiplier;
            Snapshot->Bias = bias;
            return STATUS_SUCCESS;
        }
    }

    RtlZeroMemory(Snapshot, sizeof(*Snapshot));
    return STATUS_RETRY;
}

/* 比较倍率和偏置所有权；序列号变化本身不视为第三方冲突。 */
static
BOOLEAN
KswordARKSystemTimeHypervSameClockValue(
    _In_ const KSW_SYSTEM_TIME_HYPERV_SNAPSHOT* Left,
    _In_ const KSW_SYSTEM_TIME_HYPERV_SNAPSHOT* Right
    )
{
    return Left != NULL &&
        Right != NULL &&
        Left->Multiplier == Right->Multiplier &&
        Left->Bias == Right->Bias;
}

/* 验证用户地址位于单个 x64 用户页内，避免跨页物理映射误写。 */
static
BOOLEAN
KswordARKSystemTimeHypervValidateUserAddress(
    _In_ PVOID UserVa
    )
{
    const ULONGLONG address = (ULONGLONG)(ULONG_PTR)UserVa;
    const ULONGLONG pageOffset =
        address & ((ULONGLONG)PAGE_SIZE - 1ULL);

    return UserVa != NULL &&
        address <= 0x00007FFFFFFFFFFFULL &&
        pageOffset <= (ULONGLONG)PAGE_SIZE -
            sizeof(KSW_SYSTEM_TIME_HYPERV_SHARED_DATA) &&
        (address & (sizeof(LONG64) - 1ULL)) == 0ULL;
}

/* 查询共享页、验证快速路径位，并建立同缓存属性的整页可写物理映射。 */
static
NTSTATUS
KswordARKSystemTimeHypervOpenMapping(
    _Out_ KSW_SYSTEM_TIME_HYPERV_MAPPING* Mapping,
    _Out_ KSW_SYSTEM_TIME_HYPERV_SNAPSHOT* Snapshot
    )
{
#if !KSW_SYSTEM_TIME_HYPERV_DIRECT_PAGE_MAPPING_ENABLED
    if (Mapping == NULL || Snapshot == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    RtlZeroMemory(Mapping, sizeof(*Mapping));
    RtlZeroMemory(Snapshot, sizeof(*Snapshot));
    return STATUS_NOT_SUPPORTED;
#elif defined(_M_AMD64) || defined(_M_X64)
    KSW_ZW_QUERY_SYSTEM_INFORMATION_ROUTINE queryRoutine = NULL;
    KSW_SYSTEM_TIME_HYPERV_PAGE_INFORMATION pageInformation = { 0 };
    PHYSICAL_ADDRESS targetPhysical = { 0 };
    PHYSICAL_ADDRESS pagePhysical = { 0 };
    SIZE_T pageOffset = 0U;
    ULONG returnedLength = 0UL;
    volatile UCHAR* bypassByte = NULL;
    NTSTATUS status = STATUS_SUCCESS;

    if (Mapping == NULL || Snapshot == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    RtlZeroMemory(Mapping, sizeof(*Mapping));
    RtlZeroMemory(Snapshot, sizeof(*Snapshot));

    if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
        return STATUS_INVALID_DEVICE_STATE;
    }
    if (!KswordARKSystemTimeHypervIsMicrosoftHypervisor()) {
        return STATUS_NOT_SUPPORTED;
    }

    queryRoutine = KswordARKSystemTimeHypervResolveQueryRoutine();
    if (queryRoutine == NULL) {
        return STATUS_PROCEDURE_NOT_FOUND;
    }
    status = queryRoutine(
        KSW_SYSTEM_TIME_HYPERV_SHARED_PAGE_INFORMATION,
        &pageInformation,
        sizeof(pageInformation),
        &returnedLength);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    if (returnedLength != 0UL &&
        returnedLength < sizeof(pageInformation)) {
        return STATUS_INFO_LENGTH_MISMATCH;
    }
    if (!KswordARKSystemTimeHypervValidateUserAddress(
            pageInformation.HypervisorSharedUserVa) ||
        !MmIsAddressValid(
            pageInformation.HypervisorSharedUserVa)) {
        return STATUS_DEVICE_NOT_READY;
    }

    bypassByte = (volatile UCHAR*)(ULONG_PTR)(
        KSW_SYSTEM_TIME_SHARED_DATA_KERNEL_BASE +
        KSW_SYSTEM_TIME_QPC_BYPASS_OFFSET);
    if (!MmIsAddressValid((PVOID)bypassByte) ||
        ((*bypassByte &
            (KSW_SYSTEM_TIME_QPC_BYPASS_ENABLED_BIT |
             KSW_SYSTEM_TIME_QPC_HYPERV_PAGE_BIT)) !=
            (KSW_SYSTEM_TIME_QPC_BYPASS_ENABLED_BIT |
             KSW_SYSTEM_TIME_QPC_HYPERV_PAGE_BIT))) {
        return STATUS_DEVICE_NOT_READY;
    }

    targetPhysical = MmGetPhysicalAddress(
        pageInformation.HypervisorSharedUserVa);
    pageOffset = (SIZE_T)(
        (ULONGLONG)targetPhysical.QuadPart &
        ((ULONGLONG)PAGE_SIZE - 1ULL));
    pagePhysical.QuadPart =
        targetPhysical.QuadPart - (LONGLONG)pageOffset;
    Mapping->MappedPage = MmMapIoSpace(
        pagePhysical,
        PAGE_SIZE,
        MmCached);
    if (Mapping->MappedPage == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    Mapping->SharedData =
        (volatile KSW_SYSTEM_TIME_HYPERV_SHARED_DATA*)(
            (UCHAR*)Mapping->MappedPage + pageOffset);
    Mapping->SharedUserVa =
        pageInformation.HypervisorSharedUserVa;
    status = KswordARKSystemTimeHypervReadSnapshot(
        Mapping->SharedData,
        Snapshot);
    if (!NT_SUCCESS(status)) {
        MmUnmapIoSpace(Mapping->MappedPage, PAGE_SIZE);
        RtlZeroMemory(Mapping, sizeof(*Mapping));
        return status;
    }
    return STATUS_SUCCESS;
#else
    UNREFERENCED_PARAMETER(Mapping);
    UNREFERENCED_PARAMETER(Snapshot);
    return STATUS_NOT_SUPPORTED;
#endif
}

/* 解除临时或持久物理映射，并清空所有易误用的地址。 */
static
VOID
KswordARKSystemTimeHypervCloseMapping(
    _Inout_ KSW_SYSTEM_TIME_HYPERV_MAPPING* Mapping
    )
{
    if (Mapping == NULL) {
        return;
    }
    if (Mapping->MappedPage != NULL) {
        MmUnmapIoSpace(Mapping->MappedPage, PAGE_SIZE);
    }
    RtlZeroMemory(Mapping, sizeof(*Mapping));
}

/* 根据协议命令从原始 Hyper-V 倍率计算 N 或 1/N 的目标倍率。 */
static
NTSTATUS
KswordARKSystemTimeHypervComputeMultiplier(
    _In_ ULONGLONG OriginalMultiplier,
    _In_ ULONG Command,
    _In_ ULONG Factor,
    _Out_ ULONGLONG* Multiplier
    )
{
    if (Multiplier == NULL || OriginalMultiplier == 0ULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (Command == KSWORD_ARK_SYSTEM_TIME_COMMAND_SPEED_UP) {
        if (Factor == 0UL ||
            OriginalMultiplier > MAXULONGLONG / Factor) {
            return STATUS_INTEGER_OVERFLOW;
        }
        *Multiplier = OriginalMultiplier * Factor;
    } else if (Command ==
        KSWORD_ARK_SYSTEM_TIME_COMMAND_SLOW_DOWN) {
        if (Factor == 0UL) {
            return STATUS_INVALID_PARAMETER;
        }
        *Multiplier = OriginalMultiplier / Factor;
    } else if (Command ==
        KSWORD_ARK_SYSTEM_TIME_COMMAND_RESET) {
        *Multiplier = OriginalMultiplier;
    } else {
        return STATUS_INVALID_PARAMETER;
    }

    return *Multiplier == 0ULL
        ? STATUS_INTEGER_OVERFLOW
        : STATUS_SUCCESS;
}

/* 读取最终会被 ntdll 叠加到 Hyper-V 结果上的 KUSER_SHARED_DATA QPC 偏置。 */
static
NTSTATUS
KswordARKSystemTimeHypervReadGlobalQpcBias(
    _Out_ ULONGLONG* Bias
    )
{
    volatile ULONGLONG* qpcBias =
        (volatile ULONGLONG*)(ULONG_PTR)(
            KSW_SYSTEM_TIME_SHARED_DATA_KERNEL_BASE +
            KSW_SYSTEM_TIME_QPC_BIAS_OFFSET);

    if (Bias == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    if (!MmIsAddressValid((PVOID)qpcBias)) {
        return STATUS_ACCESS_VIOLATION;
    }

    __try {
        *Bias = *qpcBias;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        *Bias = 0ULL;
        return GetExceptionCode();
    }
    return STATUS_SUCCESS;
}

/* 以 10 毫秒容差核对共享页公式与未接管的内核 QPC，拒绝错误布局。 */
static
NTSTATUS
KswordARKSystemTimeHypervValidateClockFormula(
    _In_ const KSW_SYSTEM_TIME_HYPERV_SNAPSHOT* Snapshot
    )
{
#if defined(_M_AMD64) || defined(_M_X64)
    LARGE_INTEGER frequency = { 0 };
    LARGE_INTEGER kernelCounter = { 0 };
    ULONGLONG globalBias = 0ULL;
    ULONGLONG tsc = 0ULL;
    ULONGLONG sharedCounter = 0ULL;
    ULONGLONG difference = 0ULL;
    ULONGLONG tolerance = 0ULL;
    NTSTATUS status = STATUS_SUCCESS;

    if (Snapshot == NULL || Snapshot->Multiplier == 0ULL) {
        return STATUS_INVALID_PARAMETER;
    }
    status = KswordARKSystemTimeHypervReadGlobalQpcBias(
        &globalBias);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    tsc = __rdtsc();
    sharedCounter =
        __umulh(tsc, Snapshot->Multiplier) +
        Snapshot->Bias +
        globalBias;
    kernelCounter = KeQueryPerformanceCounter(&frequency);
    if (kernelCounter.QuadPart <= 0LL ||
        frequency.QuadPart <= 0LL) {
        return STATUS_DATA_ERROR;
    }

    difference = sharedCounter >=
        (ULONGLONG)kernelCounter.QuadPart
        ? sharedCounter - (ULONGLONG)kernelCounter.QuadPart
        : (ULONGLONG)kernelCounter.QuadPart - sharedCounter;
    tolerance = (ULONGLONG)frequency.QuadPart / 100ULL;
    if (tolerance < 1000ULL) {
        tolerance = 1000ULL;
    }
    return difference <= tolerance
        ? STATUS_SUCCESS
        : STATUS_DATA_ERROR;
#else
    UNREFERENCED_PARAMETER(Snapshot);
    return STATUS_NOT_SUPPORTED;
#endif
}
/*
 * 先把序列号原子置零，让 ntdll 临时回退到系统调用，再发布倍率和偏置。
 * 发布失败时恢复进入函数时观察到的值，不留下半写入共享页。
 */
static
NTSTATUS
KswordARKSystemTimeHypervWriteSnapshot(
    _In_ volatile KSW_SYSTEM_TIME_HYPERV_SHARED_DATA* SharedData,
    _In_ const KSW_SYSTEM_TIME_HYPERV_SNAPSHOT* Expected,
    _In_ ULONGLONG Multiplier,
    _In_ ULONGLONG Bias,
    _Out_ KSW_SYSTEM_TIME_HYPERV_SNAPSHOT* Published
    )
{
    KSW_SYSTEM_TIME_HYPERV_SNAPSHOT observed = { 0 };
    ULONGLONG publishLock = 0ULL;
    LONG64 observedLock = 0LL;
    BOOLEAN ownsUpdate = FALSE;
    NTSTATUS status = STATUS_SUCCESS;

    if (SharedData == NULL || Expected == NULL ||
        Published == NULL || Multiplier == 0ULL) {
        return STATUS_INVALID_PARAMETER;
    }
    RtlZeroMemory(Published, sizeof(*Published));

    publishLock = Expected->TimeUpdateLock + 1ULL;
    if ((ULONG)publishLock == 0UL) {
        ++publishLock;
    }
    observedLock = InterlockedCompareExchange64(
        &SharedData->TimeUpdateLock,
        0LL,
        (LONG64)Expected->TimeUpdateLock);
    if ((ULONGLONG)observedLock != Expected->TimeUpdateLock) {
        return STATUS_CONFLICTING_ADDRESSES;
    }
    ownsUpdate = TRUE;

    __try {
        KeMemoryBarrier();
        (void)InterlockedExchange64(
            &SharedData->QpcMultiplier,
            (LONG64)Multiplier);
        (void)InterlockedExchange64(
            &SharedData->QpcBias,
            (LONG64)Bias);
        KeMemoryBarrier();
        (void)InterlockedExchange64(
            &SharedData->TimeUpdateLock,
            (LONG64)publishLock);
        ownsUpdate = FALSE;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();
    }

    if (ownsUpdate) {
        (void)InterlockedExchange64(
            &SharedData->QpcMultiplier,
            (LONG64)Expected->Multiplier);
        (void)InterlockedExchange64(
            &SharedData->QpcBias,
            (LONG64)Expected->Bias);
        KeMemoryBarrier();
        (void)InterlockedExchange64(
            &SharedData->TimeUpdateLock,
            (LONG64)publishLock);
    }
    if (!NT_SUCCESS(status)) {
        return status;
    }

    /*
     * 先记录已经提交的所有权值；即使随后的稳定读遇到瞬时序列冲突，
     * 调用方仍可据此执行只恢复“本功能最后发布值”的安全回滚。
     */
    Published->TimeUpdateLock = publishLock;
    Published->Multiplier = Multiplier;
    Published->Bias = Bias;
    status = KswordARKSystemTimeHypervReadSnapshot(
        SharedData,
        &observed);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    if (observed.Multiplier != Multiplier ||
        observed.Bias != Bias) {
        return STATUS_DATA_ERROR;
    }
    *Published = observed;
    return STATUS_SUCCESS;
}

/*
 * 用已经接管的 KeQueryPerformanceCounter 作为连续目标，并反解共享页偏置。
 * high64(TSC * multiplier) + pageBias + globalBias 因而与内核虚拟 QPC 对齐。
 */
static
NTSTATUS
KswordARKSystemTimeHypervUpdateLocked(
    _In_ ULONG Command,
    _In_ ULONG Factor,
    _In_ BOOLEAN AllowOriginalValue
    )
{
#if defined(_M_AMD64) || defined(_M_X64)
    KSW_SYSTEM_TIME_HYPERV_SNAPSHOT current = { 0 };
    KSW_SYSTEM_TIME_HYPERV_SNAPSHOT published = { 0 };
    LARGE_INTEGER targetCounter = { 0 };
    ULONGLONG globalBias = 0ULL;
    ULONGLONG multiplier = 0ULL;
    ULONGLONG tsc = 0ULL;
    ULONGLONG pageBias = 0ULL;
    NTSTATUS status = STATUS_SUCCESS;

    if (!g_KswordArkSystemTimeHypervState.Prepared ||
        g_KswordArkSystemTimeHypervState.Mapping.SharedData == NULL) {
        return STATUS_DEVICE_NOT_READY;
    }

    status = KswordARKSystemTimeHypervReadSnapshot(
        g_KswordArkSystemTimeHypervState.Mapping.SharedData,
        &current);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    if (g_KswordArkSystemTimeHypervState.Active) {
        const BOOLEAN isActiveValue =
            KswordARKSystemTimeHypervSameClockValue(
                &current,
                &g_KswordArkSystemTimeHypervState.ActiveValue);
        const BOOLEAN isOriginalValue =
            KswordARKSystemTimeHypervSameClockValue(
                &current,
                &g_KswordArkSystemTimeHypervState.Original);

        if (!isActiveValue &&
            !(AllowOriginalValue && isOriginalValue)) {
            return STATUS_CONFLICTING_ADDRESSES;
        }
    } else if (!KswordARKSystemTimeHypervSameClockValue(
            &current,
            &g_KswordArkSystemTimeHypervState.Original)) {
        return STATUS_CONFLICTING_ADDRESSES;
    }

    status = KswordARKSystemTimeHypervComputeMultiplier(
        g_KswordArkSystemTimeHypervState.Original.Multiplier,
        Command,
        Factor,
        &multiplier);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    status = KswordARKSystemTimeHypervReadGlobalQpcBias(
        &globalBias);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    tsc = __rdtsc();
    targetCounter = KeQueryPerformanceCounter(NULL);
    if (targetCounter.QuadPart <= 0LL) {
        return STATUS_DATA_ERROR;
    }
    pageBias =
        (ULONGLONG)targetCounter.QuadPart -
        globalBias -
        __umulh(tsc, multiplier);
    status = KswordARKSystemTimeHypervWriteSnapshot(
        g_KswordArkSystemTimeHypervState.Mapping.SharedData,
        &current,
        multiplier,
        pageBias,
        &published);
    if (!NT_SUCCESS(status)) {
        if (published.TimeUpdateLock != 0ULL &&
            published.Multiplier == multiplier &&
            published.Bias == pageBias) {
            g_KswordArkSystemTimeHypervState.ActiveValue = published;
        }
        return status;
    }

    g_KswordArkSystemTimeHypervState.ActiveValue = published;
    g_KswordArkSystemTimeHypervState.Command = Command;
    g_KswordArkSystemTimeHypervState.Factor = Factor;
    return STATUS_SUCCESS;
#else
    UNREFERENCED_PARAMETER(Command);
    UNREFERENCED_PARAMETER(Factor);
    UNREFERENCED_PARAMETER(AllowOriginalValue);
    return STATUS_NOT_SUPPORTED;
#endif
}

VOID
KswordARKSystemTimeHypervInitialize(
    VOID
    )
{
    RtlZeroMemory(
        &g_KswordArkSystemTimeHypervState,
        sizeof(g_KswordArkSystemTimeHypervState));
    KeInitializeSpinLock(
        &g_KswordArkSystemTimeHypervState.Lock);
    g_KswordArkSystemTimeHypervState.Command =
        KSWORD_ARK_SYSTEM_TIME_COMMAND_RESET;
    g_KswordArkSystemTimeHypervState.Factor = 1UL;
    g_KswordArkSystemTimeHypervState.Initialized = TRUE;
}

NTSTATUS
KswordARKSystemTimeHypervQuery(
    _Out_ KSWORD_ARK_SYSTEM_TIME_HYPERV_DIAGNOSTICS* Diagnostics
    )
{
    KSW_SYSTEM_TIME_HYPERV_MAPPING temporaryMapping = { 0 };
    KSW_SYSTEM_TIME_HYPERV_SNAPSHOT temporarySnapshot = { 0 };
    KIRQL oldIrql = PASSIVE_LEVEL;
    NTSTATUS status = STATUS_SUCCESS;

    if (Diagnostics == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    RtlZeroMemory(Diagnostics, sizeof(*Diagnostics));
    if (KswordARKSystemTimeHypervIsMicrosoftHypervisor()) {
        Diagnostics->StateFlags |=
            KSWORD_ARK_SYSTEM_TIME_STATE_HYPERV_PRESENT;
    } else {
        return STATUS_NOT_SUPPORTED;
    }

    KeAcquireSpinLock(
        &g_KswordArkSystemTimeHypervState.Lock,
        &oldIrql);
    if (g_KswordArkSystemTimeHypervState.Prepared) {
        Diagnostics->StateFlags |=
            KSWORD_ARK_SYSTEM_TIME_STATE_HYPERV_SHARED_PAGE;
        if (g_KswordArkSystemTimeHypervState.Active) {
            Diagnostics->StateFlags |=
                KSWORD_ARK_SYSTEM_TIME_STATE_HYPERV_ACTIVE;
        }
        Diagnostics->SharedUserVa =
            g_KswordArkSystemTimeHypervState.Mapping.SharedUserVa;
        Diagnostics->OriginalMultiplier =
            g_KswordArkSystemTimeHypervState.Original.Multiplier;
        Diagnostics->OriginalBias =
            g_KswordArkSystemTimeHypervState.Original.Bias;
        status = KswordARKSystemTimeHypervReadSnapshot(
            g_KswordArkSystemTimeHypervState.Mapping.SharedData,
            &temporarySnapshot);
        KeReleaseSpinLock(
            &g_KswordArkSystemTimeHypervState.Lock,
            oldIrql);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        Diagnostics->TimeUpdateLock =
            temporarySnapshot.TimeUpdateLock;
        Diagnostics->CurrentMultiplier =
            temporarySnapshot.Multiplier;
        Diagnostics->CurrentBias = temporarySnapshot.Bias;
        return STATUS_SUCCESS;
    }
    KeReleaseSpinLock(
        &g_KswordArkSystemTimeHypervState.Lock,
        oldIrql);

    status = KswordARKSystemTimeHypervOpenMapping(
        &temporaryMapping,
        &temporarySnapshot);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    Diagnostics->StateFlags |=
        KSWORD_ARK_SYSTEM_TIME_STATE_HYPERV_SHARED_PAGE;
    Diagnostics->SharedUserVa =
        temporaryMapping.SharedUserVa;
    Diagnostics->TimeUpdateLock =
        temporarySnapshot.TimeUpdateLock;
    Diagnostics->OriginalMultiplier =
        temporarySnapshot.Multiplier;
    Diagnostics->OriginalBias = temporarySnapshot.Bias;
    Diagnostics->CurrentMultiplier =
        temporarySnapshot.Multiplier;
    Diagnostics->CurrentBias = temporarySnapshot.Bias;
    KswordARKSystemTimeHypervCloseMapping(
        &temporaryMapping);
    return STATUS_SUCCESS;
}

NTSTATUS
KswordARKSystemTimeHypervPrepare(
    VOID
    )
{
    KSW_SYSTEM_TIME_HYPERV_MAPPING mapping = { 0 };
    KSW_SYSTEM_TIME_HYPERV_SNAPSHOT snapshot = { 0 };
    KIRQL oldIrql = PASSIVE_LEVEL;
    NTSTATUS status = STATUS_SUCCESS;

    status = KswordARKSystemTimeHypervOpenMapping(
        &mapping,
        &snapshot);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    status = KswordARKSystemTimeHypervValidateClockFormula(
        &snapshot);
    if (!NT_SUCCESS(status)) {
        KswordARKSystemTimeHypervCloseMapping(&mapping);
        return status;
    }

    KeAcquireSpinLock(
        &g_KswordArkSystemTimeHypervState.Lock,
        &oldIrql);
    if (!g_KswordArkSystemTimeHypervState.Initialized ||
        g_KswordArkSystemTimeHypervState.Prepared) {
        status = STATUS_INVALID_DEVICE_STATE;
    } else {
        g_KswordArkSystemTimeHypervState.Mapping = mapping;
        g_KswordArkSystemTimeHypervState.Original = snapshot;
        g_KswordArkSystemTimeHypervState.ActiveValue = snapshot;
        g_KswordArkSystemTimeHypervState.Prepared = TRUE;
        g_KswordArkSystemTimeHypervState.Active = FALSE;
        RtlZeroMemory(&mapping, sizeof(mapping));
    }
    KeReleaseSpinLock(
        &g_KswordArkSystemTimeHypervState.Lock,
        oldIrql);

    KswordARKSystemTimeHypervCloseMapping(&mapping);
    return status;
}

NTSTATUS
KswordARKSystemTimeHypervActivate(
    _In_ ULONG Command,
    _In_ ULONG Factor
    )
{
    KIRQL oldIrql = PASSIVE_LEVEL;
    NTSTATUS status = STATUS_SUCCESS;

    KeAcquireSpinLock(
        &g_KswordArkSystemTimeHypervState.Lock,
        &oldIrql);
    if (!g_KswordArkSystemTimeHypervState.Prepared ||
        g_KswordArkSystemTimeHypervState.Active) {
        status = STATUS_INVALID_DEVICE_STATE;
    } else {
        status = KswordARKSystemTimeHypervUpdateLocked(
            Command,
            Factor,
            FALSE);
        if (NT_SUCCESS(status)) {
            g_KswordArkSystemTimeHypervState.Active = TRUE;
        }
    }
    KeReleaseSpinLock(
        &g_KswordArkSystemTimeHypervState.Lock,
        oldIrql);
    return status;
}

NTSTATUS
KswordARKSystemTimeHypervReconfigure(
    _In_ ULONG Command,
    _In_ ULONG Factor
    )
{
    KIRQL oldIrql = PASSIVE_LEVEL;
    NTSTATUS status = STATUS_SUCCESS;

    KeAcquireSpinLock(
        &g_KswordArkSystemTimeHypervState.Lock,
        &oldIrql);
    if (!g_KswordArkSystemTimeHypervState.Active) {
        status = STATUS_DEVICE_NOT_READY;
    } else {
        status = KswordARKSystemTimeHypervUpdateLocked(
            Command,
            Factor,
            FALSE);
    }
    KeReleaseSpinLock(
        &g_KswordArkSystemTimeHypervState.Lock,
        oldIrql);
    return status;
}

NTSTATUS
KswordARKSystemTimeHypervMaintain(
    VOID
    )
{
    KSW_SYSTEM_TIME_HYPERV_SNAPSHOT current = { 0 };
    KIRQL oldIrql = PASSIVE_LEVEL;
    NTSTATUS status = STATUS_SUCCESS;

    KeAcquireSpinLock(
        &g_KswordArkSystemTimeHypervState.Lock,
        &oldIrql);
    if (!g_KswordArkSystemTimeHypervState.Active) {
        status = STATUS_DEVICE_NOT_READY;
    } else {
        status = KswordARKSystemTimeHypervReadSnapshot(
            g_KswordArkSystemTimeHypervState.Mapping.SharedData,
            &current);
        if (NT_SUCCESS(status) &&
            KswordARKSystemTimeHypervSameClockValue(
                &current,
                &g_KswordArkSystemTimeHypervState.ActiveValue)) {
            g_KswordArkSystemTimeHypervState.ActiveValue.TimeUpdateLock =
                current.TimeUpdateLock;
        } else if (NT_SUCCESS(status) &&
            KswordARKSystemTimeHypervSameClockValue(
                &current,
                &g_KswordArkSystemTimeHypervState.Original)) {
            status = KswordARKSystemTimeHypervUpdateLocked(
                g_KswordArkSystemTimeHypervState.Command,
                g_KswordArkSystemTimeHypervState.Factor,
                TRUE);
        } else if (NT_SUCCESS(status)) {
            status = STATUS_CONFLICTING_ADDRESSES;
        }
    }
    KeReleaseSpinLock(
        &g_KswordArkSystemTimeHypervState.Lock,
        oldIrql);
    return status;
}

NTSTATUS
KswordARKSystemTimeHypervRestore(
    VOID
    )
{
    KSW_SYSTEM_TIME_HYPERV_MAPPING mapping = { 0 };
    KSW_SYSTEM_TIME_HYPERV_SNAPSHOT current = { 0 };
    KSW_SYSTEM_TIME_HYPERV_SNAPSHOT published = { 0 };
    KIRQL oldIrql = PASSIVE_LEVEL;
    NTSTATUS status = STATUS_SUCCESS;

    KeAcquireSpinLock(
        &g_KswordArkSystemTimeHypervState.Lock,
        &oldIrql);
    if (g_KswordArkSystemTimeHypervState.Prepared) {
        status = KswordARKSystemTimeHypervReadSnapshot(
            g_KswordArkSystemTimeHypervState.Mapping.SharedData,
            &current);
        if (NT_SUCCESS(status) &&
            KswordARKSystemTimeHypervSameClockValue(
                &current,
                &g_KswordArkSystemTimeHypervState.ActiveValue) &&
            !KswordARKSystemTimeHypervSameClockValue(
                &current,
                &g_KswordArkSystemTimeHypervState.Original)) {
            status = KswordARKSystemTimeHypervWriteSnapshot(
                g_KswordArkSystemTimeHypervState.Mapping.SharedData,
                &current,
                g_KswordArkSystemTimeHypervState.Original.Multiplier,
                g_KswordArkSystemTimeHypervState.Original.Bias,
                &published);
        } else if (NT_SUCCESS(status) &&
            !KswordARKSystemTimeHypervSameClockValue(
                &current,
                &g_KswordArkSystemTimeHypervState.Original)) {
            status = STATUS_CONFLICTING_ADDRESSES;
        }

        mapping = g_KswordArkSystemTimeHypervState.Mapping;
        RtlZeroMemory(
            &g_KswordArkSystemTimeHypervState.Mapping,
            sizeof(g_KswordArkSystemTimeHypervState.Mapping));
        RtlZeroMemory(
            &g_KswordArkSystemTimeHypervState.Original,
            sizeof(g_KswordArkSystemTimeHypervState.Original));
        RtlZeroMemory(
            &g_KswordArkSystemTimeHypervState.ActiveValue,
            sizeof(g_KswordArkSystemTimeHypervState.ActiveValue));
        g_KswordArkSystemTimeHypervState.Command =
            KSWORD_ARK_SYSTEM_TIME_COMMAND_RESET;
        g_KswordArkSystemTimeHypervState.Factor = 1UL;
        g_KswordArkSystemTimeHypervState.Prepared = FALSE;
        g_KswordArkSystemTimeHypervState.Active = FALSE;
    }
    KeReleaseSpinLock(
        &g_KswordArkSystemTimeHypervState.Lock,
        oldIrql);

    KswordARKSystemTimeHypervCloseMapping(&mapping);
    return status;
}