/*++

Module Name:

    system_time_runtime.c

Abstract:

    以连续虚拟性能计数器实现系统全局加速、减速与可恢复接管。

Environment:

    Kernel-mode Driver Framework.

--*/

#include "system_time_internal.h"
#include "system_time_counter.h"

#include <intrin.h>

/* HAL 计数器回调在当前 x64 Windows 上不接收参数并返回 64 位计数。 */
typedef LONGLONG
(*KSW_SYSTEM_TIME_COUNTER_ROUTINE)(
    VOID
    );

/* QPC 旁路位位于 KUSER_SHARED_DATA 的长期兼容字段。 */
#define KSW_SYSTEM_TIME_SHARED_DATA_KERNEL_BASE 0xFFFFF78000000000ULL
#define KSW_SYSTEM_TIME_QPC_BYPASS_OFFSET        0x3C6ULL
#define KSW_SYSTEM_TIME_QPC_BYPASS_BIT           0x01U
#define KSW_SYSTEM_TIME_QPC_BYPASS_CLEAR_MASK    ((CHAR)-2)
#define KSW_SYSTEM_TIME_INTERNAL_BYPASS_BIT       0x00010000L

/* 周期维护只在槽被系统恢复为原函数时重新接管，不覆盖未知第三方。 */
#define KSW_SYSTEM_TIME_MAINTENANCE_PERIOD_MS 1000L
#define KSW_SYSTEM_TIME_DRAIN_RETRY_COUNT      100UL
#define KSW_SYSTEM_TIME_DRAIN_DELAY_100NS      (-10000LL)

#if defined(_M_AMD64) || defined(_M_X64)
#pragma intrinsic(_InterlockedAnd8)
#pragma intrinsic(_InterlockedOr8)
#endif

/* 全局状态由控制锁保护；标为 volatile 的字段还会被 DPC 或钩子读取。 */
typedef struct _KSWORD_ARK_SYSTEM_TIME_STATE
{
    EX_PUSH_LOCK ControlLock;
    KTIMER MaintenanceTimer;
    KDPC MaintenanceDpc;
    KSWORD_ARK_SYSTEM_TIME_RESOLUTION Resolution;
    PVOID OriginalPrimary;
    PVOID OriginalSecondary;
    volatile LONG Initialized;
    volatile LONG Active;
    volatile LONG ConflictDetected;
    volatile LONG Generation;
    volatile LONG RuntimeStatus;
    volatile LONG LastStatus;
    ULONG LastCommand;
    ULONG Factor;
    ULONG ResolutionMode;
    BOOLEAN Resolved;
    BOOLEAN OriginalQpcBypassBit;
    BOOLEAN OriginalInternalBypassBit;
    BOOLEAN PatchBitsCaptured;
} KSWORD_ARK_SYSTEM_TIME_STATE;

static KSWORD_ARK_SYSTEM_TIME_STATE g_KswordArkSystemTimeState;

/* 返回内核态 KUSER_SHARED_DATA 中 QPC 旁路字节的可写别名。 */
static
volatile CHAR*
KswordARKSystemTimeQpcBypassByte(
    VOID
    )
{
    return (volatile CHAR*)(ULONG_PTR)(
        KSW_SYSTEM_TIME_SHARED_DATA_KERNEL_BASE +
        KSW_SYSTEM_TIME_QPC_BYPASS_OFFSET);
}

/* 读取一个函数指针槽；SEH 防止异常解析状态造成系统崩溃。 */
static
BOOLEAN
KswordARKSystemTimeReadSlot(
    _In_ volatile PVOID* Slot,
    _Out_ PVOID* Value
    )
{
    if (Slot == NULL || Value == NULL) {
        return FALSE;
    }

    __try {
        *Value = *(PVOID volatile*)Slot;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        *Value = NULL;
        return FALSE;
    }
    return TRUE;
}

/* 仅当槽仍指向预期原函数时安装本功能钩子，未知指针视为冲突。 */
static
BOOLEAN
KswordARKSystemTimePatchSlot(
    _In_ volatile PVOID* Slot,
    _In_ PVOID ExpectedOriginal
    )
{
    PVOID observed = NULL;

    if (Slot == NULL || ExpectedOriginal == NULL) {
        return FALSE;
    }

    observed = InterlockedCompareExchangePointer(
        (PVOID volatile*)Slot,
        KswordARKSystemTimeCounterHookAddress(),
        ExpectedOriginal);
    return observed == ExpectedOriginal ||
        observed == KswordARKSystemTimeCounterHookAddress();
}

/* 只恢复仍由本功能持有的槽，避免覆盖后来安装的第三方钩子。 */
static
BOOLEAN
KswordARKSystemTimeRestoreSlot(
    _In_ volatile PVOID* Slot,
    _In_ PVOID Original
    )
{
    PVOID observed = NULL;

    if (Slot == NULL || Original == NULL) {
        return FALSE;
    }

    observed = InterlockedCompareExchangePointer(
        (PVOID volatile*)Slot,
        Original,
        KswordARKSystemTimeCounterHookAddress());
    return observed == KswordARKSystemTimeCounterHookAddress() ||
        observed == Original;
}

/* 保存并关闭用户态 QPC 旁路位和 HAL 内部旁路位。 */
static
NTSTATUS
KswordARKSystemTimeDisableBypassesLocked(
    VOID
    )
{
#if defined(_M_AMD64) || defined(_M_X64)
    volatile CHAR* qpcBypass = NULL;
    CHAR oldQpcByte = 0;
    LONG oldInternalFlags = 0L;

    qpcBypass = KswordARKSystemTimeQpcBypassByte();
    if (!MmIsAddressValid((PVOID)qpcBypass) ||
        g_KswordArkSystemTimeState.Resolution.InternalFlags == NULL) {
        return STATUS_ACCESS_VIOLATION;
    }

    __try {
        oldQpcByte = _InterlockedAnd8(
            qpcBypass,
            KSW_SYSTEM_TIME_QPC_BYPASS_CLEAR_MASK);
        oldInternalFlags = InterlockedAnd(
            g_KswordArkSystemTimeState.Resolution.InternalFlags,
            ~KSW_SYSTEM_TIME_INTERNAL_BYPASS_BIT);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return GetExceptionCode();
    }

    g_KswordArkSystemTimeState.OriginalQpcBypassBit =
        (oldQpcByte &
            KSW_SYSTEM_TIME_QPC_BYPASS_BIT) != 0;
    g_KswordArkSystemTimeState.OriginalInternalBypassBit =
        (oldInternalFlags &
            KSW_SYSTEM_TIME_INTERNAL_BYPASS_BIT) != 0;
    g_KswordArkSystemTimeState.PatchBitsCaptured = TRUE;
    KeMemoryBarrier();
    return STATUS_SUCCESS;
#else
    return STATUS_NOT_SUPPORTED;
#endif
}

/* 按激活前快照恢复两个旁路位，不改写同字节中的其它系统标志。 */
static
VOID
KswordARKSystemTimeRestoreBypasses(
    VOID
    )
{
#if defined(_M_AMD64) || defined(_M_X64)
    volatile CHAR* qpcBypass = NULL;

    if (!g_KswordArkSystemTimeState.PatchBitsCaptured) {
        return;
    }

    qpcBypass = KswordARKSystemTimeQpcBypassByte();
    __try {
        if (g_KswordArkSystemTimeState.OriginalQpcBypassBit) {
            (void)_InterlockedOr8(
                qpcBypass,
                (CHAR)KSW_SYSTEM_TIME_QPC_BYPASS_BIT);
        } else {
            (void)_InterlockedAnd8(
                qpcBypass,
                KSW_SYSTEM_TIME_QPC_BYPASS_CLEAR_MASK);
        }

        if (g_KswordArkSystemTimeState.OriginalInternalBypassBit) {
            (void)InterlockedOr(
                g_KswordArkSystemTimeState.Resolution.InternalFlags,
                KSW_SYSTEM_TIME_INTERNAL_BYPASS_BIT);
        } else {
            (void)InterlockedAnd(
                g_KswordArkSystemTimeState.Resolution.InternalFlags,
                ~KSW_SYSTEM_TIME_INTERNAL_BYPASS_BIT);
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        InterlockedExchange(
            &g_KswordArkSystemTimeState.ConflictDetected,
            1L);
    }

    g_KswordArkSystemTimeState.PatchBitsCaptured = FALSE;
#endif
}

/* 解析并缓存当前构建的两个计数器槽；失败时保留可查询状态码。 */
static
NTSTATUS
KswordARKSystemTimeResolveLocked(
    VOID
    )
{
    NTSTATUS status = STATUS_SUCCESS;

    if (g_KswordArkSystemTimeState.Resolved) {
        return STATUS_SUCCESS;
    }

    status = KswordARKSystemTimeResolve(
        g_KswordArkSystemTimeState.ResolutionMode,
        &g_KswordArkSystemTimeState.Resolution);
    if (!NT_SUCCESS(status)) {
        InterlockedExchange(
            &g_KswordArkSystemTimeState.RuntimeStatus,
            KSWORD_ARK_SYSTEM_TIME_STATUS_RESOLVE_FAILED);
        InterlockedExchange(
            &g_KswordArkSystemTimeState.LastStatus,
            status);
        return status;
    }

    g_KswordArkSystemTimeState.Resolved = TRUE;
    InterlockedExchange(
        &g_KswordArkSystemTimeState.RuntimeStatus,
        KSWORD_ARK_SYSTEM_TIME_STATUS_OK);
    InterlockedExchange(
        &g_KswordArkSystemTimeState.LastStatus,
        STATUS_SUCCESS);
    return STATUS_SUCCESS;
}

/*
 * 切换解析方案前必须处于未接管状态。
 * 清除旧解析和旁路快照，确保下一次启用按新方案重新定位并重新取证。
 */
static
NTSTATUS
KswordARKSystemTimeSelectResolutionModeLocked(
    _In_ ULONG ResolutionMode
    )
{
    if (ResolutionMode !=
            KSWORD_ARK_SYSTEM_TIME_RESOLUTION_ORIGINAL_COMPAT &&
        ResolutionMode !=
            KSWORD_ARK_SYSTEM_TIME_RESOLUTION_GUARDED) {
        return STATUS_INVALID_PARAMETER;
    }

    if (ResolutionMode ==
        g_KswordArkSystemTimeState.ResolutionMode) {
        return STATUS_SUCCESS;
    }
    if (InterlockedCompareExchange(
            &g_KswordArkSystemTimeState.Active,
            0L,
            0L) != 0L) {
        return STATUS_DEVICE_BUSY;
    }

    RtlZeroMemory(
        &g_KswordArkSystemTimeState.Resolution,
        sizeof(g_KswordArkSystemTimeState.Resolution));
    g_KswordArkSystemTimeState.OriginalPrimary = NULL;
    g_KswordArkSystemTimeState.OriginalSecondary = NULL;
    g_KswordArkSystemTimeState.ResolutionMode = ResolutionMode;
    g_KswordArkSystemTimeState.Resolved = FALSE;
    g_KswordArkSystemTimeState.PatchBitsCaptured = FALSE;
    return STATUS_SUCCESS;
}

/* 读取两个槽的当前函数，激活前将它们作为可恢复基线。 */
static
NTSTATUS
KswordARKSystemTimeCaptureOriginalsLocked(
    VOID
    )
{
    PVOID primary = NULL;
    PVOID secondary = NULL;

    if (!KswordARKSystemTimeReadSlot(
            g_KswordArkSystemTimeState.Resolution.PrimarySlot,
            &primary) ||
        !KswordARKSystemTimeReadSlot(
            g_KswordArkSystemTimeState.Resolution.SecondarySlot,
            &secondary) ||
        primary == NULL ||
        secondary == NULL ||
        primary == KswordARKSystemTimeCounterHookAddress() ||
        secondary == KswordARKSystemTimeCounterHookAddress()) {
        return STATUS_CONFLICTING_ADDRESSES;
    }

    g_KswordArkSystemTimeState.OriginalPrimary = primary;
    g_KswordArkSystemTimeState.OriginalSecondary = secondary;
    return STATUS_SUCCESS;
}

/* 构造当前状态位；调用者持有控制锁或处在单线程初始化阶段。 */
static
ULONG
KswordARKSystemTimeStateFlagsLocked(
    VOID
    )
{
    ULONG flags = 0UL;
    PVOID primary = NULL;
    PVOID secondary = NULL;

    if (InterlockedCompareExchange(
            &g_KswordArkSystemTimeState.Initialized,
            0L,
            0L) != 0L) {
        flags |= KSWORD_ARK_SYSTEM_TIME_STATE_INITIALIZED;
    }
    if (g_KswordArkSystemTimeState.Resolved) {
        flags |= KSWORD_ARK_SYSTEM_TIME_STATE_SUPPORTED;
    }
    if (InterlockedCompareExchange(
            &g_KswordArkSystemTimeState.Active,
            0L,
            0L) != 0L) {
        flags |= KSWORD_ARK_SYSTEM_TIME_STATE_ACTIVE;
        if (g_KswordArkSystemTimeState.LastCommand ==
            KSWORD_ARK_SYSTEM_TIME_COMMAND_SPEED_UP) {
            flags |= KSWORD_ARK_SYSTEM_TIME_STATE_SPEED_UP;
        } else if (g_KswordArkSystemTimeState.LastCommand ==
            KSWORD_ARK_SYSTEM_TIME_COMMAND_SLOW_DOWN) {
            flags |= KSWORD_ARK_SYSTEM_TIME_STATE_SLOW_DOWN;
        }

        if (KswordARKSystemTimeReadSlot(
            g_KswordArkSystemTimeState.Resolution.PrimarySlot,
            &primary) &&
            primary ==
                KswordARKSystemTimeCounterHookAddress()) {
            flags |=
                KSWORD_ARK_SYSTEM_TIME_STATE_PRIMARY_HOOKED;
        }
        if (KswordARKSystemTimeReadSlot(
            g_KswordArkSystemTimeState.Resolution.SecondarySlot,
            &secondary) &&
            secondary ==
                KswordARKSystemTimeCounterHookAddress()) {
            flags |=
                KSWORD_ARK_SYSTEM_TIME_STATE_SECONDARY_HOOKED;
        }
        flags |=
            KSWORD_ARK_SYSTEM_TIME_STATE_QPC_BYPASS_DISABLED |
            KSWORD_ARK_SYSTEM_TIME_STATE_INTERNAL_FLAG_PATCHED;
    }
    if (g_KswordArkSystemTimeState.Resolution.UsesHandlerTable) {
        flags |= KSWORD_ARK_SYSTEM_TIME_STATE_HANDLER_TABLE;
    }
    if (InterlockedCompareExchange(
            &g_KswordArkSystemTimeState.ConflictDetected,
            0L,
            0L) != 0L) {
        flags |= KSWORD_ARK_SYSTEM_TIME_STATE_CONFLICT;
    }
    return flags;
}

/* 将当前状态写入固定查询响应，调用者必须持有控制锁。 */
static
VOID
KswordARKSystemTimeFillQueryLocked(
    _Out_ KSWORD_ARK_QUERY_SYSTEM_TIME_RESPONSE* Response
    )
{
    LARGE_INTEGER counter = { 0 };

    RtlZeroMemory(Response, sizeof(*Response));
    Response->version =
        KSWORD_ARK_SYSTEM_TIME_PROTOCOL_VERSION;
    Response->size = sizeof(*Response);
    Response->status = (ULONG)InterlockedCompareExchange(
        &g_KswordArkSystemTimeState.RuntimeStatus,
        0L,
        0L);
    Response->stateFlags =
        KswordARKSystemTimeStateFlagsLocked();
    Response->generation = (ULONG)InterlockedCompareExchange(
        &g_KswordArkSystemTimeState.Generation,
        0L,
        0L);
    Response->command =
        g_KswordArkSystemTimeState.LastCommand;
    Response->factor =
        g_KswordArkSystemTimeState.Factor;
    Response->osBuildNumber =
        g_KswordArkSystemTimeState.Resolution.OsBuildNumber;
    Response->lastStatus = InterlockedCompareExchange(
        &g_KswordArkSystemTimeState.LastStatus,
        0L,
        0L);
    Response->resolutionMode =
        g_KswordArkSystemTimeState.ResolutionMode;

    counter = KeQueryPerformanceCounter(NULL);
    Response->counterValue =
        (ULONGLONG)counter.QuadPart;
    Response->counterSourceAddress =
        (ULONGLONG)(ULONG_PTR)
            g_KswordArkSystemTimeState.Resolution.CounterDescriptor;
    Response->primarySlotAddress =
        (ULONGLONG)(ULONG_PTR)
            g_KswordArkSystemTimeState.Resolution.PrimarySlot;
    Response->secondarySlotAddress =
        (ULONGLONG)(ULONG_PTR)
            g_KswordArkSystemTimeState.Resolution.SecondarySlot;
}

/*
 * 停止维护并恢复接管状态。
 * 等待在途钩子退出后，驱动映像才可以安全卸载。
 */
static
NTSTATUS
KswordARKSystemTimeDeactivateLocked(
    VOID
    )
{
    BOOLEAN primaryRestored = TRUE;
    BOOLEAN secondaryRestored = TRUE;
    ULONG retryIndex = 0UL;
    LARGE_INTEGER delay = { 0 };

    InterlockedExchange(
        &g_KswordArkSystemTimeState.Active,
        0L);
    (void)KeCancelTimer(
        &g_KswordArkSystemTimeState.MaintenanceTimer);
    KeFlushQueuedDpcs();

    if (g_KswordArkSystemTimeState.OriginalPrimary != NULL) {
        primaryRestored = KswordARKSystemTimeRestoreSlot(
            g_KswordArkSystemTimeState.Resolution.PrimarySlot,
            g_KswordArkSystemTimeState.OriginalPrimary);
    }
    if (g_KswordArkSystemTimeState.OriginalSecondary != NULL) {
        secondaryRestored = KswordARKSystemTimeRestoreSlot(
            g_KswordArkSystemTimeState.Resolution.SecondarySlot,
            g_KswordArkSystemTimeState.OriginalSecondary);
    }

    KswordARKSystemTimeRestoreBypasses();
    KeMemoryBarrier();
    delay.QuadPart =
        KSW_SYSTEM_TIME_DRAIN_DELAY_100NS;
    for (retryIndex = 0UL;
         retryIndex < KSW_SYSTEM_TIME_DRAIN_RETRY_COUNT;
         ++retryIndex) {
        if (KswordARKSystemTimeCounterInFlight() == 0L) {
            break;
        }
        (void)KeDelayExecutionThread(
            KernelMode,
            FALSE,
            &delay);
    }

    g_KswordArkSystemTimeState.LastCommand =
        KSWORD_ARK_SYSTEM_TIME_COMMAND_RESET;
    g_KswordArkSystemTimeState.Factor = 1UL;
    KswordARKSystemTimeCounterReset();

    if (!primaryRestored ||
        !secondaryRestored ||
        retryIndex == KSW_SYSTEM_TIME_DRAIN_RETRY_COUNT) {
        InterlockedExchange(
            &g_KswordArkSystemTimeState.ConflictDetected,
            1L);
        InterlockedExchange(
            &g_KswordArkSystemTimeState.RuntimeStatus,
            KSWORD_ARK_SYSTEM_TIME_STATUS_CONFLICT);
        InterlockedExchange(
            &g_KswordArkSystemTimeState.LastStatus,
            STATUS_CONFLICTING_ADDRESSES);
        return STATUS_CONFLICTING_ADDRESSES;
    }

    InterlockedExchange(
        &g_KswordArkSystemTimeState.ConflictDetected,
        0L);
    InterlockedExchange(
        &g_KswordArkSystemTimeState.RuntimeStatus,
        KSWORD_ARK_SYSTEM_TIME_STATUS_OK);
    InterlockedExchange(
        &g_KswordArkSystemTimeState.LastStatus,
        STATUS_SUCCESS);
    return STATUS_SUCCESS;
}

/* 安装两个计数器槽、关闭旁路并启动每秒一次的温和维护。 */
static
NTSTATUS
KswordARKSystemTimeActivateLocked(
    _In_ ULONG Command,
    _In_ ULONG Factor
    )
{
    KSW_SYSTEM_TIME_COUNTER_ROUTINE originalCounter = NULL;
    LONGLONG initialCounter = 0LL;
    LARGE_INTEGER dueTime = { 0 };
    NTSTATUS status = STATUS_SUCCESS;

    status = KswordARKSystemTimeResolveLocked();
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = KswordARKSystemTimeCaptureOriginalsLocked();
    if (!NT_SUCCESS(status)) {
        InterlockedExchange(
            &g_KswordArkSystemTimeState.RuntimeStatus,
            KSWORD_ARK_SYSTEM_TIME_STATUS_CONFLICT);
        InterlockedExchange(
            &g_KswordArkSystemTimeState.LastStatus,
            status);
        return status;
    }

    originalCounter =
        (KSW_SYSTEM_TIME_COUNTER_ROUTINE)
            g_KswordArkSystemTimeState.OriginalPrimary;
    initialCounter = originalCounter();
    KswordARKSystemTimeCounterActivate(
        g_KswordArkSystemTimeState.OriginalPrimary,
        initialCounter,
        Command,
        Factor);
    g_KswordArkSystemTimeState.LastCommand = Command;
    g_KswordArkSystemTimeState.Factor = Factor;
    InterlockedExchange(
        &g_KswordArkSystemTimeState.ConflictDetected,
        0L);

    status = KswordARKSystemTimeDisableBypassesLocked();
    if (!NT_SUCCESS(status)) {
        KswordARKSystemTimeCounterReset();
        g_KswordArkSystemTimeState.LastCommand =
            KSWORD_ARK_SYSTEM_TIME_COMMAND_RESET;
        g_KswordArkSystemTimeState.Factor = 1UL;
        InterlockedExchange(
            &g_KswordArkSystemTimeState.RuntimeStatus,
            KSWORD_ARK_SYSTEM_TIME_STATUS_PATCH_FAILED);
        InterlockedExchange(
            &g_KswordArkSystemTimeState.LastStatus,
            status);
        return status;
    }

    if (!KswordARKSystemTimePatchSlot(
            g_KswordArkSystemTimeState.Resolution.PrimarySlot,
            g_KswordArkSystemTimeState.OriginalPrimary)) {
        KswordARKSystemTimeRestoreBypasses();
        status = STATUS_CONFLICTING_ADDRESSES;
    } else if (!KswordARKSystemTimePatchSlot(
            g_KswordArkSystemTimeState.Resolution.SecondarySlot,
            g_KswordArkSystemTimeState.OriginalSecondary)) {
        (void)KswordARKSystemTimeRestoreSlot(
            g_KswordArkSystemTimeState.Resolution.PrimarySlot,
            g_KswordArkSystemTimeState.OriginalPrimary);
        KswordARKSystemTimeRestoreBypasses();
        status = STATUS_CONFLICTING_ADDRESSES;
    }

    if (!NT_SUCCESS(status)) {
        KswordARKSystemTimeCounterReset();
        g_KswordArkSystemTimeState.LastCommand =
            KSWORD_ARK_SYSTEM_TIME_COMMAND_RESET;
        g_KswordArkSystemTimeState.Factor = 1UL;
        InterlockedExchange(
            &g_KswordArkSystemTimeState.ConflictDetected,
            1L);
        InterlockedExchange(
            &g_KswordArkSystemTimeState.RuntimeStatus,
            KSWORD_ARK_SYSTEM_TIME_STATUS_CONFLICT);
        InterlockedExchange(
            &g_KswordArkSystemTimeState.LastStatus,
            status);
        return status;
    }

    InterlockedExchange(
        &g_KswordArkSystemTimeState.Active,
        1L);
    dueTime.QuadPart =
        -((LONGLONG)KSW_SYSTEM_TIME_MAINTENANCE_PERIOD_MS *
            10000LL);
    (void)KeSetTimerEx(
        &g_KswordArkSystemTimeState.MaintenanceTimer,
        dueTime,
        KSW_SYSTEM_TIME_MAINTENANCE_PERIOD_MS,
        &g_KswordArkSystemTimeState.MaintenanceDpc);
    InterlockedExchange(
        &g_KswordArkSystemTimeState.RuntimeStatus,
        KSWORD_ARK_SYSTEM_TIME_STATUS_OK);
    InterlockedExchange(
        &g_KswordArkSystemTimeState.LastStatus,
        STATUS_SUCCESS);
    return STATUS_SUCCESS;
}

/* 活跃状态下切换倍率时先按旧倍率结算，再原子发布新控制字。 */
static
NTSTATUS
KswordARKSystemTimeReconfigureLocked(
    _In_ ULONG Command,
    _In_ ULONG Factor
    )
{
    NTSTATUS status =
        KswordARKSystemTimeCounterReconfigure(
            Command,
            Factor);

    if (!NT_SUCCESS(status)) {
        return status;
    }
    g_KswordArkSystemTimeState.LastCommand = Command;
    g_KswordArkSystemTimeState.Factor = Factor;
    return STATUS_SUCCESS;
}

/*
 * 维护 DPC 只接受“仍是原函数”或“仍是本钩子”两种状态。
 * 发现未知第三方时立即停止活动并恢复本功能仍持有的槽。
 */
static
VOID
KswordARKSystemTimeMaintenanceDpc(
    _In_ PKDPC Dpc,
    _In_opt_ PVOID DeferredContext,
    _In_opt_ PVOID SystemArgument1,
    _In_opt_ PVOID SystemArgument2
    )
{
    BOOLEAN primaryOk = TRUE;
    BOOLEAN secondaryOk = TRUE;

    UNREFERENCED_PARAMETER(Dpc);
    UNREFERENCED_PARAMETER(DeferredContext);
    UNREFERENCED_PARAMETER(SystemArgument1);
    UNREFERENCED_PARAMETER(SystemArgument2);

    if (InterlockedCompareExchange(
            &g_KswordArkSystemTimeState.Active,
            0L,
            0L) == 0L) {
        return;
    }

    primaryOk = KswordARKSystemTimePatchSlot(
        g_KswordArkSystemTimeState.Resolution.PrimarySlot,
        g_KswordArkSystemTimeState.OriginalPrimary);
    secondaryOk = KswordARKSystemTimePatchSlot(
        g_KswordArkSystemTimeState.Resolution.SecondarySlot,
        g_KswordArkSystemTimeState.OriginalSecondary);
    if (primaryOk && secondaryOk) {
        return;
    }

    InterlockedExchange(
        &g_KswordArkSystemTimeState.Active,
        0L);
    (void)KswordARKSystemTimeRestoreSlot(
        g_KswordArkSystemTimeState.Resolution.PrimarySlot,
        g_KswordArkSystemTimeState.OriginalPrimary);
    (void)KswordARKSystemTimeRestoreSlot(
        g_KswordArkSystemTimeState.Resolution.SecondarySlot,
        g_KswordArkSystemTimeState.OriginalSecondary);
    KswordARKSystemTimeRestoreBypasses();
    InterlockedExchange(
        &g_KswordArkSystemTimeState.ConflictDetected,
        1L);
    InterlockedExchange(
        &g_KswordArkSystemTimeState.RuntimeStatus,
        KSWORD_ARK_SYSTEM_TIME_STATUS_CONFLICT);
    InterlockedExchange(
        &g_KswordArkSystemTimeState.LastStatus,
        STATUS_CONFLICTING_ADDRESSES);
    (void)InterlockedIncrement(
        &g_KswordArkSystemTimeState.Generation);
}

/* 驱动加载时只初始化状态和 DPC；实际内核接管仍必须由 UI 显式触发。 */
VOID
KswordARKSystemTimeInitialize(
    VOID
    )
{
    RtlZeroMemory(
        &g_KswordArkSystemTimeState,
        sizeof(g_KswordArkSystemTimeState));
    KswordARKSystemTimeCounterInitialize();
    ExInitializePushLock(
        &g_KswordArkSystemTimeState.ControlLock);
    KeInitializeTimerEx(
        &g_KswordArkSystemTimeState.MaintenanceTimer,
        SynchronizationTimer);
    KeInitializeDpc(
        &g_KswordArkSystemTimeState.MaintenanceDpc,
        KswordARKSystemTimeMaintenanceDpc,
        NULL);
    g_KswordArkSystemTimeState.LastCommand =
        KSWORD_ARK_SYSTEM_TIME_COMMAND_RESET;
    g_KswordArkSystemTimeState.Factor = 1UL;
    g_KswordArkSystemTimeState.ResolutionMode =
        KSWORD_ARK_SYSTEM_TIME_RESOLUTION_ORIGINAL_COMPAT;
    InterlockedExchange(
        &g_KswordArkSystemTimeState.Generation,
        1L);
    InterlockedExchange(
        &g_KswordArkSystemTimeState.RuntimeStatus,
        KSWORD_ARK_SYSTEM_TIME_STATUS_OK);
    InterlockedExchange(
        &g_KswordArkSystemTimeState.LastStatus,
        STATUS_SUCCESS);
    InterlockedExchange(
        &g_KswordArkSystemTimeState.Initialized,
        1L);
}

/* 卸载路径无条件取消 DPC，并在活动时执行完整恢复与在途排空。 */
VOID
KswordARKSystemTimeUninitialize(
    VOID
    )
{
    if (InterlockedCompareExchange(
            &g_KswordArkSystemTimeState.Initialized,
            0L,
            0L) == 0L) {
        return;
    }

    ExAcquirePushLockExclusive(
        &g_KswordArkSystemTimeState.ControlLock);
    (void)KswordARKSystemTimeDeactivateLocked();
    InterlockedExchange(
        &g_KswordArkSystemTimeState.Initialized,
        0L);
    ExReleasePushLockExclusive(
        &g_KswordArkSystemTimeState.ControlLock);
}

/* 查询会尝试只读解析当前构建，但不会安装任何钩子或修改旁路位。 */
NTSTATUS
KswordARKSystemTimeQuery(
    _Out_ KSWORD_ARK_QUERY_SYSTEM_TIME_RESPONSE* Response
    )
{
    if (Response == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    if (InterlockedCompareExchange(
            &g_KswordArkSystemTimeState.Initialized,
            0L,
            0L) == 0L) {
        return STATUS_DEVICE_NOT_READY;
    }

    ExAcquirePushLockExclusive(
        &g_KswordArkSystemTimeState.ControlLock);
    if (!g_KswordArkSystemTimeState.Resolved) {
        (void)KswordARKSystemTimeResolveLocked();
    }
    KswordARKSystemTimeFillQueryLocked(Response);
    ExReleasePushLockExclusive(
        &g_KswordArkSystemTimeState.ControlLock);
    return STATUS_SUCCESS;
}

/*
 * 控制入口校验协议、确认令牌、倍率与代次后执行动作。
 * RESET 是幂等恢复命令，不受过期代次和确认令牌限制。
 */
NTSTATUS
KswordARKSystemTimeControl(
    _In_ const KSWORD_ARK_CONTROL_SYSTEM_TIME_REQUEST* Request,
    _Out_ KSWORD_ARK_CONTROL_SYSTEM_TIME_RESPONSE* Response
    )
{
    ULONG oldFlags = 0UL;
    ULONG oldGeneration = 0UL;
    NTSTATUS actionStatus = STATUS_SUCCESS;

    if (Request == NULL || Response == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    RtlZeroMemory(Response, sizeof(*Response));
    Response->version =
        KSWORD_ARK_SYSTEM_TIME_PROTOCOL_VERSION;
    Response->size = sizeof(*Response);

    if (Request->version !=
            KSWORD_ARK_SYSTEM_TIME_PROTOCOL_VERSION ||
        Request->size != sizeof(*Request) ||
        (Request->command !=
            KSWORD_ARK_SYSTEM_TIME_COMMAND_RESET &&
         Request->command !=
            KSWORD_ARK_SYSTEM_TIME_COMMAND_SPEED_UP &&
         Request->command !=
            KSWORD_ARK_SYSTEM_TIME_COMMAND_SLOW_DOWN)) {
        Response->status =
            KSWORD_ARK_SYSTEM_TIME_STATUS_INVALID_REQUEST;
        Response->lastStatus = STATUS_INVALID_PARAMETER;
        return STATUS_SUCCESS;
    }

    if (Request->command !=
            KSWORD_ARK_SYSTEM_TIME_COMMAND_RESET &&
        (Request->factor <
            KSWORD_ARK_SYSTEM_TIME_MIN_FACTOR ||
         Request->factor >
            KSWORD_ARK_SYSTEM_TIME_MAX_FACTOR)) {
        Response->status =
            KSWORD_ARK_SYSTEM_TIME_STATUS_INVALID_REQUEST;
        Response->lastStatus = STATUS_INVALID_PARAMETER;
        return STATUS_SUCCESS;
    }

    if (Request->command !=
            KSWORD_ARK_SYSTEM_TIME_COMMAND_RESET &&
        Request->resolutionMode !=
            KSWORD_ARK_SYSTEM_TIME_RESOLUTION_ORIGINAL_COMPAT &&
        Request->resolutionMode !=
            KSWORD_ARK_SYSTEM_TIME_RESOLUTION_GUARDED) {
        Response->status =
            KSWORD_ARK_SYSTEM_TIME_STATUS_INVALID_REQUEST;
        Response->lastStatus = STATUS_INVALID_PARAMETER;
        return STATUS_SUCCESS;
    }

    if (Request->command !=
            KSWORD_ARK_SYSTEM_TIME_COMMAND_RESET &&
        ((Request->flags &
            KSWORD_ARK_SYSTEM_TIME_CONTROL_FLAG_UI_CONFIRMED) == 0UL ||
         Request->confirmationToken !=
            KSWORD_ARK_SYSTEM_TIME_CONFIRMATION_TOKEN)) {
        Response->status =
            KSWORD_ARK_SYSTEM_TIME_STATUS_CONFIRMATION_REQUIRED;
        Response->lastStatus = STATUS_REQUEST_NOT_ACCEPTED;
        return STATUS_SUCCESS;
    }

    ExAcquirePushLockExclusive(
        &g_KswordArkSystemTimeState.ControlLock);
    oldFlags = KswordARKSystemTimeStateFlagsLocked();
    oldGeneration = (ULONG)InterlockedCompareExchange(
        &g_KswordArkSystemTimeState.Generation,
        0L,
        0L);

    if (Request->command !=
            KSWORD_ARK_SYSTEM_TIME_COMMAND_RESET &&
        InterlockedCompareExchange(
            &g_KswordArkSystemTimeState.ConflictDetected,
            0L,
            0L) != 0L) {
        actionStatus = STATUS_CONFLICTING_ADDRESSES;
        Response->status =
            KSWORD_ARK_SYSTEM_TIME_STATUS_CONFLICT;
    } else if (Request->command !=
            KSWORD_ARK_SYSTEM_TIME_COMMAND_RESET &&
        Request->expectedGeneration != 0UL &&
        Request->expectedGeneration != oldGeneration) {
        actionStatus = STATUS_REVISION_MISMATCH;
        Response->status =
            KSWORD_ARK_SYSTEM_TIME_STATUS_STALE_GENERATION;
    } else if (Request->command ==
            KSWORD_ARK_SYSTEM_TIME_COMMAND_RESET) {
        actionStatus =
            KswordARKSystemTimeDeactivateLocked();
        Response->status = NT_SUCCESS(actionStatus)
            ? KSWORD_ARK_SYSTEM_TIME_STATUS_OK
            : KSWORD_ARK_SYSTEM_TIME_STATUS_CONFLICT;
    } else {
        /*
         * 未激活时允许切换方案并强制重新解析。
         * 已激活时只有相同方案可以继续调整倍率。
         */
        actionStatus =
            KswordARKSystemTimeSelectResolutionModeLocked(
                Request->resolutionMode);
        if (!NT_SUCCESS(actionStatus)) {
            Response->status =
                KSWORD_ARK_SYSTEM_TIME_STATUS_INVALID_REQUEST;
        } else if (InterlockedCompareExchange(
                &g_KswordArkSystemTimeState.Active,
                0L,
                0L) != 0L) {
            actionStatus =
                KswordARKSystemTimeReconfigureLocked(
                    Request->command,
                    Request->factor);
            Response->status = NT_SUCCESS(actionStatus)
                ? KSWORD_ARK_SYSTEM_TIME_STATUS_OK
                : KSWORD_ARK_SYSTEM_TIME_STATUS_INTERNAL_ERROR;
        } else {
            actionStatus =
                KswordARKSystemTimeActivateLocked(
                    Request->command,
                    Request->factor);
            Response->status = NT_SUCCESS(actionStatus)
                ? KSWORD_ARK_SYSTEM_TIME_STATUS_OK
                : (ULONG)InterlockedCompareExchange(
                    &g_KswordArkSystemTimeState.RuntimeStatus,
                    0L,
                    0L);
        }
    }

    if (NT_SUCCESS(actionStatus) &&
        Response->status ==
            KSWORD_ARK_SYSTEM_TIME_STATUS_OK) {
        (void)InterlockedIncrement(
            &g_KswordArkSystemTimeState.Generation);
    }

    Response->oldStateFlags = oldFlags;
    Response->newStateFlags =
        KswordARKSystemTimeStateFlagsLocked();
    Response->oldGeneration = oldGeneration;
    Response->newGeneration =
        (ULONG)InterlockedCompareExchange(
            &g_KswordArkSystemTimeState.Generation,
            0L,
            0L);
    Response->command =
        g_KswordArkSystemTimeState.LastCommand;
    Response->factor =
        g_KswordArkSystemTimeState.Factor;
    Response->osBuildNumber =
        g_KswordArkSystemTimeState.Resolution.OsBuildNumber;
    Response->lastStatus = actionStatus;
    Response->resolutionMode =
        g_KswordArkSystemTimeState.ResolutionMode;
    Response->counterValue =
        (ULONGLONG)KeQueryPerformanceCounter(NULL).QuadPart;
    ExReleasePushLockExclusive(
        &g_KswordArkSystemTimeState.ControlLock);
    return STATUS_SUCCESS;
}
