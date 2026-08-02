/*++

Module Name:

    system_time_runtime.c

Abstract:

    以连续虚拟性能计数器实现系统全局加速、减速与可恢复接管。

Third-Party Notice:

    参考机制的许可证与归档说明位于：
    third_party/SystemWideTransmission/LICENSE.txt
    third_party/SystemWideTransmission/NOTICE.md

Environment:

    Kernel-mode Driver Framework.

--*/

#include "system_time_internal.h"
#include "ark/ark_push_lock.h"
#include "system_time_counter.h"
#include "system_time_hyperv.h"

/* HAL 计数器回调在当前 x64 Windows 上不接收参数并返回 64 位计数。 */
typedef LONGLONG
(*KSW_SYSTEM_TIME_COUNTER_ROUTINE)(
    VOID
    );

/* QPC 旁路位位于 KUSER_SHARED_DATA 的长期兼容字段。 */
#define KSW_SYSTEM_TIME_SHARED_DATA_KERNEL_BASE 0xFFFFF78000000000ULL
#define KSW_SYSTEM_TIME_QPC_BYPASS_OFFSET        0x3C6ULL
#define KSW_SYSTEM_TIME_QPC_BYPASS_BIT           0x01U
#define KSW_SYSTEM_TIME_QPC_BYPASS_CLEAR_MASK    0xFEU
#define KSW_SYSTEM_TIME_INTERNAL_BYPASS_BIT       0x00010000L

/* 周期维护只在槽被系统恢复为原函数时重新接管，不覆盖未知第三方。 */
#define KSW_SYSTEM_TIME_MAINTENANCE_PERIOD_MS 1000L
#define KSW_SYSTEM_TIME_DRAIN_RETRY_COUNT      100UL
#define KSW_SYSTEM_TIME_DRAIN_DELAY_100NS      (-10000LL)

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
    ULONG Backend;
    BOOLEAN Resolved;
    BOOLEAN OriginalQpcBypassBit;
    BOOLEAN OriginalInternalBypassBit;
    BOOLEAN PatchBitsCaptured;
    BOOLEAN QpcBypassPatched;
} KSWORD_ARK_SYSTEM_TIME_STATE;

static KSWORD_ARK_SYSTEM_TIME_STATE g_KswordArkSystemTimeState;

/* 计数器槽和原函数必须位于当前有效的内核地址空间。 */
static
BOOLEAN
KswordARKSystemTimeIsKernelAddressValid(
    _In_opt_ const VOID* Address
    )
{
    return Address != NULL &&
        (ULONG_PTR)Address >= (ULONG_PTR)MmSystemRangeStart &&
        MmIsAddressValid((PVOID)Address);
}

/* 指针槽横跨的首尾字节都必须已驻留，才允许执行原子读写。 */
static
BOOLEAN
KswordARKSystemTimeIsSlotAddressValid(
    _In_opt_ volatile PVOID* Slot
    )
{
    const UCHAR* first = (const UCHAR*)Slot;

    return KswordARKSystemTimeIsKernelAddressValid(first) &&
        KswordARKSystemTimeIsKernelAddressValid(
            first + sizeof(PVOID) - 1U);
}

/* 返回 KUSER_SHARED_DATA 中 QPC 旁路字节的只读内核映射。 */
static
volatile UCHAR*
KswordARKSystemTimeQpcBypassByte(
    VOID
    )
{
    return (volatile UCHAR*)(ULONG_PTR)(
        KSW_SYSTEM_TIME_SHARED_DATA_KERNEL_BASE +
        KSW_SYSTEM_TIME_QPC_BYPASS_OFFSET);
}

/*
 * KUSER_SHARED_DATA 的内核虚拟映射在新系统上是只读的，MmIsAddressValid
 * 只能证明页面存在，不能证明它允许写入。这里沿用原功能的物理页映射
 * 原理，但按整页建立短期、同缓存属性的可写映射，并在解除映射前验证
 * 目标位，避免再对 0xFFFFF780... 直接执行写操作而触发 0x50。
 */
static
NTSTATUS
KswordARKSystemTimeWriteQpcBypassBit(
    _In_ BOOLEAN Enabled,
    _Out_opt_ BOOLEAN* PreviousEnabled
    )
{
#if defined(_M_AMD64) || defined(_M_X64)
    volatile UCHAR* qpcBypass =
        KswordARKSystemTimeQpcBypassByte();
    PHYSICAL_ADDRESS targetPhysical = { 0 };
    PHYSICAL_ADDRESS pagePhysical = { 0 };
    SIZE_T pageOffset = 0U;
    PVOID mappedPage = NULL;
    volatile UCHAR* mappedByte = NULL;
    UCHAR oldByte = 0U;
    UCHAR newByte = 0U;
    NTSTATUS status = STATUS_SUCCESS;

    if (PreviousEnabled != NULL) {
        *PreviousEnabled = FALSE;
    }
    if (KeGetCurrentIrql() > DISPATCH_LEVEL) {
        return STATUS_INVALID_DEVICE_STATE;
    }
    if (!MmIsAddressValid((PVOID)qpcBypass)) {
        return STATUS_ACCESS_VIOLATION;
    }

    targetPhysical = MmGetPhysicalAddress((PVOID)qpcBypass);
    pageOffset = (SIZE_T)(
        (ULONGLONG)targetPhysical.QuadPart &
        ((ULONGLONG)PAGE_SIZE - 1ULL));
    pagePhysical.QuadPart =
        targetPhysical.QuadPart - (LONGLONG)pageOffset;
    mappedPage = MmMapIoSpace(
        pagePhysical,
        PAGE_SIZE,
        MmCached);
    if (mappedPage == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    mappedByte = (volatile UCHAR*)(
        (UCHAR*)mappedPage + pageOffset);
    __try {
        oldByte = *mappedByte;
        newByte = Enabled
            ? (UCHAR)(oldByte |
                KSW_SYSTEM_TIME_QPC_BYPASS_BIT)
            : (UCHAR)(oldByte &
                KSW_SYSTEM_TIME_QPC_BYPASS_CLEAR_MASK);
        *mappedByte = newByte;
        KeMemoryBarrier();
        if (((*mappedByte &
                KSW_SYSTEM_TIME_QPC_BYPASS_BIT) != 0U) !=
            (Enabled != FALSE)) {
            *mappedByte = oldByte;
            KeMemoryBarrier();
            status = STATUS_DATA_ERROR;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();
    }

    MmUnmapIoSpace(mappedPage, PAGE_SIZE);
    if (NT_SUCCESS(status) && PreviousEnabled != NULL) {
        *PreviousEnabled =
            (oldByte & KSW_SYSTEM_TIME_QPC_BYPASS_BIT) != 0U;
    }
    return status;
#else
    UNREFERENCED_PARAMETER(Enabled);
    UNREFERENCED_PARAMETER(PreviousEnabled);
    return STATUS_NOT_SUPPORTED;
#endif
}

/* 读取一个函数指针槽；SEH 防止异常解析状态造成系统崩溃。 */
static
BOOLEAN
KswordARKSystemTimeReadSlot(
    _In_ volatile PVOID* Slot,
    _Out_ PVOID* Value
    )
{
    if (Value == NULL ||
        !KswordARKSystemTimeIsSlotAddressValid(Slot)) {
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

    if (!KswordARKSystemTimeIsSlotAddressValid(Slot) ||
        !KswordARKSystemTimeIsKernelAddressValid(ExpectedOriginal)) {
        return FALSE;
    }

    __try {
        observed = InterlockedCompareExchangePointer(
            (PVOID volatile*)Slot,
            KswordARKSystemTimeCounterHookAddress(),
            ExpectedOriginal);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return FALSE;
    }
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

    if (!KswordARKSystemTimeIsSlotAddressValid(Slot) ||
        !KswordARKSystemTimeIsKernelAddressValid(Original)) {
        return FALSE;
    }

    __try {
        observed = InterlockedCompareExchangePointer(
            (PVOID volatile*)Slot,
            Original,
            KswordARKSystemTimeCounterHookAddress());
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return FALSE;
    }
    return observed == KswordARKSystemTimeCounterHookAddress() ||
        observed == Original;
}

/* 按后端保存旁路快照；Hyper-V 路径只关闭 HAL 内部旁路。 */
static
NTSTATUS
KswordARKSystemTimeConfigureBypassesLocked(
    _In_ BOOLEAN DisableUserQpcBypass
    )
{
#if defined(_M_AMD64) || defined(_M_X64)
    volatile UCHAR* qpcBypass =
        KswordARKSystemTimeQpcBypassByte();
    BOOLEAN oldQpcBypassBit = FALSE;
    LONG oldInternalFlags = 0L;
    NTSTATUS status = STATUS_SUCCESS;
    NTSTATUS rollbackStatus = STATUS_SUCCESS;

    if (g_KswordArkSystemTimeState.Resolution.InternalFlags == NULL ||
        !MmIsAddressValid((PVOID)qpcBypass)) {
        return STATUS_ACCESS_VIOLATION;
    }

    if (DisableUserQpcBypass) {
        status = KswordARKSystemTimeWriteQpcBypassBit(
            FALSE,
            &oldQpcBypassBit);
        if (!NT_SUCCESS(status)) {
            return status;
        }
    } else {
        __try {
            oldQpcBypassBit =
                ((*qpcBypass & KSW_SYSTEM_TIME_QPC_BYPASS_BIT) != 0U);
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            return GetExceptionCode();
        }
        if (!oldQpcBypassBit) {
            return STATUS_DEVICE_NOT_READY;
        }
    }

    __try {
        oldInternalFlags = InterlockedAnd(
            g_KswordArkSystemTimeState.Resolution.InternalFlags,
            ~KSW_SYSTEM_TIME_INTERNAL_BYPASS_BIT);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();
        if (DisableUserQpcBypass) {
            rollbackStatus = KswordARKSystemTimeWriteQpcBypassBit(
                oldQpcBypassBit,
                NULL);
            if (!NT_SUCCESS(rollbackStatus)) {
                InterlockedExchange(
                    &g_KswordArkSystemTimeState.ConflictDetected,
                    1L);
                return rollbackStatus;
            }
        }
        return status;
    }

    g_KswordArkSystemTimeState.OriginalQpcBypassBit =
        oldQpcBypassBit;
    g_KswordArkSystemTimeState.OriginalInternalBypassBit =
        (oldInternalFlags &
            KSW_SYSTEM_TIME_INTERNAL_BYPASS_BIT) != 0;
    g_KswordArkSystemTimeState.PatchBitsCaptured = TRUE;
    g_KswordArkSystemTimeState.QpcBypassPatched =
        DisableUserQpcBypass;
    KeMemoryBarrier();
    return STATUS_SUCCESS;
#else
    UNREFERENCED_PARAMETER(DisableUserQpcBypass);
    return STATUS_NOT_SUPPORTED;
#endif
}

/* 按激活前快照恢复实际修改过的旁路位，不改写其它系统标志。 */
static
NTSTATUS
KswordARKSystemTimeRestoreBypasses(
    VOID
    )
{
#if defined(_M_AMD64) || defined(_M_X64)
    NTSTATUS qpcStatus = STATUS_SUCCESS;
    NTSTATUS internalStatus = STATUS_SUCCESS;

    if (!g_KswordArkSystemTimeState.PatchBitsCaptured) {
        return STATUS_SUCCESS;
    }

    if (g_KswordArkSystemTimeState.QpcBypassPatched) {
        qpcStatus = KswordARKSystemTimeWriteQpcBypassBit(
            g_KswordArkSystemTimeState.OriginalQpcBypassBit,
            NULL);
    }
    __try {
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
        internalStatus = GetExceptionCode();
    }

    if (!NT_SUCCESS(qpcStatus) ||
        !NT_SUCCESS(internalStatus)) {
        InterlockedExchange(
            &g_KswordArkSystemTimeState.ConflictDetected,
            1L);
        return !NT_SUCCESS(qpcStatus)
            ? qpcStatus
            : internalStatus;
    }
    g_KswordArkSystemTimeState.PatchBitsCaptured = FALSE;
    g_KswordArkSystemTimeState.QpcBypassPatched = FALSE;
    return STATUS_SUCCESS;
#else
    /* 非 x64 路径不会捕获或修改旁路位，恢复保持幂等成功。 */
    return STATUS_SUCCESS;
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

/* 后端只能在未接管时切换，防止一半共享页、一半兼容旁路的混合状态。 */
static
NTSTATUS
KswordARKSystemTimeSelectBackendLocked(
    _In_ ULONG Backend
    )
{
    if (Backend !=
            KSWORD_ARK_SYSTEM_TIME_BACKEND_HYPERV_SHARED_QPC &&
        Backend !=
            KSWORD_ARK_SYSTEM_TIME_BACKEND_HAL_COMPAT) {
        return STATUS_INVALID_PARAMETER;
    }
    if (Backend == g_KswordArkSystemTimeState.Backend) {
        return STATUS_SUCCESS;
    }
    if (InterlockedCompareExchange(
            &g_KswordArkSystemTimeState.Active,
            0L,
            0L) != 0L) {
        return STATUS_DEVICE_BUSY;
    }

    g_KswordArkSystemTimeState.Backend = Backend;
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
        !KswordARKSystemTimeIsKernelAddressValid(primary) ||
        !KswordARKSystemTimeIsKernelAddressValid(secondary) ||
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
    KSWORD_ARK_SYSTEM_TIME_HYPERV_DIAGNOSTICS hyperv = { 0 };
    ULONG flags = 0UL;
    PVOID primary = NULL;
    PVOID secondary = NULL;

    (void)KswordARKSystemTimeHypervQuery(&hyperv);
    flags |= hyperv.StateFlags;
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
        if (g_KswordArkSystemTimeState.QpcBypassPatched) {
            flags |=
                KSWORD_ARK_SYSTEM_TIME_STATE_QPC_BYPASS_DISABLED;
        }
        if (g_KswordArkSystemTimeState.PatchBitsCaptured) {
            flags |=
                KSWORD_ARK_SYSTEM_TIME_STATE_INTERNAL_FLAG_PATCHED;
        }
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
    KSWORD_ARK_SYSTEM_TIME_HYPERV_DIAGNOSTICS hyperv = { 0 };
    LARGE_INTEGER counter = { 0 };

    (void)KswordARKSystemTimeHypervQuery(&hyperv);
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
    Response->backend =
        g_KswordArkSystemTimeState.Backend;

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
    Response->hypervisorSharedPageAddress =
        (ULONGLONG)(ULONG_PTR)hyperv.SharedUserVa;
    Response->hypervisorTimeUpdateLock =
        hyperv.TimeUpdateLock;
    Response->hypervisorOriginalMultiplier =
        hyperv.OriginalMultiplier;
    Response->hypervisorOriginalBias =
        hyperv.OriginalBias;
    Response->hypervisorCurrentMultiplier =
        hyperv.CurrentMultiplier;
    Response->hypervisorCurrentBias =
        hyperv.CurrentBias;
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
    NTSTATUS hypervStatus = STATUS_SUCCESS;
    NTSTATUS bypassStatus = STATUS_SUCCESS;
    ULONG retryIndex = 0UL;
    LARGE_INTEGER delay = { 0 };

    InterlockedExchange(
        &g_KswordArkSystemTimeState.Active,
        0L);
    (void)KeCancelTimer(
        &g_KswordArkSystemTimeState.MaintenanceTimer);
    KeFlushQueuedDpcs();

    if (g_KswordArkSystemTimeState.Backend ==
        KSWORD_ARK_SYSTEM_TIME_BACKEND_HYPERV_SHARED_QPC) {
        hypervStatus = KswordARKSystemTimeHypervRestore();
    }
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

    bypassStatus = KswordARKSystemTimeRestoreBypasses();
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
        !NT_SUCCESS(hypervStatus) ||
        !NT_SUCCESS(bypassStatus) ||
        retryIndex == KSW_SYSTEM_TIME_DRAIN_RETRY_COUNT) {
        const NTSTATUS failureStatus =
            !NT_SUCCESS(hypervStatus)
            ? hypervStatus
            : !NT_SUCCESS(bypassStatus)
                ? bypassStatus
                : STATUS_CONFLICTING_ADDRESSES;

        InterlockedExchange(
            &g_KswordArkSystemTimeState.ConflictDetected,
            1L);
        InterlockedExchange(
            &g_KswordArkSystemTimeState.RuntimeStatus,
            KSWORD_ARK_SYSTEM_TIME_STATUS_CONFLICT);
        InterlockedExchange(
            &g_KswordArkSystemTimeState.LastStatus,
            failureStatus);
        return failureStatus;
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

/* 把 Hyper-V 探测失败转换为稳定 UI 状态，不把不同失败都伪装成“不存在”。 */
static
ULONG
KswordARKSystemTimeHypervFailureStatus(
    _In_ NTSTATUS Status,
    _In_ BOOLEAN DuringWrite
    )
{
    if (Status == STATUS_NOT_SUPPORTED) {
        return KSWORD_ARK_SYSTEM_TIME_STATUS_HYPERV_NOT_PRESENT;
    }
    if (Status == STATUS_DEVICE_NOT_READY ||
        Status == STATUS_PROCEDURE_NOT_FOUND) {
        return KSWORD_ARK_SYSTEM_TIME_STATUS_HYPERV_PAGE_UNAVAILABLE;
    }
    if (Status == STATUS_CONFLICTING_ADDRESSES ||
        Status == STATUS_DATA_ERROR ||
        Status == STATUS_RETRY) {
        return KSWORD_ARK_SYSTEM_TIME_STATUS_HYPERV_VALIDATION_FAILED;
    }
    return DuringWrite
        ? KSWORD_ARK_SYSTEM_TIME_STATUS_HYPERV_WRITE_FAILED
        : KSWORD_ARK_SYSTEM_TIME_STATUS_HYPERV_PAGE_UNAVAILABLE;
}

/* 安装内核计数器槽，并按所选后端配置用户态 QPC 路径。 */
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
    BOOLEAN hypervPrepared = FALSE;
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

    if (g_KswordArkSystemTimeState.Backend ==
        KSWORD_ARK_SYSTEM_TIME_BACKEND_HYPERV_SHARED_QPC) {
        status = KswordARKSystemTimeHypervPrepare();
        if (!NT_SUCCESS(status)) {
            InterlockedExchange(
                &g_KswordArkSystemTimeState.RuntimeStatus,
                (LONG)KswordARKSystemTimeHypervFailureStatus(
                    status,
                    FALSE));
            InterlockedExchange(
                &g_KswordArkSystemTimeState.LastStatus,
                status);
            if (status == STATUS_CONFLICTING_ADDRESSES ||
                status == STATUS_DATA_ERROR) {
                InterlockedExchange(
                    &g_KswordArkSystemTimeState.ConflictDetected,
                    1L);
            }
            return status;
        }
        hypervPrepared = TRUE;
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

    status = KswordARKSystemTimeConfigureBypassesLocked(
        g_KswordArkSystemTimeState.Backend ==
            KSWORD_ARK_SYSTEM_TIME_BACKEND_HAL_COMPAT);
    if (!NT_SUCCESS(status)) {
        KswordARKSystemTimeCounterReset();
        if (hypervPrepared) {
            (void)KswordARKSystemTimeHypervRestore();
        }
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
        (void)KswordARKSystemTimeRestoreBypasses();
        status = STATUS_CONFLICTING_ADDRESSES;
    } else if (!KswordARKSystemTimePatchSlot(
            g_KswordArkSystemTimeState.Resolution.SecondarySlot,
            g_KswordArkSystemTimeState.OriginalSecondary)) {
        (void)KswordARKSystemTimeRestoreSlot(
            g_KswordArkSystemTimeState.Resolution.PrimarySlot,
            g_KswordArkSystemTimeState.OriginalPrimary);
        (void)KswordARKSystemTimeRestoreBypasses();
        status = STATUS_CONFLICTING_ADDRESSES;
    }

    if (!NT_SUCCESS(status)) {
        if (hypervPrepared) {
            (void)KswordARKSystemTimeHypervRestore();
        }
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

    if (g_KswordArkSystemTimeState.Backend ==
        KSWORD_ARK_SYSTEM_TIME_BACKEND_HYPERV_SHARED_QPC) {
        status = KswordARKSystemTimeHypervActivate(
            Command,
            Factor);
        if (!NT_SUCCESS(status)) {
            (void)KswordARKSystemTimeRestoreSlot(
                g_KswordArkSystemTimeState.Resolution.PrimarySlot,
                g_KswordArkSystemTimeState.OriginalPrimary);
            (void)KswordARKSystemTimeRestoreSlot(
                g_KswordArkSystemTimeState.Resolution.SecondarySlot,
                g_KswordArkSystemTimeState.OriginalSecondary);
            (void)KswordARKSystemTimeRestoreBypasses();
            (void)KswordARKSystemTimeHypervRestore();
            KswordARKSystemTimeCounterReset();
            g_KswordArkSystemTimeState.LastCommand =
                KSWORD_ARK_SYSTEM_TIME_COMMAND_RESET;
            g_KswordArkSystemTimeState.Factor = 1UL;
            InterlockedExchange(
                &g_KswordArkSystemTimeState.RuntimeStatus,
                (LONG)KswordARKSystemTimeHypervFailureStatus(
                    status,
                    TRUE));
            InterlockedExchange(
                &g_KswordArkSystemTimeState.LastStatus,
                status);
            if (status == STATUS_CONFLICTING_ADDRESSES ||
                status == STATUS_DATA_ERROR) {
                InterlockedExchange(
                    &g_KswordArkSystemTimeState.ConflictDetected,
                    1L);
            }
            return status;
        }
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

/* 活跃状态下先结算内核计数，再以同一目标连续更新 Hyper-V 共享页。 */
static
NTSTATUS
KswordARKSystemTimeReconfigureLocked(
    _In_ ULONG Command,
    _In_ ULONG Factor
    )
{
    const ULONG oldCommand =
        g_KswordArkSystemTimeState.LastCommand;
    const ULONG oldFactor =
        g_KswordArkSystemTimeState.Factor;
    NTSTATUS hypervRollbackStatus = STATUS_SUCCESS;
    NTSTATUS counterRollbackStatus = STATUS_SUCCESS;
    NTSTATUS status =
        KswordARKSystemTimeCounterReconfigure(
            Command,
            Factor);

    if (!NT_SUCCESS(status)) {
        return status;
    }
    if (g_KswordArkSystemTimeState.Backend ==
        KSWORD_ARK_SYSTEM_TIME_BACKEND_HYPERV_SHARED_QPC) {
        status = KswordARKSystemTimeHypervReconfigure(
            Command,
            Factor);
        if (!NT_SUCCESS(status)) {
            /*
             * 共享页可能已经提交、只是稳定读回失败。先让共享页以当前
             * 内核虚拟计数为连续锚点退回旧倍率，再退回内核倍率；任一
             * 回滚失败都停止接管，避免用户态和内核态计时路径分叉。
             */
            hypervRollbackStatus =
                KswordARKSystemTimeHypervReconfigure(
                    oldCommand,
                    oldFactor);
            counterRollbackStatus =
                KswordARKSystemTimeCounterReconfigure(
                    oldCommand,
                    oldFactor);
            if (!NT_SUCCESS(hypervRollbackStatus) ||
                !NT_SUCCESS(counterRollbackStatus)) {
                (void)KswordARKSystemTimeDeactivateLocked();
            }
            InterlockedExchange(
                &g_KswordArkSystemTimeState.RuntimeStatus,
                (LONG)KswordARKSystemTimeHypervFailureStatus(
                    status,
                    TRUE));
            InterlockedExchange(
                &g_KswordArkSystemTimeState.LastStatus,
                status);
            if (status == STATUS_CONFLICTING_ADDRESSES ||
                status == STATUS_DATA_ERROR) {
                InterlockedExchange(
                    &g_KswordArkSystemTimeState.ConflictDetected,
                    1L);
            }
            return status;
        }
    }

    g_KswordArkSystemTimeState.LastCommand = Command;
    g_KswordArkSystemTimeState.Factor = Factor;
    InterlockedExchange(
        &g_KswordArkSystemTimeState.RuntimeStatus,
        KSWORD_ARK_SYSTEM_TIME_STATUS_OK);
    InterlockedExchange(
        &g_KswordArkSystemTimeState.LastStatus,
        STATUS_SUCCESS);
    return STATUS_SUCCESS;
}

/*
 * 维护 DPC 只接受“仍是原函数”或“仍是本钩子”两种状态。
 * Hyper-V 页只接受原快照或本功能快照，未知写入会触发失败关闭。
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
    NTSTATUS hypervStatus = STATUS_SUCCESS;

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
    if (primaryOk && secondaryOk &&
        g_KswordArkSystemTimeState.Backend ==
            KSWORD_ARK_SYSTEM_TIME_BACKEND_HYPERV_SHARED_QPC) {
        hypervStatus = KswordARKSystemTimeHypervMaintain();
        if (hypervStatus == STATUS_RETRY ||
            hypervStatus == STATUS_DEVICE_BUSY) {
            return;
        }
    }
    if (primaryOk && secondaryOk &&
        NT_SUCCESS(hypervStatus)) {
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
    if (g_KswordArkSystemTimeState.Backend ==
        KSWORD_ARK_SYSTEM_TIME_BACKEND_HYPERV_SHARED_QPC) {
        (void)KswordARKSystemTimeHypervRestore();
    }
    (void)KswordARKSystemTimeRestoreBypasses();
    KswordARKSystemTimeCounterReset();
    InterlockedExchange(
        &g_KswordArkSystemTimeState.ConflictDetected,
        1L);
    InterlockedExchange(
        &g_KswordArkSystemTimeState.RuntimeStatus,
        KSWORD_ARK_SYSTEM_TIME_STATUS_CONFLICT);
    InterlockedExchange(
        &g_KswordArkSystemTimeState.LastStatus,
        NT_SUCCESS(hypervStatus)
            ? STATUS_CONFLICTING_ADDRESSES
            : hypervStatus);
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
    KswordARKSystemTimeHypervInitialize();
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
    g_KswordArkSystemTimeState.Backend =
        KSWORD_ARK_SYSTEM_TIME_BACKEND_HYPERV_SHARED_QPC;
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

    KswordARKAcquirePushLockExclusive(
        &g_KswordArkSystemTimeState.ControlLock);
    (void)KswordARKSystemTimeDeactivateLocked();
    InterlockedExchange(
        &g_KswordArkSystemTimeState.Initialized,
        0L);
    KswordARKReleasePushLockExclusive(
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

    KswordARKAcquirePushLockExclusive(
        &g_KswordArkSystemTimeState.ControlLock);
    if (!g_KswordArkSystemTimeState.Resolved) {
        (void)KswordARKSystemTimeResolveLocked();
    }
    KswordARKSystemTimeFillQueryLocked(Response);
    KswordARKReleasePushLockExclusive(
        &g_KswordArkSystemTimeState.ControlLock);
    return STATUS_SUCCESS;
}

/*
 * 控制入口校验协议、确认令牌、倍率与代次后执行动作。
 * RESET 是幂等恢复命令，不受过期代次和确认令牌限制；已接管时切到连续 1x，
 * 不把领先的虚拟计数器直接换回较小的原始计数器。
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
        (Request->resolutionMode !=
            KSWORD_ARK_SYSTEM_TIME_RESOLUTION_ORIGINAL_COMPAT &&
         Request->resolutionMode !=
            KSWORD_ARK_SYSTEM_TIME_RESOLUTION_GUARDED)) {
        Response->status =
            KSWORD_ARK_SYSTEM_TIME_STATUS_INVALID_REQUEST;
        Response->lastStatus = STATUS_INVALID_PARAMETER;
        return STATUS_SUCCESS;
    }

    if (Request->command !=
            KSWORD_ARK_SYSTEM_TIME_COMMAND_RESET &&
        Request->backend !=
            KSWORD_ARK_SYSTEM_TIME_BACKEND_HYPERV_SHARED_QPC &&
        Request->backend !=
            KSWORD_ARK_SYSTEM_TIME_BACKEND_HAL_COMPAT) {
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

    KswordARKAcquirePushLockExclusive(
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
        if (InterlockedCompareExchange(
                &g_KswordArkSystemTimeState.Active,
                0L,
                0L) != 0L) {
            /*
             * 加速后虚拟计数可能领先原始 QPC。直接恢复函数槽会让系统计数回跳；
             * 保留钩子并原子切换到 1x，使既有偏移保持不变而后续增量恢复原速。
             */
            actionStatus =
                KswordARKSystemTimeReconfigureLocked(
                    KSWORD_ARK_SYSTEM_TIME_COMMAND_RESET,
                    1UL);
        } else {
            actionStatus =
                KswordARKSystemTimeDeactivateLocked();
        }
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
        if (NT_SUCCESS(actionStatus)) {
            actionStatus = KswordARKSystemTimeSelectBackendLocked(
                Request->backend);
        }
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
                : (ULONG)InterlockedCompareExchange(
                    &g_KswordArkSystemTimeState.RuntimeStatus,
                    0L,
                    0L);
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
    Response->backend =
        g_KswordArkSystemTimeState.Backend;
    Response->counterValue =
        (ULONGLONG)KeQueryPerformanceCounter(NULL).QuadPart;
    KswordARKReleasePushLockExclusive(
        &g_KswordArkSystemTimeState.ControlLock);
    return STATUS_SUCCESS;
}
