#include "ark/ark_driver.h"

/*++

Module Name:

    bugcheck_guard.c

Abstract:

    Explicitly-confirmed, one-shot KeBugCheckEx delay guard.

--*/

#if !defined(_WIN64)
#error The bugcheck delay guard only supports x64 builds.
#endif

#define KSWORD_ARK_BUGCHECK_GUARD_STATE_UNINSTALLED 0L
#define KSWORD_ARK_BUGCHECK_GUARD_STATE_INSTALLED   1L
#define KSWORD_ARK_BUGCHECK_GUARD_STATE_RESTORING   2L

typedef VOID
(NTAPI* KSWORD_ARK_KE_BUGCHECK_EX_FN)(
    _In_ ULONG BugCheckCode,
    _In_ ULONG_PTR Parameter1,
    _In_ ULONG_PTR Parameter2,
    _In_ ULONG_PTR Parameter3,
    _In_ ULONG_PTR Parameter4
    );

typedef struct _KSWORD_ARK_BUGCHECK_GUARD_STATE
{
    FAST_MUTEX ControlLock;
    volatile LONG HookState;
    volatile LONG Enabled;
    volatile LONG Fired;
    volatile LONG TryIgnoreError;
    volatile LONG ErrorIgnored;
    volatile LONG HookExecutions;
    ULONG DelaySeconds;
    PVOID Target;
    PMDL TargetMdl;
    PVOID WritableAlias;
    UCHAR OriginalBytes[KSWORD_ARK_BUGCHECK_GUARD_HOOK_BYTES];
    UCHAR HookBytes[KSWORD_ARK_BUGCHECK_GUARD_HOOK_BYTES];
    NTSTATUS LastStatus;
} KSWORD_ARK_BUGCHECK_GUARD_STATE;

static KSWORD_ARK_BUGCHECK_GUARD_STATE g_KswordArkBugcheckGuard;

static VOID
NTAPI
KswordARKBugcheckGuardHook(
    _In_ ULONG BugCheckCode,
    _In_ ULONG_PTR Parameter1,
    _In_ ULONG_PTR Parameter2,
    _In_ ULONG_PTR Parameter3,
    _In_ ULONG_PTR Parameter4
    );

static BOOLEAN
KswordARKBugcheckGuardLooksHooked(
    _In_reads_bytes_(KSWORD_ARK_BUGCHECK_GUARD_HOOK_BYTES) const UCHAR* Bytes
    )
{
    if (Bytes[0] == 0xE9U || Bytes[0] == 0xEBU || Bytes[0] == 0xCCU) {
        return TRUE;
    }

    if ((Bytes[0] == 0xFFU && Bytes[1] == 0x25U) ||
        (Bytes[0] == 0x48U && Bytes[1] == 0xB8U &&
         Bytes[10] == 0xFFU && Bytes[11] == 0xE0U)) {
        return TRUE;
    }

    return FALSE;
}

static VOID
KswordARKBugcheckGuardBuildHook(
    _Out_writes_bytes_(KSWORD_ARK_BUGCHECK_GUARD_HOOK_BYTES) UCHAR* Patch
    )
{
    PVOID hookTarget = (PVOID)(ULONG_PTR)KswordARKBugcheckGuardHook;
    RtlZeroMemory(Patch, KSWORD_ARK_BUGCHECK_GUARD_HOOK_BYTES);
    Patch[0] = 0x48U;
    Patch[1] = 0xB8U;
    RtlCopyMemory(Patch + 2U, &hookTarget, sizeof(hookTarget));
    Patch[10] = 0xFFU;
    Patch[11] = 0xE0U;
}

static ULONG
KswordARKBugcheckGuardStateFlags(VOID)
{
    ULONG flags = 0UL;

    if (g_KswordArkBugcheckGuard.Target != NULL) {
        flags |= KSWORD_ARK_BUGCHECK_GUARD_STATE_TARGET_RESOLVED;
    }
    if (InterlockedCompareExchange(&g_KswordArkBugcheckGuard.Enabled, 1L, 1L) != 0L) {
        flags |= KSWORD_ARK_BUGCHECK_GUARD_STATE_ACTIVE;
    }
    if (InterlockedCompareExchange(&g_KswordArkBugcheckGuard.HookState, 1L, 1L) == KSWORD_ARK_BUGCHECK_GUARD_STATE_INSTALLED) {
        flags |= KSWORD_ARK_BUGCHECK_GUARD_STATE_PATCH_INSTALLED;
    }

    if (InterlockedCompareExchange(&g_KswordArkBugcheckGuard.Fired, 1L, 1L) != 0L) {
        flags |= KSWORD_ARK_BUGCHECK_GUARD_STATE_FIRED;
    }
    if (InterlockedCompareExchange(&g_KswordArkBugcheckGuard.TryIgnoreError, 1L, 1L) != 0L) {
        flags |= KSWORD_ARK_BUGCHECK_GUARD_STATE_TRY_IGNORE_ERROR;
    }
    if (InterlockedCompareExchange(&g_KswordArkBugcheckGuard.ErrorIgnored, 1L, 1L) != 0L) {
        flags |= KSWORD_ARK_BUGCHECK_GUARD_STATE_ERROR_IGNORED;
    }
    if (InterlockedCompareExchange(&g_KswordArkBugcheckGuard.HookExecutions, 0L, 0L) != 0L) {
        flags |= KSWORD_ARK_BUGCHECK_GUARD_STATE_HOOK_EXECUTING;
    }
    return flags;
}
static VOID
KswordARKBugcheckGuardRestoreFromCrashPath(VOID)
{
    LONG state = InterlockedCompareExchange(
        &g_KswordArkBugcheckGuard.HookState,
        KSWORD_ARK_BUGCHECK_GUARD_STATE_RESTORING,
        KSWORD_ARK_BUGCHECK_GUARD_STATE_INSTALLED);

    if (state == KSWORD_ARK_BUGCHECK_GUARD_STATE_INSTALLED) {
        if (g_KswordArkBugcheckGuard.WritableAlias != NULL) {
            RtlCopyMemory(g_KswordArkBugcheckGuard.WritableAlias, g_KswordArkBugcheckGuard.OriginalBytes, KSWORD_ARK_BUGCHECK_GUARD_HOOK_BYTES);
            KeMemoryBarrier();
            KeInvalidateRangeAllCaches(g_KswordArkBugcheckGuard.Target, KSWORD_ARK_BUGCHECK_GUARD_HOOK_BYTES);
        }
        InterlockedExchange(&g_KswordArkBugcheckGuard.HookState, KSWORD_ARK_BUGCHECK_GUARD_STATE_UNINSTALLED);
        return;
    }

    while (state == KSWORD_ARK_BUGCHECK_GUARD_STATE_RESTORING) {
        KeStallExecutionProcessor(10UL);
        state = InterlockedCompareExchange(&g_KswordArkBugcheckGuard.HookState, 0L, 0L);
    }
}

static VOID
KswordARKBugcheckGuardReleaseMappingLocked(VOID)
{
    InterlockedExchange(&g_KswordArkBugcheckGuard.Enabled, 0L);
    KswordARKBugcheckGuardRestoreFromCrashPath();
    if (InterlockedCompareExchange(
            &g_KswordArkBugcheckGuard.HookExecutions,
            0L,
            0L) != 0L) {
        // A triggering CPU is still executing this driver. A later disable
        // request can release the mapping after the return attempt completes.
        return;
    }
    InterlockedExchange(&g_KswordArkBugcheckGuard.Fired, 0L);
    InterlockedExchange(&g_KswordArkBugcheckGuard.TryIgnoreError, 0L);
    InterlockedExchange(&g_KswordArkBugcheckGuard.ErrorIgnored, 0L);
    if (g_KswordArkBugcheckGuard.WritableAlias != NULL) {
        MmUnmapLockedPages(g_KswordArkBugcheckGuard.WritableAlias, g_KswordArkBugcheckGuard.TargetMdl);
        g_KswordArkBugcheckGuard.WritableAlias = NULL;
    }
    if (g_KswordArkBugcheckGuard.TargetMdl != NULL) {
        MmUnlockPages(g_KswordArkBugcheckGuard.TargetMdl);
        IoFreeMdl(g_KswordArkBugcheckGuard.TargetMdl);
        g_KswordArkBugcheckGuard.TargetMdl = NULL;
    }
    g_KswordArkBugcheckGuard.Target = NULL;
    RtlZeroMemory(g_KswordArkBugcheckGuard.OriginalBytes, sizeof(g_KswordArkBugcheckGuard.OriginalBytes));
    RtlZeroMemory(g_KswordArkBugcheckGuard.HookBytes, sizeof(g_KswordArkBugcheckGuard.HookBytes));
    g_KswordArkBugcheckGuard.DelaySeconds = 0UL;
}

static VOID
KswordARKBugcheckGuardDelay(
    _In_ ULONG DelaySeconds
    )
{
    LARGE_INTEGER frequency;
    LARGE_INTEGER start;
    ULONGLONG targetTicks;

    if (DelaySeconds > KSWORD_ARK_BUGCHECK_GUARD_MAX_DELAY_SECONDS) {
        DelaySeconds = KSWORD_ARK_BUGCHECK_GUARD_MAX_DELAY_SECONDS;
    }
    start = KeQueryPerformanceCounter(&frequency);
    if (frequency.QuadPart <= 0) {
        ULONG index;
        for (index = 0UL; index < DelaySeconds * 1000UL; ++index) {
            KeStallExecutionProcessor(1000UL);
        }
        return;
    }
    targetTicks = (ULONGLONG)frequency.QuadPart * (ULONGLONG)DelaySeconds;
    while ((ULONGLONG)(KeQueryPerformanceCounter(NULL).QuadPart - start.QuadPart) < targetTicks) {
        KeStallExecutionProcessor(1000UL);
    }
}

static VOID
NTAPI
KswordARKBugcheckGuardHook(
    _In_ ULONG BugCheckCode,
    _In_ ULONG_PTR Parameter1,
    _In_ ULONG_PTR Parameter2,
    _In_ ULONG_PTR Parameter3,
    _In_ ULONG_PTR Parameter4
    )
{
    KSWORD_ARK_KE_BUGCHECK_EX_FN target;
    BOOLEAN firstHit;
    BOOLEAN tryIgnoreError;

    InterlockedIncrement(&g_KswordArkBugcheckGuard.HookExecutions);
    target =
        (KSWORD_ARK_KE_BUGCHECK_EX_FN)g_KswordArkBugcheckGuard.Target;
    firstHit =
        InterlockedCompareExchange(&g_KswordArkBugcheckGuard.Fired, 1L, 0L) == 0L;
    tryIgnoreError = InterlockedCompareExchange(
        &g_KswordArkBugcheckGuard.TryIgnoreError,
        1L,
        1L) != 0L;

    InterlockedExchange(&g_KswordArkBugcheckGuard.Enabled, 0L);
    KswordARKBugcheckGuardRestoreFromCrashPath();
    if (firstHit) {
        KswordARKBugcheckGuardDelay(g_KswordArkBugcheckGuard.DelaySeconds);
    }
    if (tryIgnoreError) {
        // KeBugCheckEx is declared no-return and many callers have no valid
        // continuation. Returning is only a best-effort experiment and can
        // immediately fault or invoke another bugcheck.
        InterlockedExchange(&g_KswordArkBugcheckGuard.ErrorIgnored, 1L);
        InterlockedDecrement(&g_KswordArkBugcheckGuard.HookExecutions);
        return;
    }
    InterlockedDecrement(&g_KswordArkBugcheckGuard.HookExecutions);
    if (target != NULL) {
        target(BugCheckCode, Parameter1, Parameter2, Parameter3, Parameter4);
    }
    KeBugCheckEx(BugCheckCode, Parameter1, Parameter2, Parameter3, Parameter4);
}

static NTSTATUS
KswordARKBugcheckGuardEnableLocked(
    _In_ ULONG DelaySeconds,
    _In_ BOOLEAN TryIgnoreError
    )
{
    UNICODE_STRING routineName;
    NTSTATUS status = STATUS_SUCCESS;
    PVOID target = NULL;
    PMDL mdl = NULL;
    PVOID writableAlias = NULL;
    BOOLEAN pagesLocked = FALSE;
    if (InterlockedCompareExchange(&g_KswordArkBugcheckGuard.HookState, 0L, 0L) != KSWORD_ARK_BUGCHECK_GUARD_STATE_UNINSTALLED) {
        return STATUS_ALREADY_REGISTERED;
    }
    if (InterlockedCompareExchange(
            &g_KswordArkBugcheckGuard.HookExecutions,
            0L,
            0L) != 0L ||
        g_KswordArkBugcheckGuard.Target != NULL ||
        g_KswordArkBugcheckGuard.TargetMdl != NULL ||
        g_KswordArkBugcheckGuard.WritableAlias != NULL) {
        return STATUS_DEVICE_BUSY;
    }

    RtlInitUnicodeString(&routineName, L"KeBugCheckEx");
    target = MmGetSystemRoutineAddress(&routineName);
    if (target == NULL) {
        return STATUS_NOT_SUPPORTED;
    }
    mdl = IoAllocateMdl(target, KSWORD_ARK_BUGCHECK_GUARD_HOOK_BYTES, FALSE, FALSE, NULL);
    if (mdl == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    __try {
        MmProbeAndLockPages(mdl, KernelMode, IoReadAccess);
        pagesLocked = TRUE;
        writableAlias = MmMapLockedPagesSpecifyCache(
            mdl,
            KernelMode,
            MmCached,
            NULL,
            FALSE,
            NormalPagePriority | MdlMappingNoExecute);
        if (writableAlias == NULL) {
            status = STATUS_INSUFFICIENT_RESOURCES;
            __leave;
        }
        status = MmProtectMdlSystemAddress(mdl, PAGE_READWRITE);
        if (!NT_SUCCESS(status)) {
            __leave;
        }
        RtlCopyMemory(g_KswordArkBugcheckGuard.OriginalBytes, writableAlias, KSWORD_ARK_BUGCHECK_GUARD_HOOK_BYTES);
        if (KswordARKBugcheckGuardLooksHooked(g_KswordArkBugcheckGuard.OriginalBytes)) {
            status = STATUS_OBJECT_NAME_COLLISION;
            __leave;
        }
        KswordARKBugcheckGuardBuildHook(g_KswordArkBugcheckGuard.HookBytes);
        g_KswordArkBugcheckGuard.Target = target;
        g_KswordArkBugcheckGuard.TargetMdl = mdl;
        g_KswordArkBugcheckGuard.WritableAlias = writableAlias;
        g_KswordArkBugcheckGuard.DelaySeconds = DelaySeconds;
        InterlockedExchange(&g_KswordArkBugcheckGuard.Fired, 0L);
        InterlockedExchange(&g_KswordArkBugcheckGuard.TryIgnoreError, TryIgnoreError ? 1L : 0L);
        InterlockedExchange(&g_KswordArkBugcheckGuard.ErrorIgnored, 0L);
        InterlockedExchange(&g_KswordArkBugcheckGuard.HookExecutions, 0L);
        InterlockedExchange(&g_KswordArkBugcheckGuard.Enabled, 1L);
        InterlockedExchange(&g_KswordArkBugcheckGuard.HookState, KSWORD_ARK_BUGCHECK_GUARD_STATE_INSTALLED);
        RtlCopyMemory(writableAlias, g_KswordArkBugcheckGuard.HookBytes, KSWORD_ARK_BUGCHECK_GUARD_HOOK_BYTES);
        KeMemoryBarrier();
        KeInvalidateRangeAllCaches(target, KSWORD_ARK_BUGCHECK_GUARD_HOOK_BYTES);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();
    }

    if (!NT_SUCCESS(status)) {
        if (writableAlias != NULL &&
            InterlockedCompareExchange(
                &g_KswordArkBugcheckGuard.HookState,
                KSWORD_ARK_BUGCHECK_GUARD_STATE_RESTORING,
                KSWORD_ARK_BUGCHECK_GUARD_STATE_INSTALLED) ==
                KSWORD_ARK_BUGCHECK_GUARD_STATE_INSTALLED) {
            RtlCopyMemory(
                writableAlias,
                g_KswordArkBugcheckGuard.OriginalBytes,
                KSWORD_ARK_BUGCHECK_GUARD_HOOK_BYTES);
            KeMemoryBarrier();
            KeInvalidateRangeAllCaches(
                target,
                KSWORD_ARK_BUGCHECK_GUARD_HOOK_BYTES);
            InterlockedExchange(
                &g_KswordArkBugcheckGuard.HookState,
                KSWORD_ARK_BUGCHECK_GUARD_STATE_UNINSTALLED);
        }
        InterlockedExchange(&g_KswordArkBugcheckGuard.Enabled, 0L);
        InterlockedExchange(&g_KswordArkBugcheckGuard.TryIgnoreError, 0L);
        InterlockedExchange(&g_KswordArkBugcheckGuard.ErrorIgnored, 0L);
        InterlockedExchange(&g_KswordArkBugcheckGuard.HookExecutions, 0L);
        if (writableAlias != NULL) {
            MmUnmapLockedPages(writableAlias, mdl);
        }
        if (pagesLocked) {
            MmUnlockPages(mdl);
        }
        IoFreeMdl(mdl);
        g_KswordArkBugcheckGuard.Target = NULL;
        g_KswordArkBugcheckGuard.TargetMdl = NULL;
        g_KswordArkBugcheckGuard.WritableAlias = NULL;
        g_KswordArkBugcheckGuard.DelaySeconds = 0UL;
        RtlZeroMemory(g_KswordArkBugcheckGuard.OriginalBytes, sizeof(g_KswordArkBugcheckGuard.OriginalBytes));
        RtlZeroMemory(g_KswordArkBugcheckGuard.HookBytes, sizeof(g_KswordArkBugcheckGuard.HookBytes));
    }
    return status;
}

static VOID
KswordARKBugcheckGuardFillResponse(
    _Out_ KSWORD_ARK_BUGCHECK_GUARD_RESPONSE* Response,
    _In_ ULONG Status
    )
{
    RtlZeroMemory(Response, sizeof(*Response));
    Response->size = sizeof(*Response);
    Response->version = KSWORD_ARK_BUGCHECK_GUARD_PROTOCOL_VERSION;
    Response->status = Status;
    Response->stateFlags = KswordARKBugcheckGuardStateFlags();
    Response->delaySeconds = g_KswordArkBugcheckGuard.DelaySeconds;
    Response->lastStatus = g_KswordArkBugcheckGuard.LastStatus;
    Response->targetAddress = (ULONGLONG)(ULONG_PTR)g_KswordArkBugcheckGuard.Target;
    RtlCopyMemory(Response->originalBytes, g_KswordArkBugcheckGuard.OriginalBytes, sizeof(Response->originalBytes));
    RtlCopyMemory(Response->hookBytes, g_KswordArkBugcheckGuard.HookBytes, sizeof(Response->hookBytes));
}

VOID
KswordARKBugcheckGuardInitialize(
    VOID
    )
{
    RtlZeroMemory(&g_KswordArkBugcheckGuard, sizeof(g_KswordArkBugcheckGuard));
    ExInitializeFastMutex(&g_KswordArkBugcheckGuard.ControlLock);
    g_KswordArkBugcheckGuard.LastStatus = STATUS_SUCCESS;
}

VOID
KswordARKBugcheckGuardUninitialize(
    VOID
    )
{
    ExAcquireFastMutex(&g_KswordArkBugcheckGuard.ControlLock);
    KswordARKBugcheckGuardReleaseMappingLocked();
    g_KswordArkBugcheckGuard.LastStatus = STATUS_SUCCESS;
    ExReleaseFastMutex(&g_KswordArkBugcheckGuard.ControlLock);
}

NTSTATUS
KswordARKBugcheckGuardIoctlConfigure(
    _In_ WDFDEVICE Device,
    _In_ WDFREQUEST Request,
    _In_ size_t InputBufferLength,
    _In_ size_t OutputBufferLength,
    _Out_ size_t* BytesReturned
    )
{
    KSWORD_ARK_BUGCHECK_GUARD_REQUEST* input = NULL;
    KSWORD_ARK_BUGCHECK_GUARD_RESPONSE* output = NULL;
    NTSTATUS status;
    ULONG protocolStatus = KSWORD_ARK_BUGCHECK_GUARD_STATUS_INVALID_REQUEST;

    UNREFERENCED_PARAMETER(Device);

    if (BytesReturned == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *BytesReturned = 0U;
    status = WdfRequestRetrieveInputBuffer(
        Request,
        sizeof(*input),
        (PVOID*)&input,
        NULL);
    if (!NT_SUCCESS(status) || InputBufferLength < sizeof(*input)) {
        return NT_SUCCESS(status) ? STATUS_BUFFER_TOO_SMALL : status;
    }
    status = WdfRequestRetrieveOutputBuffer(
        Request,
        sizeof(*output),
        (PVOID*)&output,
        NULL);
    if (!NT_SUCCESS(status) || OutputBufferLength < sizeof(*output)) {
        return NT_SUCCESS(status) ? STATUS_BUFFER_TOO_SMALL : status;
    }

    ExAcquireFastMutex(&g_KswordArkBugcheckGuard.ControlLock);
    if (input->size != sizeof(*input) ||
        input->version != KSWORD_ARK_BUGCHECK_GUARD_PROTOCOL_VERSION ||
        input->reserved0 != 0UL ||
        input->reserved1 != 0UL ||
        (input->flags & ~(KSWORD_ARK_BUGCHECK_GUARD_FLAG_UI_CONFIRMED | KSWORD_ARK_BUGCHECK_GUARD_FLAG_TRY_IGNORE_ERROR)) != 0UL) {
        g_KswordArkBugcheckGuard.LastStatus = STATUS_INVALID_PARAMETER;
        protocolStatus = KSWORD_ARK_BUGCHECK_GUARD_STATUS_INVALID_REQUEST;
    }
    else if (input->action == KSWORD_ARK_BUGCHECK_GUARD_ACTION_QUERY) {
        protocolStatus =
            InterlockedCompareExchange(&g_KswordArkBugcheckGuard.HookState, 0L, 0L) ==
                KSWORD_ARK_BUGCHECK_GUARD_STATE_INSTALLED
            ? KSWORD_ARK_BUGCHECK_GUARD_STATUS_ACTIVE
            : KSWORD_ARK_BUGCHECK_GUARD_STATUS_INACTIVE;
    }
    else if (input->action == KSWORD_ARK_BUGCHECK_GUARD_ACTION_DISABLE) {
        KswordARKBugcheckGuardReleaseMappingLocked();
        g_KswordArkBugcheckGuard.LastStatus = STATUS_SUCCESS;
        protocolStatus = KSWORD_ARK_BUGCHECK_GUARD_STATUS_INACTIVE;
    }
    else if (input->action == KSWORD_ARK_BUGCHECK_GUARD_ACTION_ENABLE) {
        if ((input->flags & KSWORD_ARK_BUGCHECK_GUARD_FLAG_UI_CONFIRMED) == 0UL ||
            input->confirmationToken != KSWORD_ARK_BUGCHECK_GUARD_CONFIRMATION_TOKEN) {
            g_KswordArkBugcheckGuard.LastStatus = STATUS_ACCESS_DENIED;
            protocolStatus = KSWORD_ARK_BUGCHECK_GUARD_STATUS_CONFIRMATION_NEEDED;
        }
        else if (input->delaySeconds < KSWORD_ARK_BUGCHECK_GUARD_MIN_DELAY_SECONDS ||
                 input->delaySeconds > KSWORD_ARK_BUGCHECK_GUARD_MAX_DELAY_SECONDS) {
            g_KswordArkBugcheckGuard.LastStatus = STATUS_INVALID_PARAMETER;
            protocolStatus = KSWORD_ARK_BUGCHECK_GUARD_STATUS_INVALID_REQUEST;
        }
        else {
            status = KswordARKBugcheckGuardEnableLocked(
                input->delaySeconds,
                (input->flags & KSWORD_ARK_BUGCHECK_GUARD_FLAG_TRY_IGNORE_ERROR) != 0UL);
            g_KswordArkBugcheckGuard.LastStatus = status;
            if (status == STATUS_SUCCESS) {
                protocolStatus = KSWORD_ARK_BUGCHECK_GUARD_STATUS_ACTIVE;
            }
            else if (status == STATUS_ALREADY_REGISTERED) {
                protocolStatus = KSWORD_ARK_BUGCHECK_GUARD_STATUS_ACTIVE;
            }
            else if (status == STATUS_NOT_SUPPORTED) {
                protocolStatus = KSWORD_ARK_BUGCHECK_GUARD_STATUS_UNSUPPORTED;
            }
            else if (status == STATUS_OBJECT_NAME_COLLISION) {
                protocolStatus = KSWORD_ARK_BUGCHECK_GUARD_STATUS_CONFLICT;
            }
            else if (status == STATUS_DEVICE_BUSY) {
                protocolStatus = KSWORD_ARK_BUGCHECK_GUARD_STATUS_BUSY;
            }
            else {
                protocolStatus = KSWORD_ARK_BUGCHECK_GUARD_STATUS_PATCH_FAILED;
            }
        }
    }
    else {
        g_KswordArkBugcheckGuard.LastStatus = STATUS_INVALID_PARAMETER;
        protocolStatus = KSWORD_ARK_BUGCHECK_GUARD_STATUS_INVALID_REQUEST;
    }

    KswordARKBugcheckGuardFillResponse(output, protocolStatus);
    ExReleaseFastMutex(&g_KswordArkBugcheckGuard.ControlLock);
    *BytesReturned = sizeof(*output);
    return STATUS_SUCCESS;
}
