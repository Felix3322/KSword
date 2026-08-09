/*++

Module Name:

    process_protect_kernel.c

Abstract:

    Kernel protection layer for the process protection feature. Where the
    object-callback layer strips access on individual handle operations, this
    layer stamps EPROCESS.Protection (PP/PPL) on matching processes and keeps
    it stamped: it applies at process-create time so a restarted target is
    protected again, and a background scan restores the byte whenever something
    outside this driver clears it.

Environment:

    Kernel-mode Driver Framework

--*/

#include "process_protect_internal.h"

#include "ark/ark_process.h"
#include "../process/process_extended.h"

NTKERNELAPI
LONGLONG
NTAPI
PsGetProcessCreateTimeQuadPart(
    _In_ PEPROCESS Process
    );

// 一条已解析出来的"该给这个进程施加什么"的决定。
typedef struct _KSWORD_ARK_PROCESS_PROTECT_KERNEL_DECISION
{
    BOOLEAN Matched;
    BOOLEAN SelfHeal;
    UCHAR Protection;
    ULONG RuleId;
    ULONG RuleIndex;
    ULONG HardenFlags;
} KSWORD_ARK_PROCESS_PROTECT_KERNEL_DECISION;

static VOID
KswordArkProcessProtectResolveKernelDecision(
    _In_ KSWORD_ARK_PROCESS_PROTECT_STATE* State,
    _In_ ULONG ProcessId,
    _In_opt_z_ PCWSTR ImagePath,
    _Out_ KSWORD_ARK_PROCESS_PROTECT_KERNEL_DECISION* DecisionOut
    )
/*++

Routine Description:

    Pick the first enabled rule that both matches the process and carries a
    non-zero kernelProtection. Matching reuses the object-callback layer's
    comparison helper so one rule cannot mean two different things across the
    two layers.

--*/
{
    ULONG ruleIndex = 0UL;

    RtlZeroMemory(DecisionOut, sizeof(*DecisionOut));

    KswordARKAcquirePushLockShared(&State->ConfigLock);

    if ((State->GlobalFlags & KSWORD_ARK_PROCESS_PROTECT_FLAG_ENABLED) == 0UL ||
        (State->GlobalFlags & KSWORD_ARK_PROCESS_PROTECT_FLAG_KERNEL_PROTECTION) == 0UL) {
        KswordARKReleasePushLockShared(&State->ConfigLock);
        return;
    }

    for (ruleIndex = 0UL; ruleIndex < State->RuleCount; ++ruleIndex) {
        const KSWORD_ARK_PROCESS_PROTECT_RULE* protectRule = &State->Rules[ruleIndex];

        if ((protectRule->flags & KSWORD_ARK_PROCESS_PROTECT_RULE_FLAG_ENABLED) == 0UL ||
            protectRule->kernelProtection == 0UL) {
            continue;
        }
        if (!KswordArkProcessProtectIdentityMatchPublic(
                protectRule->targetKind,
                protectRule->targetProcessId,
                protectRule->targetImage,
                ProcessId,
                ImagePath)) {
            continue;
        }

        DecisionOut->Matched = TRUE;
        DecisionOut->SelfHeal =
            ((protectRule->flags & KSWORD_ARK_PROCESS_PROTECT_RULE_FLAG_SELF_HEAL) != 0UL) ? TRUE : FALSE;
        DecisionOut->Protection = (UCHAR)(protectRule->kernelProtection & 0xFFUL);
        DecisionOut->RuleId = protectRule->ruleId;
        DecisionOut->RuleIndex = ruleIndex;
        DecisionOut->HardenFlags = protectRule->hardenFlags;
        break;
    }

    KswordARKReleasePushLockShared(&State->ConfigLock);
}

static VOID
KswordArkProcessProtectTrackProcess(
    _In_ KSWORD_ARK_PROCESS_PROTECT_STATE* State,
    _In_ ULONG ProcessId,
    _In_ LONGLONG CreateTimeQuadPart,
    _In_ const KSWORD_ARK_PROCESS_PROTECT_KERNEL_DECISION* Decision
    )
/*++

Routine Description:

    Insert or refresh the tracking entry that the self-heal scan walks.
    Identity is (PID, creation time): PID alone is reusable, and re-stamping a
    recycled PID would put PP on an unrelated process.

--*/
{
    ULONG entryIndex = 0UL;
    BOOLEAN replaced = FALSE;

    KswordARKAcquirePushLockExclusive(&State->TrackedLock);

    for (entryIndex = 0UL; entryIndex < State->TrackedCount; ++entryIndex) {
        KSWORD_ARK_PROCESS_PROTECT_TRACKED_ENTRY* entry = &State->Tracked[entryIndex];
        if (entry->ProcessId != ProcessId) {
            continue;
        }
        entry->CreateTimeQuadPart = CreateTimeQuadPart;
        entry->RuleId = Decision->RuleId;
        entry->RuleIndex = Decision->RuleIndex;
        entry->ExpectedProtection = Decision->Protection;
        entry->HardenFlags = Decision->HardenFlags;
        replaced = TRUE;
        break;
    }

    if (!replaced && State->TrackedCount < KSWORD_ARK_PROCESS_PROTECT_MAX_TRACKED) {
        KSWORD_ARK_PROCESS_PROTECT_TRACKED_ENTRY* entry = &State->Tracked[State->TrackedCount];
        RtlZeroMemory(entry, sizeof(*entry));
        entry->ProcessId = ProcessId;
        entry->CreateTimeQuadPart = CreateTimeQuadPart;
        entry->RuleId = Decision->RuleId;
        entry->RuleIndex = Decision->RuleIndex;
        entry->ExpectedProtection = Decision->Protection;
        entry->HardenFlags = Decision->HardenFlags;
        State->TrackedCount += 1UL;
        replaced = TRUE;
    }

    KswordARKReleasePushLockExclusive(&State->TrackedLock);

    if (!replaced) {
        // 台账满了：保护本身已经打上，只是不再纳入自愈巡检。说明白比默默丢弃好。
        KswordArkProcessProtectLogFormat(
            State,
            "Warn",
            "Process protection tracking table full (%lu), pid=%lu keeps its protection but is not scanned.",
            (unsigned long)KSWORD_ARK_PROCESS_PROTECT_MAX_TRACKED,
            (unsigned long)ProcessId);
    }
}

VOID
KswordArkProcessProtectKernelUntrackProcess(
    _In_ ULONG ProcessId
    )
/*++

Routine Description:

    Drop a process from the self-heal table on exit. The scan would eventually
    notice too, but removing eagerly keeps the table from filling up with dead
    PIDs on machines that churn short-lived protected processes.

--*/
{
    KSWORD_ARK_PROCESS_PROTECT_STATE* state = KswordArkProcessProtectGetState();
    ULONG entryIndex = 0UL;

    if (state == NULL || ProcessId == 0UL) {
        return;
    }

    KswordARKAcquirePushLockExclusive(&state->TrackedLock);
    for (entryIndex = 0UL; entryIndex < state->TrackedCount; ++entryIndex) {
        if (state->Tracked[entryIndex].ProcessId != ProcessId) {
            continue;
        }
        if (entryIndex + 1UL < state->TrackedCount) {
            state->Tracked[entryIndex] = state->Tracked[state->TrackedCount - 1UL];
        }
        state->TrackedCount -= 1UL;
        RtlZeroMemory(&state->Tracked[state->TrackedCount], sizeof(state->Tracked[0]));
        break;
    }
    KswordARKReleasePushLockExclusive(&state->TrackedLock);
}

static VOID
KswordArkProcessProtectApplyHarden(
    _In_ KSWORD_ARK_PROCESS_PROTECT_STATE* State,
    _In_ PEPROCESS ProcessObject,
    _In_ ULONG ProcessId,
    _In_ ULONG HardenFlags
    )
{
    NTSTATUS status = STATUS_SUCCESS;

    if ((HardenFlags & KSWORD_ARK_PROCESS_PROTECT_HARDEN_CLEAR_DEBUG_PORT) == 0UL) {
        return;
    }

    status = KswordARKProcessClearDebugPortByObject(ProcessObject);
    if (NT_SUCCESS(status)) {
        (VOID)InterlockedIncrement64(&State->HardenApplyCount);
        return;
    }

    // DebugPort 偏移缺失是"这台机器的 DynData 不全"，不是配置错误，只记一次。
    KswordArkProcessProtectLogFormat(
        State,
        "Warn",
        "Process protection harden(clear debug port) failed, pid=%lu, status=0x%08lX.",
        (unsigned long)ProcessId,
        (unsigned long)status);
}

static BOOLEAN
KswordArkProcessProtectStampProcess(
    _In_ KSWORD_ARK_PROCESS_PROTECT_STATE* State,
    _In_ PEPROCESS ProcessObject,
    _In_ ULONG ProcessId,
    _In_ const KSWORD_ARK_PROCESS_PROTECT_KERNEL_DECISION* Decision
    )
/*++

Routine Description:

    Write the decided PS_PROTECTION byte onto the process and fold the outcome
    into the counters.

Return Value:

    TRUE when the byte was written and verified.

--*/
{
    const NTSTATUS status = KswordARKDriverApplyProcessProtectionToObject(
        ProcessObject,
        Decision->Protection);

    if (!NT_SUCCESS(status)) {
        (VOID)InterlockedIncrement64(&State->KernelApplyFailureCount);
        (VOID)InterlockedExchange(&State->LastKernelApplyStatus, (LONG)status);
        return FALSE;
    }

    (VOID)InterlockedIncrement64(&State->KernelApplyCount);
    if (Decision->RuleIndex < KSWORD_ARK_PROCESS_PROTECT_MAX_RULES) {
        (VOID)InterlockedIncrement64(&State->RuleKernelApplyCounts[Decision->RuleIndex]);
    }
    KswordArkProcessProtectApplyHarden(State, ProcessObject, ProcessId, Decision->HardenFlags);
    return TRUE;
}

VOID
KswordArkProcessProtectKernelApplyToProcess(
    _In_ PEPROCESS ProcessObject,
    _In_ ULONG ProcessId,
    _In_opt_z_ PCWSTR ImagePath
    )
{
    KSWORD_ARK_PROCESS_PROTECT_STATE* state = KswordArkProcessProtectGetState();
    KSWORD_ARK_PROCESS_PROTECT_KERNEL_DECISION decision;

    if (state == NULL || ProcessObject == NULL || ProcessId == 0UL) {
        return;
    }

    KswordArkProcessProtectResolveKernelDecision(state, ProcessId, ImagePath, &decision);
    if (!decision.Matched) {
        return;
    }

    if (!KswordArkProcessProtectStampProcess(state, ProcessObject, ProcessId, &decision)) {
        return;
    }

    if (decision.SelfHeal) {
        KswordArkProcessProtectTrackProcess(
            state,
            ProcessId,
            PsGetProcessCreateTimeQuadPart(ProcessObject),
            &decision);
    }

    KswordArkProcessProtectLogFormat(
        state,
        "Info",
        "Process protection applied, pid=%lu, protection=0x%02lX, ruleId=%lu, harden=0x%08lX.",
        (unsigned long)ProcessId,
        (unsigned long)decision.Protection,
        (unsigned long)decision.RuleId,
        (unsigned long)decision.HardenFlags);
}

VOID
KswordArkProcessProtectNotifyProcessCreate(
    _In_ PEPROCESS ProcessObject,
    _In_ ULONG ProcessId,
    _In_opt_ PCUNICODE_STRING ImageFileName
    )
{
    WCHAR imagePathBuffer[KSWORD_ARK_PROCESS_PROTECT_IMAGE_CHARS] = { 0 };
    USHORT copyChars = 0U;

    if (ProcessObject == NULL || ProcessId == 0UL) {
        return;
    }

    // 创建通知给的是 UNICODE_STRING 且未必带终止符，先落成 NUL 结尾的定长串。
    if (ImageFileName != NULL && ImageFileName->Buffer != NULL && ImageFileName->Length != 0U) {
        copyChars = (USHORT)(ImageFileName->Length / sizeof(WCHAR));
        if (copyChars >= KSWORD_ARK_PROCESS_PROTECT_IMAGE_CHARS) {
            copyChars = (USHORT)(KSWORD_ARK_PROCESS_PROTECT_IMAGE_CHARS - 1U);
        }
        RtlCopyMemory(imagePathBuffer, ImageFileName->Buffer, (SIZE_T)copyChars * sizeof(WCHAR));
    }
    imagePathBuffer[copyChars] = L'\0';

    KswordArkProcessProtectKernelApplyToProcess(ProcessObject, ProcessId, imagePathBuffer);
}

VOID
KswordArkProcessProtectNotifyProcessExit(
    _In_ ULONG ProcessId
    )
{
    KswordArkProcessProtectKernelUntrackProcess(ProcessId);
}

static VOID
KswordArkProcessProtectRecordTamper(
    _In_ KSWORD_ARK_PROCESS_PROTECT_STATE* State,
    _In_ const KSWORD_ARK_PROCESS_PROTECT_TRACKED_ENTRY* Entry,
    _In_ UCHAR ObservedProtection,
    _In_opt_z_ PCWSTR ImagePath
    )
{
    LARGE_INTEGER nowUtc = { 0 };

    KeQuerySystemTimePrecise(&nowUtc);

    KswordARKAcquirePushLockExclusive(&State->LastTamperLock);
    State->LastTamperUtc100ns = nowUtc;
    State->LastTamperProcessId = Entry->ProcessId;
    State->LastTamperObservedProtection = (ULONG)ObservedProtection;
    State->LastTamperExpectedProtection = (ULONG)Entry->ExpectedProtection;
    State->LastTamperRuleId = Entry->RuleId;
    KswordArkProcessProtectCopyFixedWideText(
        State->LastTamperImage,
        KSWORD_ARK_PROCESS_PROTECT_IMAGE_CHARS,
        ImagePath);
    KswordARKReleasePushLockExclusive(&State->LastTamperLock);
}

static VOID
KswordArkProcessProtectScanOnce(
    _In_ KSWORD_ARK_PROCESS_PROTECT_STATE* State,
    _Inout_updates_(KSWORD_ARK_PROCESS_PROTECT_MAX_TRACKED)
        KSWORD_ARK_PROCESS_PROTECT_TRACKED_ENTRY* Snapshot,
    _Inout_updates_(KSWORD_ARK_PROCESS_PROTECT_MAX_TRACKED) ULONG* StaleProcessIds
    )
/*++

Routine Description:

    One self-heal pass. The tracked table is snapshotted under a shared lock and
    then walked without holding it: PsLookupProcessByProcessId plus an EPROCESS
    write per entry is far too long to keep process creation waiting on the
    exclusive lock.

--*/
{
    ULONG snapshotCount = 0UL;
    ULONG staleCount = 0UL;
    ULONG entryIndex = 0UL;

    KswordARKAcquirePushLockShared(&State->TrackedLock);
    snapshotCount = State->TrackedCount;
    if (snapshotCount > KSWORD_ARK_PROCESS_PROTECT_MAX_TRACKED) {
        snapshotCount = KSWORD_ARK_PROCESS_PROTECT_MAX_TRACKED;
    }
    if (snapshotCount != 0UL) {
        RtlCopyMemory(Snapshot, State->Tracked, (SIZE_T)snapshotCount * sizeof(Snapshot[0]));
    }
    KswordARKReleasePushLockShared(&State->TrackedLock);

    for (entryIndex = 0UL; entryIndex < snapshotCount; ++entryIndex) {
        const KSWORD_ARK_PROCESS_PROTECT_TRACKED_ENTRY* entry = &Snapshot[entryIndex];
        PEPROCESS processObject = NULL;
        UCHAR observedProtection = 0U;
        NTSTATUS status = STATUS_SUCCESS;

        status = PsLookupProcessByProcessId(ULongToHandle(entry->ProcessId), &processObject);
        if (!NT_SUCCESS(status) || processObject == NULL) {
            StaleProcessIds[staleCount++] = entry->ProcessId;
            continue;
        }

        // PID 复用检测：创建时间对不上说明这个 PID 已经属于另一个进程。
        if (PsGetProcessCreateTimeQuadPart(processObject) != entry->CreateTimeQuadPart) {
            StaleProcessIds[staleCount++] = entry->ProcessId;
            ObDereferenceObject(processObject);
            continue;
        }

        status = KswordARKProcessReadProtectionByte(processObject, &observedProtection);
        if (NT_SUCCESS(status) && observedProtection != entry->ExpectedProtection) {
            KSWORD_ARK_PROCESS_PROTECT_KERNEL_DECISION healDecision;
            WCHAR imagePathBuffer[KSWORD_ARK_PROCESS_PROTECT_IMAGE_CHARS] = { 0 };

            RtlZeroMemory(&healDecision, sizeof(healDecision));
            healDecision.Matched = TRUE;
            healDecision.Protection = entry->ExpectedProtection;
            healDecision.RuleId = entry->RuleId;
            healDecision.RuleIndex = entry->RuleIndex;
            healDecision.HardenFlags = entry->HardenFlags;

            (VOID)KswordArkResolveProcessImagePath(
                processObject,
                imagePathBuffer,
                RTL_NUMBER_OF(imagePathBuffer),
                NULL);
            KswordArkProcessProtectRecordTamper(State, entry, observedProtection, imagePathBuffer);

            if (KswordArkProcessProtectStampProcess(
                    State,
                    processObject,
                    entry->ProcessId,
                    &healDecision)) {
                (VOID)InterlockedIncrement64(&State->SelfHealCount);
                KswordArkProcessProtectLogFormat(
                    State,
                    "Warn",
                    "Process protection self-healed, pid=%lu, observed=0x%02lX, restored=0x%02lX, ruleId=%lu.",
                    (unsigned long)entry->ProcessId,
                    (unsigned long)observedProtection,
                    (unsigned long)entry->ExpectedProtection,
                    (unsigned long)entry->RuleId);
            }
        }

        ObDereferenceObject(processObject);
    }

    for (entryIndex = 0UL; entryIndex < staleCount; ++entryIndex) {
        KswordArkProcessProtectKernelUntrackProcess(StaleProcessIds[entryIndex]);
    }
}

static KSTART_ROUTINE KswordArkProcessProtectScanThread;

static VOID
KswordArkProcessProtectScanThread(
    _In_ PVOID StartContext
    )
{
    KSWORD_ARK_PROCESS_PROTECT_STATE* state = (KSWORD_ARK_PROCESS_PROTECT_STATE*)StartContext;
    KSWORD_ARK_PROCESS_PROTECT_TRACKED_ENTRY* snapshot = NULL;
    ULONG* staleProcessIds = NULL;

    // 快照缓冲一次性分配：每轮在栈上放 256 项会直接吃掉内核栈。
    snapshot = (KSWORD_ARK_PROCESS_PROTECT_TRACKED_ENTRY*)KswordArkAllocateNonPaged(
        sizeof(KSWORD_ARK_PROCESS_PROTECT_TRACKED_ENTRY) * KSWORD_ARK_PROCESS_PROTECT_MAX_TRACKED,
        KSWORD_ARK_PROCESS_PROTECT_TAG_STATE);
    staleProcessIds = (ULONG*)KswordArkAllocateNonPaged(
        sizeof(ULONG) * KSWORD_ARK_PROCESS_PROTECT_MAX_TRACKED,
        KSWORD_ARK_PROCESS_PROTECT_TAG_STATE);

    if (snapshot == NULL || staleProcessIds == NULL) {
        KswordArkProcessProtectLogFormat(
            state,
            "Warn",
            "Process protection scan thread cannot allocate its buffers; self-heal is disabled.");
    }

    while (InterlockedCompareExchange(&state->ScanStopping, 0L, 0L) == 0L) {
        LARGE_INTEGER waitTimeout;
        ULONG intervalMs = 0UL;
        BOOLEAN scanEnabled = FALSE;

        KswordARKAcquirePushLockShared(&state->ConfigLock);
        intervalMs = state->ScanIntervalMs;
        scanEnabled =
            ((state->GlobalFlags & KSWORD_ARK_PROCESS_PROTECT_FLAG_ENABLED) != 0UL &&
             (state->GlobalFlags & KSWORD_ARK_PROCESS_PROTECT_FLAG_KERNEL_PROTECTION) != 0UL &&
             (state->GlobalFlags & KSWORD_ARK_PROCESS_PROTECT_FLAG_SELF_HEAL_SCAN) != 0UL)
            ? TRUE
            : FALSE;
        KswordARKReleasePushLockShared(&state->ConfigLock);

        if (intervalMs < KSWORD_ARK_PROCESS_PROTECT_SCAN_INTERVAL_MIN_MS ||
            intervalMs > KSWORD_ARK_PROCESS_PROTECT_SCAN_INTERVAL_MAX_MS) {
            intervalMs = KSWORD_ARK_PROCESS_PROTECT_SCAN_INTERVAL_DEFAULT_MS;
        }

        if (scanEnabled && snapshot != NULL && staleProcessIds != NULL) {
            KswordArkProcessProtectScanOnce(state, snapshot, staleProcessIds);
        }

        // 负值 = 相对超时，单位 100ns。停止时事件会立刻把等待打断。
        waitTimeout.QuadPart = -((LONGLONG)intervalMs * 10000LL);
        (VOID)KeWaitForSingleObject(
            &state->ScanWakeEvent,
            Executive,
            KernelMode,
            FALSE,
            &waitTimeout);
    }

    if (snapshot != NULL) {
        ExFreePoolWithTag(snapshot, KSWORD_ARK_PROCESS_PROTECT_TAG_STATE);
    }
    if (staleProcessIds != NULL) {
        ExFreePoolWithTag(staleProcessIds, KSWORD_ARK_PROCESS_PROTECT_TAG_STATE);
    }
    PsTerminateSystemThread(STATUS_SUCCESS);
}

NTSTATUS
KswordArkProcessProtectKernelStart(
    _In_ KSWORD_ARK_PROCESS_PROTECT_STATE* State
    )
{
    HANDLE threadHandle = NULL;
    OBJECT_ATTRIBUTES threadAttributes;
    NTSTATUS status = STATUS_SUCCESS;

    if (State == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    if (State->ScanThread != NULL) {
        return STATUS_SUCCESS;
    }

    InitializeObjectAttributes(&threadAttributes, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
    status = PsCreateSystemThread(
        &threadHandle,
        THREAD_ALL_ACCESS,
        &threadAttributes,
        NULL,
        NULL,
        KswordArkProcessProtectScanThread,
        State);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    // 卸载时要等线程退出，所以换成对象引用保存；句柄本身立刻关掉。
    status = ObReferenceObjectByHandle(
        threadHandle,
        THREAD_ALL_ACCESS,
        *PsThreadType,
        KernelMode,
        (PVOID*)&State->ScanThread,
        NULL);
    ZwClose(threadHandle);
    if (!NT_SUCCESS(status)) {
        // 线程已经跑起来了，但拿不到引用就无法安全等待它退出；
        // 让它自己按停止标志收尾，本次启动记为失败。
        State->ScanThread = NULL;
        (VOID)InterlockedExchange(&State->ScanStopping, 1L);
        KeSetEvent(&State->ScanWakeEvent, IO_NO_INCREMENT, FALSE);
        return status;
    }
    return STATUS_SUCCESS;
}

VOID
KswordArkProcessProtectKernelStop(
    _In_ KSWORD_ARK_PROCESS_PROTECT_STATE* State
    )
{
    if (State == NULL) {
        return;
    }

    (VOID)InterlockedExchange(&State->ScanStopping, 1L);
    KeSetEvent(&State->ScanWakeEvent, IO_NO_INCREMENT, FALSE);

    if (State->ScanThread != NULL) {
        (VOID)KeWaitForSingleObject(State->ScanThread, Executive, KernelMode, FALSE, NULL);
        ObDereferenceObject(State->ScanThread);
        State->ScanThread = NULL;
    }
}

VOID
KswordArkProcessProtectKernelResetTracking(
    _In_ KSWORD_ARK_PROCESS_PROTECT_STATE* State
    )
{
    if (State == NULL) {
        return;
    }

    // 换表后旧台账里的期望值可能已经不属于任何规则；继续自愈等于按已删除的
    // 规则强行维持保护。清空后由下一次进程创建或用户重新下发来重建。
    KswordARKAcquirePushLockExclusive(&State->TrackedLock);
    RtlZeroMemory(State->Tracked, sizeof(State->Tracked));
    State->TrackedCount = 0UL;
    KswordARKReleasePushLockExclusive(&State->TrackedLock);
}
