/*++

Module Name:

    callback_waiter.c

Abstract:

    WAIT/ANSWER/CANCEL model and pending-decision context management.

Environment:

    Kernel-mode Driver Framework

--*/

#include "callback_internal.h"
#include "ark/ark_push_lock.h"

static VOID
KswordArkPendingDecisionReference(
    _In_ KSWORD_ARK_PENDING_DECISION* pendingDecision
    )
{
    if (pendingDecision != NULL) {
        (VOID)InterlockedIncrement(&pendingDecision->RefCount);
    }
}

static VOID
KswordArkPendingDecisionRelease(
    _In_opt_ KSWORD_ARK_PENDING_DECISION* pendingDecision
    )
{
    if (pendingDecision == NULL) {
        return;
    }

    if (InterlockedDecrement(&pendingDecision->RefCount) == 0) {
        ExFreePoolWithTag(pendingDecision, KSWORD_ARK_CALLBACK_TAG_PENDING);
    }
}

static KSWORD_ARK_PENDING_DECISION*
KswordArkFindPendingDecisionByGuidLocked(
    _In_ KSWORD_ARK_CALLBACK_RUNTIME* runtime,
    _In_ const KSWORD_ARK_GUID128* eventGuid
    )
{
    PLIST_ENTRY currentEntry = NULL;

    if (runtime == NULL || eventGuid == NULL) {
        return NULL;
    }

    currentEntry = runtime->PendingDecisionList.Flink;
    while (currentEntry != &runtime->PendingDecisionList) {
        KSWORD_ARK_PENDING_DECISION* currentDecision =
            CONTAINING_RECORD(currentEntry, KSWORD_ARK_PENDING_DECISION, Link);
        if (KswordArkGuidEquals(&currentDecision->EventGuid, eventGuid)) {
            return currentDecision;
        }
        currentEntry = currentEntry->Flink;
    }

    return NULL;
}

static BOOLEAN
KswordArkInsertPendingDecision(
    _In_ KSWORD_ARK_CALLBACK_RUNTIME* runtime,
    _In_ KSWORD_ARK_PENDING_DECISION* pendingDecision
    )
{
    BOOLEAN inserted = FALSE;

    if (runtime == NULL || pendingDecision == NULL) {
        return FALSE;
    }

    KswordARKAcquirePushLockExclusive(&runtime->PendingLock);
    // 卸载已开始时不再发布新的等待项，避免注销回调后留下无法被唤醒的等待者。
    if (InterlockedCompareExchange(&runtime->Stopping, 0L, 0L) == 0L) {
        InsertTailList(&runtime->PendingDecisionList, &pendingDecision->Link);
        KswordArkPendingDecisionReference(pendingDecision); // list reference
        (VOID)InterlockedIncrement(&runtime->PendingDecisionCount);
        inserted = TRUE;
    }
    KswordARKReleasePushLockExclusive(&runtime->PendingLock);
    return inserted;
}

static VOID
KswordArkRemovePendingDecision(
    _In_ KSWORD_ARK_CALLBACK_RUNTIME* runtime,
    _In_ KSWORD_ARK_PENDING_DECISION* pendingDecision
    )
{
    BOOLEAN removed = FALSE;

    KswordARKAcquirePushLockExclusive(&runtime->PendingLock);
    if (pendingDecision->Link.Flink != NULL && pendingDecision->Link.Blink != NULL) {
        RemoveEntryList(&pendingDecision->Link);
        // 链接只在持有 PendingLock 时清零，取消路径据此识别已脱链的项。
        pendingDecision->Link.Flink = NULL;
        pendingDecision->Link.Blink = NULL;
        (VOID)InterlockedDecrement(&runtime->PendingDecisionCount);
        removed = TRUE;
    }
    KswordARKReleasePushLockExclusive(&runtime->PendingLock);

    if (removed) {
        KswordArkPendingDecisionRelease(pendingDecision); // drop list reference
    }
}

static VOID
KswordArkBuildEventPacket(
    _In_ const KSWORD_ARK_PENDING_DECISION* pendingDecision,
    _Out_ KSWORD_ARK_CALLBACK_EVENT_PACKET* packetOut
    )
{
    if (pendingDecision == NULL || packetOut == NULL) {
        return;
    }

    RtlZeroMemory(packetOut, sizeof(*packetOut));
    packetOut->size = sizeof(*packetOut);
    packetOut->version = KSWORD_ARK_CALLBACK_PROTOCOL_VERSION;
    packetOut->eventGuid = pendingDecision->EventGuid;
    packetOut->callbackType = pendingDecision->CallbackType;
    packetOut->operationType = pendingDecision->OperationType;
    packetOut->action = pendingDecision->Match.Action;
    packetOut->matchMode = pendingDecision->Match.MatchMode;
    packetOut->defaultDecision = pendingDecision->DefaultDecision;
    packetOut->timeoutMs = pendingDecision->TimeoutMs;
    packetOut->groupId = pendingDecision->Match.GroupId;
    packetOut->ruleId = pendingDecision->Match.RuleId;
    packetOut->groupPriority = pendingDecision->Match.GroupPriority;
    packetOut->rulePriority = pendingDecision->Match.RulePriority;
    packetOut->originatingPid = pendingDecision->OriginatingPid;
    packetOut->originatingTid = pendingDecision->OriginatingTid;
    packetOut->sessionId = pendingDecision->SessionId;
    packetOut->pathUnavailable = pendingDecision->PathUnavailable;
    packetOut->createdAtUtc100ns = (ULONG64)pendingDecision->CreatedAtUtc100ns.QuadPart;
    packetOut->deadlineUtc100ns = (ULONG64)pendingDecision->DeadlineUtc100ns.QuadPart;

    KswordArkCopyWideStringToFixedBuffer(
        pendingDecision->InitiatorPath,
        packetOut->initiatorPath,
        RTL_NUMBER_OF(packetOut->initiatorPath));
    KswordArkCopyWideStringToFixedBuffer(
        pendingDecision->TargetPath,
        packetOut->targetPath,
        RTL_NUMBER_OF(packetOut->targetPath));
    KswordArkCopyWideStringToFixedBuffer(
        pendingDecision->Match.RuleInitiatorPattern,
        packetOut->ruleInitiatorPattern,
        RTL_NUMBER_OF(packetOut->ruleInitiatorPattern));
    KswordArkCopyWideStringToFixedBuffer(
        pendingDecision->Match.RuleTargetPattern,
        packetOut->ruleTargetPattern,
        RTL_NUMBER_OF(packetOut->ruleTargetPattern));
    KswordArkCopyWideStringToFixedBuffer(
        pendingDecision->Match.GroupName,
        packetOut->groupName,
        RTL_NUMBER_OF(packetOut->groupName));
    KswordArkCopyWideStringToFixedBuffer(
        pendingDecision->Match.RuleName,
        packetOut->ruleName,
        RTL_NUMBER_OF(packetOut->ruleName));
}

static NTSTATUS
KswordArkDispatchEventToWaitingRequest(
    _In_ KSWORD_ARK_CALLBACK_RUNTIME* runtime,
    _In_ const KSWORD_ARK_PENDING_DECISION* pendingDecision
    )
{
    WDFREQUEST waitRequest = WDF_NO_HANDLE;
    KSWORD_ARK_CALLBACK_EVENT_PACKET eventPacket;
    NTSTATUS status = STATUS_SUCCESS;
    PVOID outputBuffer = NULL;
    size_t outputLength = 0;

    if (runtime == NULL || runtime->WaitQueue == WDF_NO_HANDLE || pendingDecision == NULL) {
        return STATUS_INVALID_DEVICE_STATE;
    }

    status = WdfIoQueueRetrieveNextRequest(runtime->WaitQueue, &waitRequest);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = WdfRequestRetrieveOutputBuffer(
        waitRequest,
        sizeof(KSWORD_ARK_CALLBACK_EVENT_PACKET),
        &outputBuffer,
        &outputLength);
    if (!NT_SUCCESS(status)) {
        WdfRequestCompleteWithInformation(waitRequest, status, 0U);
        return status;
    }

    KswordArkBuildEventPacket(pendingDecision, &eventPacket);
    RtlCopyMemory(outputBuffer, &eventPacket, sizeof(eventPacket));
    WdfRequestCompleteWithInformation(waitRequest, STATUS_SUCCESS, sizeof(eventPacket));
    return STATUS_SUCCESS;
}

NTSTATUS
KswordArkCallbackWaiterInitialize(
    _In_ KSWORD_ARK_CALLBACK_RUNTIME* runtime
    )
{
    WDF_IO_QUEUE_CONFIG queueConfig;
    WDF_OBJECT_ATTRIBUTES queueAttributes;
    NTSTATUS status = STATUS_SUCCESS;

    if (runtime == NULL || runtime->Device == WDF_NO_HANDLE) {
        return STATUS_INVALID_PARAMETER;
    }

    WDF_IO_QUEUE_CONFIG_INIT(&queueConfig, WdfIoQueueDispatchManual);
    queueConfig.PowerManaged = WdfFalse;

    WDF_OBJECT_ATTRIBUTES_INIT(&queueAttributes);
    queueAttributes.ParentObject = runtime->Device;

    status = WdfIoQueueCreate(
        runtime->Device,
        &queueConfig,
        &queueAttributes,
        &runtime->WaitQueue);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    return STATUS_SUCCESS;
}

VOID
KswordArkCallbackWaiterUninitialize(
    _In_ KSWORD_ARK_CALLBACK_RUNTIME* runtime
    )
{
    if (runtime == NULL) {
        return;
    }

    // 不能通过全局运行时查询取消项，因为卸载会先撤销全局发布再销毁此队列。
    (VOID)KswordArkCallbackCancelAllPendingForRuntime(runtime);
    if (runtime->WaitQueue != WDF_NO_HANDLE) {
        WdfIoQueuePurgeSynchronously(runtime->WaitQueue);
        WdfObjectDelete(runtime->WaitQueue);
        runtime->WaitQueue = WDF_NO_HANDLE;
    }
}

NTSTATUS
KswordArkCallbackIoctlWaitEventInternal(
    _In_ WDFREQUEST Request,
    _In_ size_t OutputBufferLength,
    _Out_ size_t* CompleteBytesOut
    )
{
    KSWORD_ARK_CALLBACK_RUNTIME* runtime = KswordArkCallbackGetRuntime();
    NTSTATUS status = STATUS_SUCCESS;
    UNREFERENCED_PARAMETER(OutputBufferLength);

    if (CompleteBytesOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *CompleteBytesOut = 0U;

    if (runtime == NULL || runtime->WaitQueue == WDF_NO_HANDLE) {
        return STATUS_INVALID_DEVICE_STATE;
    }

    status = WdfRequestForwardToIoQueue(Request, runtime->WaitQueue);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    return STATUS_PENDING;
}

NTSTATUS
KswordArkCallbackIoctlAnswerEventInternal(
    _In_ WDFREQUEST Request,
    _In_ size_t InputBufferLength,
    _Out_ size_t* CompleteBytesOut
    )
{
    KSWORD_ARK_CALLBACK_RUNTIME* runtime = KswordArkCallbackGetRuntime();
    KSWORD_ARK_CALLBACK_ANSWER_REQUEST* answerRequest = NULL;
    size_t answerLength = 0;
    KSWORD_ARK_PENDING_DECISION* matchedDecision = NULL;
    NTSTATUS status = STATUS_SUCCESS;

    if (CompleteBytesOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *CompleteBytesOut = 0U;

    if (runtime == NULL) {
        return STATUS_INVALID_DEVICE_STATE;
    }

    status = WdfRequestRetrieveInputBuffer(
        Request,
        sizeof(KSWORD_ARK_CALLBACK_ANSWER_REQUEST),
        (PVOID*)&answerRequest,
        &answerLength);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    if (InputBufferLength < sizeof(KSWORD_ARK_CALLBACK_ANSWER_REQUEST) ||
        answerRequest->size < sizeof(KSWORD_ARK_CALLBACK_ANSWER_REQUEST) ||
        answerRequest->version != KSWORD_ARK_CALLBACK_PROTOCOL_VERSION) {
        return STATUS_INVALID_PARAMETER;
    }

    if (answerRequest->decision != KSWORD_ARK_DECISION_ALLOW &&
        answerRequest->decision != KSWORD_ARK_DECISION_DENY) {
        return STATUS_INVALID_PARAMETER;
    }

    // 答复、超时和取消都在同一把锁下仲裁 FinalDecision，避免超时覆盖已接受的答复。
    KswordARKAcquirePushLockExclusive(&runtime->PendingLock);
    matchedDecision = KswordArkFindPendingDecisionByGuidLocked(runtime, &answerRequest->eventGuid);
    if (matchedDecision == NULL) {
        KswordARKReleasePushLockExclusive(&runtime->PendingLock);
        return STATUS_NOT_FOUND;
    }

    if (InterlockedCompareExchange(&matchedDecision->Answered, 0L, 0L) != 0L) {
        KswordARKReleasePushLockExclusive(&runtime->PendingLock);
        return STATUS_ALREADY_COMMITTED;
    }

    matchedDecision->FinalDecision = answerRequest->decision;
    (VOID)InterlockedExchange(&matchedDecision->Answered, 1L);
    // 答复线程在锁外发信号前持有临时引用，防止并发超时路径释放该对象。
    KswordArkPendingDecisionReference(matchedDecision);
    KswordARKReleasePushLockExclusive(&runtime->PendingLock);
    KeSetEvent(&matchedDecision->DecisionEvent, IO_NO_INCREMENT, FALSE);
    *CompleteBytesOut = sizeof(KSWORD_ARK_CALLBACK_ANSWER_REQUEST);
    KswordArkPendingDecisionRelease(matchedDecision);
    return STATUS_SUCCESS;
}

NTSTATUS
KswordArkCallbackCancelAllPendingForRuntime(
    _In_ KSWORD_ARK_CALLBACK_RUNTIME* runtime
    )
{
    if (runtime == NULL) {
        return STATUS_INVALID_DEVICE_STATE;
    }

    for (;;) {
        KSWORD_ARK_PENDING_DECISION* pendingDecision = NULL;

        KswordARKAcquirePushLockExclusive(&runtime->PendingLock);
        if (!IsListEmpty(&runtime->PendingDecisionList)) {
            PLIST_ENTRY entry = RemoveHeadList(&runtime->PendingDecisionList);

            pendingDecision = CONTAINING_RECORD(entry, KSWORD_ARK_PENDING_DECISION, Link);
            // 先在受保护的原链表中脱链，绝不把节点暂挂到未受保护的本地链表。
            pendingDecision->Link.Flink = NULL;
            pendingDecision->Link.Blink = NULL;
            (VOID)InterlockedDecrement(&runtime->PendingDecisionCount);
            if (InterlockedCompareExchange(&pendingDecision->Answered, 0L, 0L) == 0L) {
                pendingDecision->FinalDecision = pendingDecision->DefaultDecision;
                (VOID)InterlockedExchange(&pendingDecision->Answered, 1L);
            }
        }
        KswordARKReleasePushLockExclusive(&runtime->PendingLock);

        if (pendingDecision == NULL) {
            break;
        }

        // 无条件置位事件，覆盖答复线程已提交但尚未来得及发信号的窄窗口。
        KeSetEvent(&pendingDecision->DecisionEvent, IO_NO_INCREMENT, FALSE);
        KswordArkPendingDecisionRelease(pendingDecision); // drop list reference
    }

    return STATUS_SUCCESS;
}

NTSTATUS
KswordArkCallbackCancelAllPendingInternal(
    VOID
    )
{
    KSWORD_ARK_CALLBACK_RUNTIME* runtime = KswordArkCallbackGetRuntime();

    return KswordArkCallbackCancelAllPendingForRuntime(runtime);
}

NTSTATUS
KswordArkCallbackAskUserDecision(
    _In_ const KSWORD_ARK_CALLBACK_EVENT_INPUT* eventInput,
    _Out_ ULONG* decisionOut
    )
{
    KSWORD_ARK_CALLBACK_RUNTIME* runtime = KswordArkCallbackGetRuntime();
    KSWORD_ARK_PENDING_DECISION* pendingDecision = NULL;
    NTSTATUS dispatchStatus = STATUS_SUCCESS;
    NTSTATUS waitStatus = STATUS_SUCCESS;
    LARGE_INTEGER timeoutInterval = { 0 };
    ULONGLONG timeout100ns = 0;
    ULONG waitTimeoutMs = 0;

    if (decisionOut == NULL || eventInput == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *decisionOut = KSWORD_ARK_DECISION_ALLOW;

    if (runtime == NULL || runtime->WaitQueue == WDF_NO_HANDLE) {
        return STATUS_INVALID_DEVICE_STATE;
    }

    if (InterlockedCompareExchange(&runtime->Stopping, 0L, 0L) != 0L) {
        // 卸载中的回调必须立即采用规则默认值，不能再创建会阻塞注销流程的等待项。
        *decisionOut = eventInput->Match.AskDefaultDecision;
        if (*decisionOut != KSWORD_ARK_DECISION_DENY) {
            *decisionOut = KSWORD_ARK_DECISION_ALLOW;
        }
        return STATUS_DEVICE_NOT_READY;
    }

    if (KeGetCurrentIrql() > APC_LEVEL) {
        *decisionOut = eventInput->Match.AskDefaultDecision;
        if (*decisionOut != KSWORD_ARK_DECISION_DENY) {
            *decisionOut = KSWORD_ARK_DECISION_ALLOW;
        }
        return STATUS_UNSUCCESSFUL;
    }

    pendingDecision = (KSWORD_ARK_PENDING_DECISION*)KswordArkAllocateNonPaged(
        sizeof(KSWORD_ARK_PENDING_DECISION),
        KSWORD_ARK_CALLBACK_TAG_PENDING);
    if (pendingDecision == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlZeroMemory(pendingDecision, sizeof(*pendingDecision));

    pendingDecision->RefCount = 1;
    pendingDecision->Answered = 0;
    KswordArkGuidGenerate(&pendingDecision->EventGuid);
    KeInitializeEvent(&pendingDecision->DecisionEvent, NotificationEvent, FALSE);

    pendingDecision->CallbackType = eventInput->CallbackType;
    pendingDecision->OperationType = eventInput->OperationType;
    pendingDecision->OriginatingPid = eventInput->OriginatingPid;
    pendingDecision->OriginatingTid = eventInput->OriginatingTid;
    pendingDecision->SessionId = eventInput->SessionId;
    pendingDecision->PathUnavailable = eventInput->PathUnavailable;
    pendingDecision->Match = eventInput->Match;
    pendingDecision->TimeoutMs = eventInput->Match.AskTimeoutMs;
    if (pendingDecision->TimeoutMs == 0U) {
        pendingDecision->TimeoutMs = 5000U;
    }
    pendingDecision->DefaultDecision = eventInput->Match.AskDefaultDecision;
    if (pendingDecision->DefaultDecision != KSWORD_ARK_DECISION_ALLOW &&
        pendingDecision->DefaultDecision != KSWORD_ARK_DECISION_DENY) {
        pendingDecision->DefaultDecision = KSWORD_ARK_DECISION_ALLOW;
    }
    pendingDecision->FinalDecision = pendingDecision->DefaultDecision;
    KswordArkGetSystemTimeUtc100ns(&pendingDecision->CreatedAtUtc100ns);
    pendingDecision->DeadlineUtc100ns.QuadPart =
        pendingDecision->CreatedAtUtc100ns.QuadPart + ((LONGLONG)pendingDecision->TimeoutMs * 10000LL);

    KswordArkCopyUnicodeToFixedBuffer(
        &eventInput->InitiatorPath,
        pendingDecision->InitiatorPath,
        RTL_NUMBER_OF(pendingDecision->InitiatorPath));
    KswordArkCopyUnicodeToFixedBuffer(
        &eventInput->TargetPath,
        pendingDecision->TargetPath,
        RTL_NUMBER_OF(pendingDecision->TargetPath));

    if (!KswordArkInsertPendingDecision(runtime, pendingDecision)) {
        // 停止状态可能在预检查后才建立；插入失败时保留规则默认决定并释放所有者引用。
        *decisionOut = pendingDecision->DefaultDecision;
        KswordArkPendingDecisionRelease(pendingDecision); // owner release
        return STATUS_DEVICE_NOT_READY;
    }
    dispatchStatus = KswordArkDispatchEventToWaitingRequest(runtime, pendingDecision);
    if (!NT_SUCCESS(dispatchStatus)) {
        KswordArkRemovePendingDecision(runtime, pendingDecision);
        *decisionOut = pendingDecision->DefaultDecision;
        KswordArkPendingDecisionRelease(pendingDecision); // owner release
        KswordArkCallbackLogFormat(
            "Warn",
            "AskUser fallback default: no waiting receiver, callback=%lu, op=0x%08lX, groupId=%lu, ruleId=%lu.",
            (unsigned long)eventInput->CallbackType,
            (unsigned long)eventInput->OperationType,
            (unsigned long)eventInput->Match.GroupId,
            (unsigned long)eventInput->Match.RuleId);
        return STATUS_NOT_FOUND;
    }

    waitTimeoutMs = pendingDecision->TimeoutMs;
    if (waitTimeoutMs > 600000UL) {
        waitTimeoutMs = 600000UL;
    }
    timeout100ns = (ULONGLONG)waitTimeoutMs * 10000ULL;
    if (timeout100ns > (ULONGLONG)MAXLONGLONG) {
        timeout100ns = (ULONGLONG)MAXLONGLONG;
    }
    timeoutInterval.QuadPart = -(LONGLONG)timeout100ns;

    waitStatus = KeWaitForSingleObject(
        &pendingDecision->DecisionEvent,
        Executive,
        KernelMode,
        FALSE,
        &timeoutInterval);
    if (waitStatus == STATUS_TIMEOUT) {
        BOOLEAN timeoutApplied = FALSE;

        // 与答复和取消共用 PendingLock，保证最终决定及其状态不会发生竞态写入。
        KswordARKAcquirePushLockExclusive(&runtime->PendingLock);
        if (InterlockedCompareExchange(&pendingDecision->Answered, 0L, 0L) == 0L) {
            pendingDecision->FinalDecision = pendingDecision->DefaultDecision;
            (VOID)InterlockedExchange(&pendingDecision->Answered, 1L);
            timeoutApplied = TRUE;
        }
        *decisionOut = pendingDecision->FinalDecision;
        KswordARKReleasePushLockExclusive(&runtime->PendingLock);

        if (timeoutApplied) {
            KswordArkCallbackLogFormat(
                "Warn",
                "AskUser timeout default applied, callback=%lu, op=0x%08lX, groupId=%lu, ruleId=%lu.",
                (unsigned long)eventInput->CallbackType,
                (unsigned long)eventInput->OperationType,
                (unsigned long)eventInput->Match.GroupId,
                (unsigned long)eventInput->Match.RuleId);
        }
    }
    else {
        // 事件唤醒后仍在锁下读取结果，以配对答复、取消和超时路径的写入同步。
        KswordARKAcquirePushLockShared(&runtime->PendingLock);
        *decisionOut = pendingDecision->FinalDecision;
        KswordARKReleasePushLockShared(&runtime->PendingLock);
    }

    KswordArkRemovePendingDecision(runtime, pendingDecision);
    KswordArkPendingDecisionRelease(pendingDecision); // owner release
    return STATUS_SUCCESS;
}

ULONG
KswordArkCallbackGetWaitingRequestCount(
    VOID
    )
{
    KSWORD_ARK_CALLBACK_RUNTIME* runtime = KswordArkCallbackGetRuntime();
    ULONG queueRequests = 0U;

    if (runtime == NULL || runtime->WaitQueue == WDF_NO_HANDLE) {
        return 0U;
    }

    (VOID)WdfIoQueueGetState(runtime->WaitQueue, &queueRequests, NULL);
    return queueRequests;
}

ULONG
KswordArkCallbackGetPendingDecisionCount(
    VOID
    )
{
    KSWORD_ARK_CALLBACK_RUNTIME* runtime = KswordArkCallbackGetRuntime();
    if (runtime == NULL) {
        return 0U;
    }

    return (ULONG)InterlockedCompareExchange(&runtime->PendingDecisionCount, 0L, 0L);
}
