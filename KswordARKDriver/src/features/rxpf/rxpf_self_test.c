/*++

Module Name:

    rxpf_self_test.c

Abstract:

    Explicit VM-only concurrent execution harness for one managed RXPF page.

Environment:

    Kernel mode, PASSIVE_LEVEL control path. Worker threads remain at
    PASSIVE_LEVEL so instruction-fetch faults are eligible for RXPF dispatch.

--*/

#include "rxpf_self_test.h"

#include "rxpf_runtime.h"
#include "src/platform/pool_compat.h"

#define KSW_RXPF_SELF_TEST_TAG 'tPxR'

typedef struct _KSW_RXPF_CONCURRENT_TEST_STATE
    KSW_RXPF_CONCURRENT_TEST_STATE,
  *PKSW_RXPF_CONCURRENT_TEST_STATE;

typedef struct _KSW_RXPF_CONCURRENT_TEST_WORKER
{
    KSW_RXPF_CONCURRENT_TEST_STATE* Shared;
    PROCESSOR_NUMBER Processor;
    KEVENT ReadyEvent;
    PETHREAD ThreadObject;
    ULONGLONG ReturnedValue;
    NTSTATUS Status;
} KSW_RXPF_CONCURRENT_TEST_WORKER,
  *PKSW_RXPF_CONCURRENT_TEST_WORKER;

struct _KSW_RXPF_CONCURRENT_TEST_STATE
{
    KEVENT StartEvent;
    KEVENT DoneEvent;
    PVOID PageAddress;
    ULONGLONG ExpectedValue;
    volatile LONG RemainingWorkers;
    volatile LONG FailedWorkers;
    ULONG WorkerCount;
    KSW_RXPF_CONCURRENT_TEST_WORKER Workers[ANYSIZE_ARRAY];
};

static VOID
KswRxpfConcurrentTestWorker(
    _In_ PVOID Context
    )
{
    PKSW_RXPF_CONCURRENT_TEST_WORKER worker =
        (PKSW_RXPF_CONCURRENT_TEST_WORKER)Context;
    PKSW_RXPF_CONCURRENT_TEST_STATE shared = worker->Shared;
    GROUP_AFFINITY targetAffinity;
    GROUP_AFFINITY previousAffinity;
    BOOLEAN affinitySet = FALSE;
    NTSTATUS status = STATUS_SUCCESS;
    ULONGLONG returnedValue = 0ULL;

    worker->ThreadObject = PsGetCurrentThread();
    ObReferenceObject(worker->ThreadObject);
    KeMemoryBarrier();
    KeSetEvent(&worker->ReadyEvent, IO_NO_INCREMENT, FALSE);

    /* The creator now owns a thread-object reference for final termination. */
    (void)KeWaitForSingleObject(
        &shared->StartEvent,
        Executive,
        KernelMode,
        FALSE,
        NULL);
    RtlZeroMemory(&targetAffinity, sizeof(targetAffinity));
    RtlZeroMemory(&previousAffinity, sizeof(previousAffinity));
    if (worker->Processor.Number >= sizeof(KAFFINITY) * 8UL) {
        status = STATUS_NOT_SUPPORTED;
    } else {
        targetAffinity.Group = worker->Processor.Group;
        targetAffinity.Mask =
            ((KAFFINITY)1) << worker->Processor.Number;
        KeSetSystemGroupAffinityThread(
            &targetAffinity,
            &previousAffinity);
        affinitySet = TRUE;
        __try {
            returnedValue = KswRxpfInvokeTestPage(shared->PageAddress);
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            status = GetExceptionCode();
        }
    }
    if (affinitySet) {
        KeRevertToUserGroupAffinityThread(&previousAffinity);
    }
    worker->ReturnedValue = returnedValue;
    if (NT_SUCCESS(status) && returnedValue != shared->ExpectedValue) {
        status = STATUS_DATA_ERROR;
    }
    worker->Status = status;
    if (!NT_SUCCESS(status)) {
        InterlockedIncrement(&shared->FailedWorkers);
    }
    KeMemoryBarrier();
    if (InterlockedDecrement(&shared->RemainingWorkers) == 0) {
        KeSetEvent(&shared->DoneEvent, IO_NO_INCREMENT, FALSE);
    }
    PsTerminateSystemThread(status);
}

NTSTATUS
KswRxpfRunConcurrentExecutionTest(
    _In_ PVOID PageAddress,
    _In_ ULONGLONG ExpectedValue,
    _Out_ ULONGLONG* ReturnedValueOut,
    _Out_ ULONG* WorkerCountOut
    )
{
    PKSW_RXPF_CONCURRENT_TEST_STATE state = NULL;
    ULONG activeCount = 0UL;
    ULONG createdCount = 0UL;
    ULONG index = 0UL;
    SIZE_T allocationBytes = 0U;
    NTSTATUS status = STATUS_SUCCESS;

    PAGED_CODE();
    if (PageAddress == NULL || ReturnedValueOut == NULL ||
        WorkerCountOut == NULL || ExpectedValue == 0ULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *ReturnedValueOut = 0ULL;
    *WorkerCountOut = 0UL;
    activeCount = KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS);
    if (activeCount == 0UL || activeCount >
        (MAXULONG_PTR - FIELD_OFFSET(
            KSW_RXPF_CONCURRENT_TEST_STATE,
            Workers)) / sizeof(KSW_RXPF_CONCURRENT_TEST_WORKER)) {
        return STATUS_NOT_SUPPORTED;
    }
    allocationBytes = FIELD_OFFSET(
        KSW_RXPF_CONCURRENT_TEST_STATE,
        Workers) + (SIZE_T)activeCount *
            sizeof(KSW_RXPF_CONCURRENT_TEST_WORKER);
    state = (PKSW_RXPF_CONCURRENT_TEST_STATE)
        KswordARKAllocateNonPagedPool(
            allocationBytes,
            KSW_RXPF_SELF_TEST_TAG);
    if (state == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlZeroMemory(state, allocationBytes);
    KeInitializeEvent(&state->StartEvent, NotificationEvent, FALSE);
    KeInitializeEvent(&state->DoneEvent, NotificationEvent, FALSE);
    state->PageAddress = PageAddress;
    state->ExpectedValue = ExpectedValue;

    /* Create every waiter before releasing the shared start event. */
    for (index = 0UL; index < activeCount; ++index) {
        PKSW_RXPF_CONCURRENT_TEST_WORKER worker =
            &state->Workers[index];
        HANDLE threadHandle = NULL;

        worker->Shared = state;
        KeInitializeEvent(&worker->ReadyEvent, NotificationEvent, FALSE);
        worker->ThreadObject = NULL;
        status = KeGetProcessorNumberFromIndex(
            index,
            &worker->Processor);
        if (!NT_SUCCESS(status)) {
            break;
        }
        status = PsCreateSystemThread(
            &threadHandle,
            THREAD_ALL_ACCESS,
            NULL,
            NULL,
            NULL,
            KswRxpfConcurrentTestWorker,
            worker);
        if (!NT_SUCCESS(status)) {
            threadHandle = NULL;
            break;
        }
        (void)KeWaitForSingleObject(
            &worker->ReadyEvent,
            Executive,
            KernelMode,
            FALSE,
            NULL);
        ZwClose(threadHandle);
        threadHandle = NULL;
        createdCount += 1UL;
    }
    if (createdCount == 0UL) {
        ExFreePoolWithTag(state, KSW_RXPF_SELF_TEST_TAG);
        return NT_SUCCESS(status) ? STATUS_UNSUCCESSFUL : status;
    }

    state->WorkerCount = createdCount;
    InterlockedExchange(
        &state->RemainingWorkers,
        (LONG)createdCount);
    KeMemoryBarrier();
    KeSetEvent(&state->StartEvent, IO_NO_INCREMENT, FALSE);
    (void)KeWaitForSingleObject(
        &state->DoneEvent,
        Executive,
        KernelMode,
        FALSE,
        NULL);

    /* Wait for thread objects, not just the pre-termination completion event. */
    for (index = 0UL; index < createdCount; ++index) {
        if (state->Workers[index].ThreadObject != NULL) {
            (void)KeWaitForSingleObject(
                state->Workers[index].ThreadObject,
                Executive,
                KernelMode,
                FALSE,
                NULL);
            ObDereferenceObject(state->Workers[index].ThreadObject);
            state->Workers[index].ThreadObject = NULL;
        }
    }
    *ReturnedValueOut = state->Workers[0].ReturnedValue;
    *WorkerCountOut = createdCount;
    if (createdCount != activeCount && NT_SUCCESS(status)) {
        status = STATUS_INSUFFICIENT_RESOURCES;
    }
    if (NT_SUCCESS(status) &&
        InterlockedCompareExchange(
            &state->FailedWorkers,
            0,
            0) != 0) {
        status = STATUS_DATA_ERROR;
    }
    ExFreePoolWithTag(state, KSW_RXPF_SELF_TEST_TAG);
    return status;
}
