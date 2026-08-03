/*++

Module Name:

    rxpf_diagnostics.c

Abstract:

    Preallocated per-processor event rings and aggregate RXPF counters.

Environment:

    Event production is safe on the vector-14 path and never allocates.

--*/

#include "rxpf_diagnostics.h"
#include "src/platform/pool_compat.h"

#define KSW_RXPF_DIAGNOSTICS_TAG 'dPxR'

typedef struct _KSW_RXPF_DIAGNOSTICS_STATE
{
    PKSW_RXPF_EVENT_RING Rings;
    ULONG ProcessorCapacity;
    volatile LONG Initialized;
    volatile LONG ActiveHandlers;
    DECLSPEC_ALIGN(8) volatile LONG64 NextSequence;
    DECLSPEC_ALIGN(8) volatile LONG64 TotalFaults;
    DECLSPEC_ALIGN(8) volatile LONG64 ManagedFaults;
    DECLSPEC_ALIGN(8) volatile LONG64 EmulatedInstructions;
    DECLSPEC_ALIGN(8) volatile LONG64 ChainedFaults;
    DECLSPEC_ALIGN(8) volatile LONG64 RecursiveFaults;
    DECLSPEC_ALIGN(8) volatile LONG64 UnsupportedInstructions;
    DECLSPEC_ALIGN(8) volatile LONG64 DroppedEvents;
    volatile LONG LastStatus;
} KSW_RXPF_DIAGNOSTICS_STATE;

static KSW_RXPF_DIAGNOSTICS_STATE g_KswRxpfDiagnostics;

NTSTATUS
KswRxpfDiagnosticsInitialize(
    _In_ ULONG MaximumProcessorCount
    )
{
    SIZE_T allocationBytes = 0U;
    PKSW_RXPF_EVENT_RING rings = NULL;

    /* Repeated initialization is idempotent for DriverEntry rollback paths. */
    if (InterlockedCompareExchange(
            &g_KswRxpfDiagnostics.Initialized,
            1,
            1) != 0) {
        return STATUS_SUCCESS;
    }
    if (MaximumProcessorCount == 0UL ||
        MaximumProcessorCount > MAXULONG_PTR /
            sizeof(KSW_RXPF_EVENT_RING)) {
        return STATUS_INVALID_PARAMETER;
    }

    /* Allocate every ring before vector 14 can be replaced. */
    allocationBytes =
        (SIZE_T)MaximumProcessorCount * sizeof(KSW_RXPF_EVENT_RING);
    rings = (PKSW_RXPF_EVENT_RING)KswordARKAllocateNonPagedPool(
        allocationBytes,
        KSW_RXPF_DIAGNOSTICS_TAG);
    if (rings == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlZeroMemory(rings, allocationBytes);

    /* Publish the complete immutable ring array with zeroed counters. */
    RtlZeroMemory(
        &g_KswRxpfDiagnostics,
        sizeof(g_KswRxpfDiagnostics));
    g_KswRxpfDiagnostics.Rings = rings;
    g_KswRxpfDiagnostics.ProcessorCapacity = MaximumProcessorCount;
    KeMemoryBarrier();
    InterlockedExchange(&g_KswRxpfDiagnostics.Initialized, 1);
    return STATUS_SUCCESS;
}

VOID
KswRxpfDiagnosticsUninitialize(
    VOID
    )
{
    PKSW_RXPF_EVENT_RING rings = g_KswRxpfDiagnostics.Rings;

    /* Unpublish producer state before releasing the backing allocation. */
    InterlockedExchange(&g_KswRxpfDiagnostics.Initialized, 0);
    KeMemoryBarrier();
    RtlZeroMemory(
        &g_KswRxpfDiagnostics,
        sizeof(g_KswRxpfDiagnostics));
    if (rings != NULL) {
        ExFreePoolWithTag(rings, KSW_RXPF_DIAGNOSTICS_TAG);
    }
}

VOID
KswRxpfDiagnosticsEnterHandler(
    VOID
    )
{
    /* One global reader count protects page resources during removal. */
    InterlockedIncrement(&g_KswRxpfDiagnostics.ActiveHandlers);
    KeMemoryBarrier();
}

VOID
KswRxpfDiagnosticsLeaveHandler(
    VOID
    )
{
    /* Publish all record accesses before leaving the lifecycle read side. */
    KeMemoryBarrier();
    InterlockedDecrement(&g_KswRxpfDiagnostics.ActiveHandlers);
}

LONG
KswRxpfDiagnosticsActiveHandlers(
    VOID
    )
{
    /* Return an atomic snapshot without taking a control-path lock. */
    return InterlockedCompareExchange(
        &g_KswRxpfDiagnostics.ActiveHandlers,
        0,
        0);
}

NTSTATUS
KswRxpfDiagnosticsWaitForHandlers(
    _In_ ULONG TimeoutMilliseconds
    )
{
    ULONG waitedMilliseconds = 0UL;
    LARGE_INTEGER interval;

    /* A one-millisecond relative delay bounds normal control-path waiting. */
    interval.QuadPart = -10LL * 1000LL;
    while (KswRxpfDiagnosticsActiveHandlers() != 0) {
        if (waitedMilliseconds >= TimeoutMilliseconds) {
            return STATUS_IO_TIMEOUT;
        }
        (void)KeDelayExecutionThread(
            KernelMode,
            FALSE,
            &interval);
        waitedMilliseconds += 1UL;
    }
    return STATUS_SUCCESS;
}

VOID
KswRxpfDiagnosticsRecord(
    _In_ ULONG ProcessorIndex,
    _In_ ULONGLONG Cr2,
    _In_ ULONGLONG Rip,
    _In_ ULONGLONG ErrorCode,
    _In_ ULONGLONG RecordId,
    _In_ ULONG DecodedInstruction,
    _In_ ULONG EmulationResult,
    _In_ ULONGLONG NewRip,
    _In_ NTSTATUS Status
    )
{
    PKSW_RXPF_EVENT_RING ring = NULL;
    PKSW_RXPF_EVENT_SLOT slot = NULL;
    LONG head = 0;
    LONG64 sequence = 0;

    /* Drop events rather than touching an absent or out-of-range ring. */
    if (InterlockedCompareExchange(
            &g_KswRxpfDiagnostics.Initialized,
            1,
            1) == 0 ||
        ProcessorIndex >= g_KswRxpfDiagnostics.ProcessorCapacity) {
        InterlockedIncrement64(&g_KswRxpfDiagnostics.DroppedEvents);
        return;
    }

    /* A processor owns its ring while interrupts are disabled in the stub. */
    ring = &g_KswRxpfDiagnostics.Rings[ProcessorIndex];
    head = InterlockedIncrement(&ring->Head) - 1;
    slot = &ring->Slots[((ULONG)head) &
        (KSW_RXPF_EVENT_RING_CAPACITY - 1UL)];
    sequence = InterlockedIncrement64(
        &g_KswRxpfDiagnostics.NextSequence);

    /* Zero Sequence while a reader-visible row is being replaced. */
    InterlockedExchange64(&slot->Sequence, 0);
    slot->Row.sequence = (ULONGLONG)sequence;
    slot->Row.timestamp = __rdtsc();
    slot->Row.cr2 = Cr2;
    slot->Row.rip = Rip;
    slot->Row.errorCode = ErrorCode;
    slot->Row.recordId = RecordId;
    slot->Row.newRip = NewRip;
    slot->Row.processorIndex = ProcessorIndex;
    slot->Row.decodedInstruction = DecodedInstruction;
    slot->Row.emulationResult = EmulationResult;
    slot->Row.status = Status;
    KeMemoryBarrier();
    InterlockedExchange64(&slot->Sequence, sequence);
}

VOID
KswRxpfDiagnosticsCountTotalFault(
    VOID
    )
{
    InterlockedIncrement64(&g_KswRxpfDiagnostics.TotalFaults);
}

VOID
KswRxpfDiagnosticsCountManagedFault(
    VOID
    )
{
    InterlockedIncrement64(&g_KswRxpfDiagnostics.ManagedFaults);
}

VOID
KswRxpfDiagnosticsCountEmulatedInstruction(
    VOID
    )
{
    InterlockedIncrement64(
        &g_KswRxpfDiagnostics.EmulatedInstructions);
}

VOID
KswRxpfDiagnosticsCountChainedFault(
    VOID
    )
{
    InterlockedIncrement64(&g_KswRxpfDiagnostics.ChainedFaults);
}

VOID
KswRxpfDiagnosticsCountRecursiveFault(
    VOID
    )
{
    InterlockedIncrement64(&g_KswRxpfDiagnostics.RecursiveFaults);
}

VOID
KswRxpfDiagnosticsCountUnsupportedInstruction(
    VOID
    )
{
    InterlockedIncrement64(
        &g_KswRxpfDiagnostics.UnsupportedInstructions);
}

VOID
KswRxpfDiagnosticsSetLastStatus(
    _In_ NTSTATUS Status
    )
{
    InterlockedExchange(
        &g_KswRxpfDiagnostics.LastStatus,
        Status);
}

VOID
KswRxpfDiagnosticsQueryStats(
    _In_ ULONG Generation,
    _In_ ULONG RegisteredPages,
    _In_ ULONG EnabledPages,
    _In_ ULONG IdtInstalled,
    _In_ ULONG ProcessorCount,
    _Out_ KSWORD_ARK_RXPF_STATS_RESPONSE* Response
    )
{
    /* Copy aligned atomic counters into a fixed user-mode response. */
    RtlZeroMemory(Response, sizeof(*Response));
    Response->version = KSWORD_ARK_RXPF_PROTOCOL_VERSION;
    Response->size = sizeof(*Response);
    Response->generation = Generation;
    Response->registeredPages = RegisteredPages;
    Response->enabledPages = EnabledPages;
    Response->idtInstalled = IdtInstalled;
    Response->processorCount = ProcessorCount;
    Response->activeHandlers =
        (ULONG)KswRxpfDiagnosticsActiveHandlers();
    Response->totalFaults =
        (ULONGLONG)InterlockedCompareExchange64(
            &g_KswRxpfDiagnostics.TotalFaults,
            0,
            0);
    Response->managedFaults =
        (ULONGLONG)InterlockedCompareExchange64(
            &g_KswRxpfDiagnostics.ManagedFaults,
            0,
            0);
    Response->emulatedInstructions =
        (ULONGLONG)InterlockedCompareExchange64(
            &g_KswRxpfDiagnostics.EmulatedInstructions,
            0,
            0);
    Response->chainedFaults =
        (ULONGLONG)InterlockedCompareExchange64(
            &g_KswRxpfDiagnostics.ChainedFaults,
            0,
            0);
    Response->recursiveFaults =
        (ULONGLONG)InterlockedCompareExchange64(
            &g_KswRxpfDiagnostics.RecursiveFaults,
            0,
            0);
    Response->unsupportedInstructions =
        (ULONGLONG)InterlockedCompareExchange64(
            &g_KswRxpfDiagnostics.UnsupportedInstructions,
            0,
            0);
    Response->droppedEvents =
        (ULONGLONG)InterlockedCompareExchange64(
            &g_KswRxpfDiagnostics.DroppedEvents,
            0,
            0);
    Response->lastStatus =
        InterlockedCompareExchange(
            &g_KswRxpfDiagnostics.LastStatus,
            0,
            0);
}

static VOID
KswRxpfDiagnosticsInsertSorted(
    _Inout_updates_(Capacity) KSWORD_ARK_RXPF_EVENT_ROW* Rows,
    _Inout_ ULONG* Count,
    _In_ ULONG Capacity,
    _In_ const KSWORD_ARK_RXPF_EVENT_ROW* Candidate
    )
{
    ULONG insertIndex = 0UL;
    ULONG moveIndex = 0UL;

    /* Keep only the earliest requested rows when the fixed response is full. */
    if (*Count >= Capacity &&
        Candidate->sequence >= Rows[Capacity - 1UL].sequence) {
        return;
    }
    insertIndex = *Count < Capacity ? *Count : Capacity - 1UL;
    while (insertIndex > 0UL &&
        Rows[insertIndex - 1UL].sequence > Candidate->sequence) {
        insertIndex -= 1UL;
    }
    moveIndex = *Count < Capacity ? *Count : Capacity - 1UL;
    while (moveIndex > insertIndex) {
        Rows[moveIndex] = Rows[moveIndex - 1UL];
        moveIndex -= 1UL;
    }
    Rows[insertIndex] = *Candidate;
    if (*Count < Capacity) {
        *Count += 1UL;
    }
}

VOID
KswRxpfDiagnosticsDrain(
    _In_ const KSWORD_ARK_RXPF_DRAIN_EVENTS_REQUEST* Request,
    _Out_ KSWORD_ARK_RXPF_DRAIN_EVENTS_RESPONSE* Response
    )
{
    ULONG processorIndex = 0UL;
    ULONG slotIndex = 0UL;
    ULONG rowCapacity = 0UL;
    ULONG returnedRows = 0UL;
    ULONG availableRows = 0UL;
    ULONGLONG newestSequence = 0ULL;

    /* Initialize a complete response even when no ring has been published. */
    RtlZeroMemory(Response, sizeof(*Response));
    Response->version = KSWORD_ARK_RXPF_PROTOCOL_VERSION;
    Response->size = sizeof(*Response);
    rowCapacity = Request->maxRows;
    if (rowCapacity == 0UL ||
        rowCapacity > KSWORD_ARK_RXPF_MAX_EVENT_ROWS) {
        rowCapacity = KSWORD_ARK_RXPF_MAX_EVENT_ROWS;
    }
    if (InterlockedCompareExchange(
            &g_KswRxpfDiagnostics.Initialized,
            1,
            1) == 0) {
        return;
    }

    /* Read each slot with a sequence-before/after stability check. */
    for (processorIndex = 0UL;
         processorIndex < g_KswRxpfDiagnostics.ProcessorCapacity;
         ++processorIndex) {
        PKSW_RXPF_EVENT_RING ring =
            &g_KswRxpfDiagnostics.Rings[processorIndex];

        for (slotIndex = 0UL;
             slotIndex < KSW_RXPF_EVENT_RING_CAPACITY;
             ++slotIndex) {
            PKSW_RXPF_EVENT_SLOT slot = &ring->Slots[slotIndex];
            LONG64 before = InterlockedCompareExchange64(
                &slot->Sequence,
                0,
                0);
            KSWORD_ARK_RXPF_EVENT_ROW candidate;
            LONG64 after = 0;

            if (before == 0) {
                continue;
            }
            RtlCopyMemory(&candidate, &slot->Row, sizeof(candidate));
            KeMemoryBarrier();
            after = InterlockedCompareExchange64(
                &slot->Sequence,
                0,
                0);
            if (before != after ||
                candidate.sequence != (ULONGLONG)before) {
                continue;
            }
            if (candidate.sequence > newestSequence) {
                newestSequence = candidate.sequence;
            }
            if (candidate.sequence <= Request->afterSequence) {
                continue;
            }
            availableRows += 1UL;
            KswRxpfDiagnosticsInsertSorted(
                Response->rows,
                &returnedRows,
                rowCapacity,
                &candidate);
        }
    }

    /* Publish bounded row counts and the global overwrite counter. */
    Response->returnedRows = returnedRows;
    Response->availableRows = availableRows;
    Response->newestSequence = newestSequence;
    Response->droppedRows =
        (ULONGLONG)InterlockedCompareExchange64(
            &g_KswRxpfDiagnostics.DroppedEvents,
            0,
            0);
}
