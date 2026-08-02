/*++

Module Name:

    work_queue_fallback.c

Abstract:

    Runtime-signature fallback for Ex worker queues.  ExQueueWorkItem is the
    stable entry anchor.  The resolver validates the partition pointer chain,
    every live node queue, all priority list heads, public WORK_QUEUE_ITEM
    fields, and (when possible) the ETHREAD queue pointer across referenced
    System threads.  No fixed private Windows offsets are used.

Environment:

    Kernel mode, PASSIVE_LEVEL read-only query path.

--*/

#include "ark/ark_dyndata.h"
#include "work_queue_fallback.h"
#include "../../platform/runtime_signature_scan.h"
#include "../../platform/pool_compat.h"

#define KSW_WORK_QUEUE_FALLBACK_TAG 'qWsK'
#define KSW_WORK_QUEUE_FALLBACK_MAX_REFERENCES 256UL
#define KSW_WORK_QUEUE_FALLBACK_SCAN_BYTES 0x0800UL
#define KSW_WORK_QUEUE_FALLBACK_PARTITION_SCAN 0x0100UL
#define KSW_WORK_QUEUE_FALLBACK_QUEUE_SCAN 0x0100UL
#define KSW_WORK_QUEUE_FALLBACK_MAX_POOL_INDEX 8UL
#define KSW_WORK_QUEUE_FALLBACK_MAX_NODES 64UL
#define KSW_WORK_QUEUE_FALLBACK_PRIORITY_COUNT 32UL
#define KSW_WORK_QUEUE_FALLBACK_THREAD_SCAN 0x0800UL
#define KSW_WORK_QUEUE_FALLBACK_MAX_THREADS 512UL
#define KSW_WORK_QUEUE_FALLBACK_WORKER_SAMPLES 8UL

typedef PETHREAD(NTAPI* KSW_WORK_QUEUE_FALLBACK_NEXT_THREAD_FN)(
    _In_ PEPROCESS Process,
    _In_opt_ PETHREAD Thread
    );

typedef struct _KSW_WORK_QUEUE_CHAIN
{
    ULONG_PTR PartitionGlobal;
    ULONG PartitionExPartition;
    ULONG ExPartitionWorkQueues;
    ULONG PoolIndex;
    ULONG PriQueueOffset;
    ULONG NodeCount;
    ULONG ValidationScore;
    ULONG_PTR QueueAddresses[KSW_WORK_QUEUE_FALLBACK_MAX_NODES];
} KSW_WORK_QUEUE_CHAIN, *PKSW_WORK_QUEUE_CHAIN;

extern NTKERNELAPI PEPROCESS PsInitialSystemProcess;

static BOOLEAN
KswordARKWorkQueueFallbackIsKernelAddress(
    _In_ ULONG_PTR Address
    )
{
#if defined(_M_AMD64) || defined(_M_X64)
    return Address >= (ULONG_PTR)MmSystemRangeStart &&
        (Address >> 48U) == 0xFFFFU;
#else
    return Address >= (ULONG_PTR)MmSystemRangeStart;
#endif
}

static BOOLEAN
KswordARKWorkQueueFallbackReadPointer(
    _In_ ULONG_PTR Address,
    _Out_ ULONG_PTR* ValueOut
    )
{
    return ValueOut != NULL &&
        KswordARKRuntimeReadMemory(
            (const VOID*)Address,
            ValueOut,
            sizeof(*ValueOut));
}

static BOOLEAN
KswordARKWorkQueueFallbackValidateListHead(
    _In_ ULONG_PTR HeadAddress,
    _Out_opt_ BOOLEAN* NonEmptyOut
    )
{
    LIST_ENTRY head;
    LIST_ENTRY first;
    LIST_ENTRY last;

    if (NonEmptyOut != NULL) {
        *NonEmptyOut = FALSE;
    }
    RtlZeroMemory(&head, sizeof(head));
    RtlZeroMemory(&first, sizeof(first));
    RtlZeroMemory(&last, sizeof(last));
    if (!KswordARKWorkQueueFallbackIsKernelAddress(HeadAddress) ||
        !KswordARKRuntimeReadMemory(
            (const VOID*)HeadAddress,
            &head,
            sizeof(head)) ||
        head.Flink == NULL || head.Blink == NULL) {
        return FALSE;
    }
    if ((ULONG_PTR)head.Flink == HeadAddress ||
        (ULONG_PTR)head.Blink == HeadAddress) {
        return (ULONG_PTR)head.Flink == HeadAddress &&
            (ULONG_PTR)head.Blink == HeadAddress;
    }
    if (!KswordARKWorkQueueFallbackIsKernelAddress((ULONG_PTR)head.Flink) ||
        !KswordARKWorkQueueFallbackIsKernelAddress((ULONG_PTR)head.Blink) ||
        !KswordARKRuntimeReadMemory(head.Flink, &first, sizeof(first)) ||
        !KswordARKRuntimeReadMemory(head.Blink, &last, sizeof(last)) ||
        (ULONG_PTR)first.Blink != HeadAddress ||
        (ULONG_PTR)last.Flink != HeadAddress) {
        return FALSE;
    }
    if (NonEmptyOut != NULL) {
        *NonEmptyOut = TRUE;
    }
    return TRUE;
}

static BOOLEAN
KswordARKWorkQueueFallbackFindPriQueueOffset(
    _In_ ULONG_PTR QueueAddress,
    _Out_ ULONG* OffsetOut,
    _Out_ ULONG* ScoreOut
    )
/*++

Routine Description:

    Locate one unique array of 32 reciprocal priority list heads inside a live
    queue.  Empty and populated heads are both validated; populated heads add
    evidence so unrelated arrays do not win on shape alone.

Return Value:

    TRUE only for one strongest array offset.

--*/
{
    ULONG candidateOffset = 0UL;
    ULONG bestOffset = 0UL;
    ULONG bestScore = 0UL;
    BOOLEAN tied = FALSE;

    if (OffsetOut == NULL || ScoreOut == NULL ||
        !KswordARKWorkQueueFallbackIsKernelAddress(QueueAddress)) {
        return FALSE;
    }
    for (candidateOffset = 0UL;
         candidateOffset < KSW_WORK_QUEUE_FALLBACK_QUEUE_SCAN;
         candidateOffset += sizeof(PVOID)) {
        ULONG priorityIndex = 0UL;
        ULONG score = 0UL;
        BOOLEAN valid = TRUE;

        for (priorityIndex = 0UL;
             priorityIndex < KSW_WORK_QUEUE_FALLBACK_PRIORITY_COUNT;
             ++priorityIndex) {
            ULONG_PTR headAddress = QueueAddress + candidateOffset +
                ((ULONG_PTR)priorityIndex * sizeof(LIST_ENTRY));
            BOOLEAN nonEmpty = FALSE;

            if (headAddress < QueueAddress ||
                !KswordARKWorkQueueFallbackValidateListHead(
                    headAddress,
                    &nonEmpty)) {
                valid = FALSE;
                break;
            }
            score += nonEmpty ? 2UL : 1UL;
        }
        if (!valid || score < bestScore) {
            continue;
        }
        if (score == bestScore && bestScore != 0UL) {
            tied = TRUE;
            continue;
        }
        bestOffset = candidateOffset;
        bestScore = score;
        tied = FALSE;
    }
    if (bestScore < KSW_WORK_QUEUE_FALLBACK_PRIORITY_COUNT || tied) {
        return FALSE;
    }
    *OffsetOut = bestOffset;
    *ScoreOut = bestScore;
    return TRUE;
}

static BOOLEAN
KswordARKWorkQueueFallbackValidateChainCandidate(
    _In_ ULONG_PTR PartitionGlobal,
    _In_ ULONG PartitionOffset,
    _In_ ULONG WorkQueuesOffset,
    _In_ ULONG PoolIndex,
    _Out_ KSW_WORK_QUEUE_CHAIN* ChainOut
    )
{
    ULONG_PTR partition = 0U;
    ULONG_PTR exPartition = 0U;
    ULONG_PTR workQueues = 0U;
    ULONG nodeCount = (ULONG)KeQueryHighestNodeNumber() + 1UL;
    ULONG nodeIndex = 0UL;
    ULONG sharedPriQueueOffset = MAXULONG;
    ULONG totalScore = 0UL;
    KSW_WORK_QUEUE_CHAIN candidate;

    if (ChainOut == NULL || nodeCount == 0UL ||
        nodeCount > KSW_WORK_QUEUE_FALLBACK_MAX_NODES ||
        !KswordARKWorkQueueFallbackReadPointer(
            PartitionGlobal,
            &partition) ||
        !KswordARKWorkQueueFallbackIsKernelAddress(partition) ||
        !KswordARKWorkQueueFallbackReadPointer(
            partition + PartitionOffset,
            &exPartition) ||
        !KswordARKWorkQueueFallbackIsKernelAddress(exPartition) ||
        !KswordARKWorkQueueFallbackReadPointer(
            exPartition + WorkQueuesOffset,
            &workQueues) ||
        !KswordARKWorkQueueFallbackIsKernelAddress(workQueues)) {
        return FALSE;
    }
    RtlZeroMemory(&candidate, sizeof(candidate));
    for (nodeIndex = 0UL; nodeIndex < nodeCount; ++nodeIndex) {
        ULONG_PTR nodeQueueArray = 0U;
        ULONG_PTR queueAddress = 0U;
        ULONG priQueueOffset = 0UL;
        ULONG queueScore = 0UL;

        if (!KswordARKWorkQueueFallbackReadPointer(
                workQueues + ((ULONG_PTR)nodeIndex * sizeof(PVOID)),
                &nodeQueueArray) ||
            !KswordARKWorkQueueFallbackIsKernelAddress(nodeQueueArray) ||
            !KswordARKWorkQueueFallbackReadPointer(
                nodeQueueArray + ((ULONG_PTR)PoolIndex * sizeof(PVOID)),
                &queueAddress) ||
            !KswordARKWorkQueueFallbackIsKernelAddress(queueAddress) ||
            !KswordARKWorkQueueFallbackFindPriQueueOffset(
                queueAddress,
                &priQueueOffset,
                &queueScore) ||
            (sharedPriQueueOffset != MAXULONG &&
             priQueueOffset != sharedPriQueueOffset)) {
            return FALSE;
        }
        sharedPriQueueOffset = priQueueOffset;
        candidate.QueueAddresses[nodeIndex] = queueAddress;
        totalScore += queueScore;
    }

    candidate.PartitionGlobal = PartitionGlobal;
    candidate.PartitionExPartition = PartitionOffset;
    candidate.ExPartitionWorkQueues = WorkQueuesOffset;
    candidate.PoolIndex = PoolIndex;
    candidate.PriQueueOffset = sharedPriQueueOffset;
    candidate.NodeCount = nodeCount;
    candidate.ValidationScore = totalScore;
    *ChainOut = candidate;
    return TRUE;
}

static BOOLEAN
KswordARKWorkQueueFallbackChainsEqual(
    _In_ const KSW_WORK_QUEUE_CHAIN* Left,
    _In_ const KSW_WORK_QUEUE_CHAIN* Right
    )
{
    return Left->PartitionGlobal == Right->PartitionGlobal &&
        Left->PartitionExPartition == Right->PartitionExPartition &&
        Left->ExPartitionWorkQueues == Right->ExPartitionWorkQueues &&
        Left->PoolIndex == Right->PoolIndex &&
        Left->PriQueueOffset == Right->PriQueueOffset;
}

static BOOLEAN
KswordARKWorkQueueFallbackFindChain(
    _In_ const KSW_RUNTIME_IMAGE_VIEW* View,
    _In_reads_(ReferenceCount) const KSW_RUNTIME_DATA_REFERENCE* References,
    _In_ ULONG ReferenceCount,
    _Out_ KSW_WORK_QUEUE_CHAIN* ChainOut
    )
{
    KSW_WORK_QUEUE_CHAIN best;
    ULONG bestScore = 0UL;
    BOOLEAN ambiguous = FALSE;
    ULONG referenceIndex = 0UL;

    if (View == NULL || References == NULL || ChainOut == NULL) {
        return FALSE;
    }
    RtlZeroMemory(&best, sizeof(best));
    for (referenceIndex = 0UL; referenceIndex < ReferenceCount; ++referenceIndex) {
        ULONG partitionOffset = 0UL;

        if (!KswordARKRuntimeAddressIsWritableData(
                View,
                References[referenceIndex].Address,
                sizeof(PVOID))) {
            continue;
        }
        for (partitionOffset = 0UL;
             partitionOffset < KSW_WORK_QUEUE_FALLBACK_PARTITION_SCAN;
             partitionOffset += sizeof(PVOID)) {
            ULONG workQueuesOffset = 0UL;

            for (workQueuesOffset = 0UL;
                 workQueuesOffset < KSW_WORK_QUEUE_FALLBACK_PARTITION_SCAN;
                 workQueuesOffset += sizeof(PVOID)) {
                ULONG poolIndex = 0UL;

                for (poolIndex = 0UL;
                     poolIndex < KSW_WORK_QUEUE_FALLBACK_MAX_POOL_INDEX;
                     ++poolIndex) {
                    KSW_WORK_QUEUE_CHAIN candidate;

                    RtlZeroMemory(&candidate, sizeof(candidate));
                    if (!KswordARKWorkQueueFallbackValidateChainCandidate(
                            References[referenceIndex].Address,
                            partitionOffset,
                            workQueuesOffset,
                            poolIndex,
                            &candidate) ||
                        candidate.ValidationScore < bestScore) {
                        continue;
                    }
                    if (candidate.ValidationScore == bestScore &&
                        bestScore != 0UL &&
                        !KswordARKWorkQueueFallbackChainsEqual(
                            &candidate,
                            &best)) {
                        ambiguous = TRUE;
                        continue;
                    }
                    best = candidate;
                    bestScore = candidate.ValidationScore;
                    ambiguous = FALSE;
                }
            }
        }
    }
    if (bestScore == 0UL || ambiguous) {
        return FALSE;
    }
    *ChainOut = best;
    return TRUE;
}

static BOOLEAN
KswordARKWorkQueueFallbackFindPriorityIndexes(
    _In_ const KSW_RUNTIME_IMAGE_VIEW* View,
    _Out_writes_(3) ULONG* PriorityIndexesOut
    )
/*++

Routine Description:

    Recover ExpBuiltinPriorities from an RVA displacement embedded in the
    bounded ExQueueWorkItem code.  The array must contain seven bounded values
    and the three supported built-in queues must map to distinct priorities.

Return Value:

    TRUE only for one matching array.

--*/
{
    ULONG_PTR routine = 0U;
    ULONG offset = 0UL;
    ULONG_PTR foundAddress = 0U;
    ULONG foundValues[3] = { 0UL, 0UL, 0UL };

    if (View == NULL || PriorityIndexesOut == NULL) {
        return FALSE;
    }
    routine = (ULONG_PTR)KswordARKRuntimeFindExport(View, "ExQueueWorkItem");
    if (routine == 0U) {
        return FALSE;
    }
    for (offset = 0UL; offset + sizeof(ULONG) <=
             KSW_WORK_QUEUE_FALLBACK_SCAN_BYTES; ++offset) {
        ULONG candidateRva = 0UL;
        ULONG values[7];
        ULONG index = 0UL;
        ULONG_PTR candidateAddress = 0U;
        BOOLEAN valid = TRUE;

        RtlZeroMemory(values, sizeof(values));
        if (!KswordARKRuntimeAddressIsExecutable(
                View,
                routine + offset,
                sizeof(candidateRva)) ||
            !KswordARKRuntimeReadMemory(
                (const VOID*)(routine + offset),
                &candidateRva,
                sizeof(candidateRva)) ||
            candidateRva >= View->Size ||
            View->Base > MAXULONG_PTR - candidateRva) {
            continue;
        }
        candidateAddress = View->Base + candidateRva;
        if ((candidateAddress & (sizeof(ULONG) - 1U)) != 0U ||
            !KswordARKRuntimeAddressInImage(
                View,
                candidateAddress,
                sizeof(values)) ||
            KswordARKRuntimeAddressIsExecutable(View, candidateAddress, 1U) ||
            !KswordARKRuntimeReadMemory(
                (const VOID*)candidateAddress,
                values,
                sizeof(values))) {
            continue;
        }
        for (index = 0UL; index < RTL_NUMBER_OF(values); ++index) {
            if (values[index] >= KSW_WORK_QUEUE_FALLBACK_PRIORITY_COUNT) {
                valid = FALSE;
                break;
            }
        }
        if (!valid || values[0] == values[1] || values[0] == values[2] ||
            values[1] == values[2]) {
            continue;
        }
        if (foundAddress != 0U && foundAddress != candidateAddress) {
            return FALSE;
        }
        foundAddress = candidateAddress;
        foundValues[0] = values[0];
        foundValues[1] = values[1];
        foundValues[2] = values[2];
    }
    if (foundAddress == 0U) {
        return FALSE;
    }
    PriorityIndexesOut[0] = foundValues[0];
    PriorityIndexesOut[1] = foundValues[1];
    PriorityIndexesOut[2] = foundValues[2];
    return TRUE;
}

static BOOLEAN
KswordARKWorkQueueFallbackQueueAddressMatches(
    _In_ ULONG_PTR Value,
    _In_ const KSW_WORK_QUEUE_CHAIN* Chain
    )
{
    ULONG nodeIndex = 0UL;

    for (nodeIndex = 0UL; nodeIndex < Chain->NodeCount; ++nodeIndex) {
        if (Value == Chain->QueueAddresses[nodeIndex]) {
            return TRUE;
        }
    }
    return FALSE;
}

static BOOLEAN
KswordARKWorkQueueFallbackInferThreadQueueOffset(
    _In_ const KSW_WORK_QUEUE_CHAIN* Chain,
    _Out_ ULONG* OffsetOut
    )
{
    UNICODE_STRING routineName;
    KSW_WORK_QUEUE_FALLBACK_NEXT_THREAD_FN nextThreadFunction = NULL;
    ULONG matchCounts[KSW_WORK_QUEUE_FALLBACK_THREAD_SCAN / sizeof(PVOID)];
    PETHREAD thread = NULL;
    ULONG threadCount = 0UL;
    ULONG offset = 0UL;
    ULONG bestCount = 0UL;
    LONG bestOffset = -1;
    BOOLEAN tied = FALSE;

    if (Chain == NULL || OffsetOut == NULL || PsInitialSystemProcess == NULL) {
        return FALSE;
    }
    RtlZeroMemory(matchCounts, sizeof(matchCounts));
    RtlInitUnicodeString(&routineName, L"PsGetNextProcessThread");
    nextThreadFunction = (KSW_WORK_QUEUE_FALLBACK_NEXT_THREAD_FN)
        MmGetSystemRoutineAddress(&routineName);
    if (nextThreadFunction == NULL) {
        return FALSE;
    }

    thread = nextThreadFunction(PsInitialSystemProcess, NULL);
    while (thread != NULL && threadCount < KSW_WORK_QUEUE_FALLBACK_MAX_THREADS) {
        PETHREAD nextThread = NULL;

        for (offset = 0UL;
             offset + sizeof(ULONG_PTR) <= KSW_WORK_QUEUE_FALLBACK_THREAD_SCAN;
             offset += sizeof(PVOID)) {
            ULONG_PTR value = 0U;

            if (KswordARKRuntimeReadMemory(
                    (const UCHAR*)thread + offset,
                    &value,
                    sizeof(value)) &&
                KswordARKWorkQueueFallbackQueueAddressMatches(value, Chain)) {
                matchCounts[offset / sizeof(PVOID)] += 1UL;
            }
        }
        nextThread = nextThreadFunction(PsInitialSystemProcess, thread);
        ObDereferenceObject(thread);
        thread = nextThread;
        threadCount += 1UL;
    }
    if (thread != NULL) {
        ObDereferenceObject(thread);
    }

    for (offset = 0UL;
         offset + sizeof(ULONG_PTR) <= KSW_WORK_QUEUE_FALLBACK_THREAD_SCAN;
         offset += sizeof(PVOID)) {
        ULONG count = matchCounts[offset / sizeof(PVOID)];

        if (count < 2UL || count < bestCount) {
            continue;
        }
        if (count == bestCount && bestCount != 0UL) {
            tied = TRUE;
            continue;
        }
        bestCount = count;
        bestOffset = (LONG)offset;
        tied = FALSE;
    }
    if (bestOffset < 0 || tied) {
        return FALSE;
    }
    *OffsetOut = (ULONG)bestOffset;
    return TRUE;
}

NTSTATUS
KswordARKWorkQueueResolveRuntimeLayout(
    _Out_ KSW_DYN_V4_WORK_QUEUE_LAYOUT* LayoutOut
    )
{
    static PCSTR const anchors[] = { "ExQueueWorkItem" };
    KSW_DYN_STATE state;
    KSW_RUNTIME_IMAGE_VIEW view;
    KSW_RUNTIME_DATA_REFERENCE* references = NULL;
    KSW_WORK_QUEUE_CHAIN chain;
    ULONG referenceCount = 0UL;
    ULONG threadQueueOffset = 0UL;
    NTSTATUS status = STATUS_NOT_SUPPORTED;

    if (LayoutOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    RtlZeroMemory(LayoutOut, sizeof(*LayoutOut));
    RtlZeroMemory(&state, sizeof(state));
    RtlZeroMemory(&view, sizeof(view));
    RtlZeroMemory(&chain, sizeof(chain));
    if (KeGetCurrentIrql() > APC_LEVEL) {
        return STATUS_INVALID_DEVICE_STATE;
    }
    KswordARKDynDataSnapshot(&state);
    if (!state.NtosActive || state.Ntoskrnl.imageBase == 0ULL ||
        state.Ntoskrnl.sizeOfImage == 0UL ||
        !KswordARKRuntimeInitializeImageView(
            (PVOID)(ULONG_PTR)state.Ntoskrnl.imageBase,
            state.Ntoskrnl.sizeOfImage,
            &view)) {
        return STATUS_DEVICE_NOT_READY;
    }

    references = (KSW_RUNTIME_DATA_REFERENCE*)KswordARKAllocateNonPagedPool(
        KSW_WORK_QUEUE_FALLBACK_MAX_REFERENCES * sizeof(*references),
        KSW_WORK_QUEUE_FALLBACK_TAG);
    if (references == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    referenceCount = KswordARKRuntimeCollectAnchoredDataReferences(
        &view,
        anchors,
        RTL_NUMBER_OF(anchors),
        2UL,
        KSW_WORK_QUEUE_FALLBACK_SCAN_BYTES,
        references,
        KSW_WORK_QUEUE_FALLBACK_MAX_REFERENCES);
    if (referenceCount == 0UL ||
        !KswordARKWorkQueueFallbackFindChain(
            &view,
            references,
            referenceCount,
            &chain) ||
        !KswordARKWorkQueueFallbackFindPriorityIndexes(
            &view,
            LayoutOut->RuntimePriorityIndexes) ||
        chain.PartitionGlobal < view.Base ||
        chain.PartitionGlobal - view.Base > MAXULONG) {
        goto Exit;
    }

    LayoutOut->ModuleBase = view.Base;
    LayoutOut->ModuleSize = view.Size;
    LayoutOut->PspSystemPartitionRva =
        (ULONG)(chain.PartitionGlobal - view.Base);
    LayoutOut->EpartitionExPartition = chain.PartitionExPartition;
    LayoutOut->ExPartitionWorkQueues = chain.ExPartitionWorkQueues;
    LayoutOut->ExWorkQueueWorkPriQueue = 0UL;
    LayoutOut->KpriQueueEntryListHead = chain.PriQueueOffset;
    LayoutOut->WorkItemList = (ULONG)FIELD_OFFSET(WORK_QUEUE_ITEM, List);
    LayoutOut->WorkItemRoutine =
        (ULONG)FIELD_OFFSET(WORK_QUEUE_ITEM, WorkerRoutine);
    LayoutOut->WorkItemParameter =
        (ULONG)FIELD_OFFSET(WORK_QUEUE_ITEM, Parameter);
    LayoutOut->ExPoolUntrusted = chain.PoolIndex;
    LayoutOut->EpartitionTypeSize = chain.PartitionExPartition + sizeof(PVOID);
    LayoutOut->ExPartitionTypeSize =
        chain.ExPartitionWorkQueues + sizeof(PVOID);
    LayoutOut->KpriQueueTypeSize = chain.PriQueueOffset +
        (KSW_WORK_QUEUE_FALLBACK_PRIORITY_COUNT * sizeof(LIST_ENTRY));
    LayoutOut->ExWorkQueueTypeSize = LayoutOut->KpriQueueTypeSize;
    LayoutOut->WorkItemTypeSize = sizeof(WORK_QUEUE_ITEM);
    LayoutOut->RuntimeFlags =
        KSW_DYN_V4_WORK_QUEUE_RUNTIME_SIGNATURE |
        KSW_DYN_V4_WORK_QUEUE_RUNTIME_ITEMS;

    if (KswordARKWorkQueueFallbackInferThreadQueueOffset(
            &chain,
            &threadQueueOffset) &&
        state.Kernel.EtStartAddress != KSW_DYN_OFFSET_UNAVAILABLE &&
        (state.KernelSources.EtStartAddress ==
             KSW_DYN_FIELD_SOURCE_PDB_PROFILE ||
         state.KernelSources.EtStartAddress ==
             KSW_DYN_FIELD_SOURCE_RUNTIME_PATTERN)) {
        LayoutOut->EthreadTcb = 0UL;
        LayoutOut->KthreadQueue = threadQueueOffset;
        LayoutOut->EthreadStartAddress = state.Kernel.EtStartAddress;
        LayoutOut->KthreadTypeSize = threadQueueOffset + sizeof(PVOID);
        LayoutOut->EthreadTypeSize = max(
            LayoutOut->KthreadTypeSize,
            LayoutOut->EthreadStartAddress + (ULONG)sizeof(PVOID));
        LayoutOut->RuntimeFlags |= KSW_DYN_V4_WORK_QUEUE_RUNTIME_THREADS;
    }
    status = STATUS_SUCCESS;

Exit:
    ExFreePoolWithTag(references, KSW_WORK_QUEUE_FALLBACK_TAG);
    if (!NT_SUCCESS(status)) {
        RtlZeroMemory(LayoutOut, sizeof(*LayoutOut));
    }
    return status;
}

NTSTATUS
KswordARKWorkQueueResolveActiveExWorkerField(
    _Out_ KSW_DYN_V4_BIT_FIELD_LAYOUT* FieldOut
    )
/*++

Routine Description:

    Infer ActiveExWorker from System threads whose queue pointer matches the
    independently signature-resolved Ex queues. Worker and non-worker samples
    must produce exactly one distinguishing set bit; ambiguity fails closed.

Return Value:

    STATUS_SUCCESS for one live-validated bit, otherwise a fail-closed status.

--*/
{
    KSW_DYN_V4_WORK_QUEUE_LAYOUT layout;
    KSW_WORK_QUEUE_CHAIN chain;
    UNICODE_STRING routineName;
    KSW_WORK_QUEUE_FALLBACK_NEXT_THREAD_FN nextThreadFunction = NULL;
    UCHAR* samples = NULL;
    UCHAR* workerSamples = NULL;
    UCHAR* otherSamples = NULL;
    ULONG workerCount = 0UL;
    ULONG otherCount = 0UL;
    ULONG threadQueueOffset = 0UL;
    ULONG_PTR partitionGlobal = 0U;
    ULONG offset = 0UL;
    ULONG bit = 0UL;
    LONG foundOffset = -1;
    LONG foundBit = -1;
    PETHREAD thread = NULL;
    NTSTATUS status = STATUS_NOT_SUPPORTED;

    if (FieldOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    RtlZeroMemory(FieldOut, sizeof(*FieldOut));
    RtlZeroMemory(&layout, sizeof(layout));
    RtlZeroMemory(&chain, sizeof(chain));
    status = KswordARKWorkQueueResolveRuntimeLayout(&layout);
    if (!NT_SUCCESS(status) ||
        (layout.RuntimeFlags & KSW_DYN_V4_WORK_QUEUE_RUNTIME_THREADS) == 0UL ||
        layout.ModuleBase > MAXULONG_PTR - layout.PspSystemPartitionRva) {
        return STATUS_NOT_SUPPORTED;
    }
    partitionGlobal = (ULONG_PTR)layout.ModuleBase +
        layout.PspSystemPartitionRva;
    if (!KswordARKWorkQueueFallbackValidateChainCandidate(
            partitionGlobal,
            layout.EpartitionExPartition,
            layout.ExPartitionWorkQueues,
            layout.ExPoolUntrusted,
            &chain) ||
        !KswordARKWorkQueueFallbackInferThreadQueueOffset(
            &chain,
            &threadQueueOffset) ||
        threadQueueOffset != layout.KthreadQueue ||
        PsInitialSystemProcess == NULL) {
        return STATUS_NOT_SUPPORTED;
    }

    samples = (UCHAR*)KswordARKAllocateNonPagedPool(
        (2UL * KSW_WORK_QUEUE_FALLBACK_WORKER_SAMPLES) *
            KSW_WORK_QUEUE_FALLBACK_THREAD_SCAN,
        KSW_WORK_QUEUE_FALLBACK_TAG);
    if (samples == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlZeroMemory(
        samples,
        (2UL * KSW_WORK_QUEUE_FALLBACK_WORKER_SAMPLES) *
            KSW_WORK_QUEUE_FALLBACK_THREAD_SCAN);
    workerSamples = samples;
    otherSamples = samples +
        (KSW_WORK_QUEUE_FALLBACK_WORKER_SAMPLES *
         KSW_WORK_QUEUE_FALLBACK_THREAD_SCAN);

    RtlInitUnicodeString(&routineName, L"PsGetNextProcessThread");
    nextThreadFunction = (KSW_WORK_QUEUE_FALLBACK_NEXT_THREAD_FN)
        MmGetSystemRoutineAddress(&routineName);
    if (nextThreadFunction == NULL) {
        status = STATUS_PROCEDURE_NOT_FOUND;
        goto Exit;
    }
    thread = nextThreadFunction(PsInitialSystemProcess, NULL);
    while (thread != NULL &&
           (workerCount < KSW_WORK_QUEUE_FALLBACK_WORKER_SAMPLES ||
            otherCount < KSW_WORK_QUEUE_FALLBACK_WORKER_SAMPLES)) {
        PETHREAD nextThread = NULL;
        ULONG_PTR queueAddress = 0U;
        BOOLEAN worker = FALSE;
        UCHAR* destination = NULL;

        if (KswordARKRuntimeReadMemory(
                (const UCHAR*)thread + threadQueueOffset,
                &queueAddress,
                sizeof(queueAddress))) {
            worker = KswordARKWorkQueueFallbackQueueAddressMatches(
                queueAddress,
                &chain);
            if (worker && workerCount < KSW_WORK_QUEUE_FALLBACK_WORKER_SAMPLES) {
                destination = workerSamples +
                    (workerCount * KSW_WORK_QUEUE_FALLBACK_THREAD_SCAN);
            }
            else if (!worker &&
                     otherCount < KSW_WORK_QUEUE_FALLBACK_WORKER_SAMPLES) {
                destination = otherSamples +
                    (otherCount * KSW_WORK_QUEUE_FALLBACK_THREAD_SCAN);
            }
            if (destination != NULL &&
                KswordARKRuntimeReadMemory(
                    thread,
                    destination,
                    KSW_WORK_QUEUE_FALLBACK_THREAD_SCAN)) {
                if (worker) {
                    workerCount += 1UL;
                }
                else {
                    otherCount += 1UL;
                }
            }
        }
        nextThread = nextThreadFunction(PsInitialSystemProcess, thread);
        ObDereferenceObject(thread);
        thread = nextThread;
    }
    if (thread != NULL) {
        ObDereferenceObject(thread);
        thread = NULL;
    }
    if (workerCount < 2UL || otherCount < 2UL) {
        status = STATUS_NOT_FOUND;
        goto Exit;
    }

    for (offset = sizeof(DISPATCHER_HEADER);
         offset < KSW_WORK_QUEUE_FALLBACK_THREAD_SCAN;
         ++offset) {
        for (bit = 0UL; bit < 8UL; ++bit) {
            UCHAR mask = (UCHAR)(1U << bit);
            ULONG sampleIndex = 0UL;
            BOOLEAN distinguishes = TRUE;

            for (sampleIndex = 0UL; sampleIndex < workerCount; ++sampleIndex) {
                if ((workerSamples[
                         sampleIndex * KSW_WORK_QUEUE_FALLBACK_THREAD_SCAN +
                         offset] & mask) == 0U) {
                    distinguishes = FALSE;
                    break;
                }
            }
            for (sampleIndex = 0UL;
                 distinguishes && sampleIndex < otherCount;
                 ++sampleIndex) {
                if ((otherSamples[
                         sampleIndex * KSW_WORK_QUEUE_FALLBACK_THREAD_SCAN +
                         offset] & mask) != 0U) {
                    distinguishes = FALSE;
                }
            }
            if (!distinguishes) {
                continue;
            }
            if (foundOffset >= 0) {
                status = STATUS_OBJECT_NAME_COLLISION;
                goto Exit;
            }
            foundOffset = (LONG)offset;
            foundBit = (LONG)bit;
        }
    }
    if (foundOffset < 0 || foundBit < 0) {
        status = STATUS_NOT_FOUND;
        goto Exit;
    }
    FieldOut->Offset = (ULONG)foundOffset;
    FieldOut->BitOffset = (ULONG)foundBit;
    FieldOut->BitCount = 1UL;
    FieldOut->StorageBytes = 1UL;
    status = STATUS_SUCCESS;

Exit:
    if (thread != NULL) {
        ObDereferenceObject(thread);
    }
    ExFreePoolWithTag(samples, KSW_WORK_QUEUE_FALLBACK_TAG);
    if (!NT_SUCCESS(status)) {
        RtlZeroMemory(FieldOut, sizeof(*FieldOut));
    }
    return status;
}
