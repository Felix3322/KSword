/*++

Module Name:

    kernel_idt_baseline.c

Abstract:

    Capture an immutable, per-CPU IDT baseline during driver initialization and
    provide compare-and-swap restoration for one verified descriptor.

Environment:

    Kernel mode, PASSIVE_LEVEL for initialize/restore callers.

--*/

#include "kernel_idt_baseline.h"
#include "src/platform/pool_compat.h"

#include <intrin.h>

#define KSW_IDT_BASELINE_TAG 'bIsK'
#define KSW_IDT_BASELINE_VECTOR_COUNT 256UL
#define KSW_IDT_BASELINE_ENTRY_BYTES 16UL

#ifndef ALL_PROCESSOR_GROUPS
#define ALL_PROCESSOR_GROUPS 0xFFFFU
#endif

#if defined(_M_AMD64) || defined(_M_X64)
#pragma intrinsic(__sidt)
#pragma intrinsic(_InterlockedCompareExchange128)
#endif

#pragma pack(push, 1)
typedef struct _KSW_IDT_BASELINE_REGISTER
{
    USHORT Limit;
    ULONG_PTR Base;
} KSW_IDT_BASELINE_REGISTER, *PKSW_IDT_BASELINE_REGISTER;

typedef struct _KSW_IDT_BASELINE_ENTRY
{
    USHORT OffsetLow;
    USHORT Selector;
    USHORT IstAndType;
    USHORT OffsetMiddle;
    ULONG OffsetHigh;
    ULONG Reserved;
} KSW_IDT_BASELINE_ENTRY, *PKSW_IDT_BASELINE_ENTRY;
#pragma pack(pop)

typedef struct _KSW_IDT_BASELINE_CPU
{
    USHORT Group;
    UCHAR Number;
    UCHAR Captured;
    ULONG VectorCount;
    KSW_IDT_BASELINE_REGISTER Idtr;
    KSW_IDT_BASELINE_ENTRY Entries[KSW_IDT_BASELINE_VECTOR_COUNT];
} KSW_IDT_BASELINE_CPU, *PKSW_IDT_BASELINE_CPU;

typedef struct _KSW_IDT_BASELINE_STATE
{
    PKSW_IDT_BASELINE_CPU Cpus;
    ULONG CpuCount;
    ULONG Generation;
    BOOLEAN Initialized;
} KSW_IDT_BASELINE_STATE;

static KSW_IDT_BASELINE_STATE g_KswordArkIdtBaseline;

static ULONGLONG
KswordARKIdtBaselineHandler(
    _In_ const KSW_IDT_BASELINE_ENTRY* Entry
    )
/*++

Routine Description:

    Decode one x64 interrupt/trap gate handler address.

Arguments:

    Entry - Copied 16-byte IDT gate.

Return Value:

    Canonical handler value or zero for invalid input/architecture.

--*/
{
#if defined(_M_AMD64) || defined(_M_X64)
    ULONGLONG handler = 0ULL;

    /* Validate the input pointer before decoding the fixed fields. */
    if (Entry == NULL) {
        return 0ULL;
    }

    /* Combine the three offset fragments defined by an x64 gate. */
    handler = (ULONGLONG)Entry->OffsetLow;
    handler |= ((ULONGLONG)Entry->OffsetMiddle) << 16;
    handler |= ((ULONGLONG)Entry->OffsetHigh) << 32;
    return handler;
#else
    UNREFERENCED_PARAMETER(Entry);
    return 0ULL;
#endif
}

static PKSW_IDT_BASELINE_CPU
KswordARKIdtBaselineFindCpu(
    _In_ USHORT ProcessorGroup,
    _In_ UCHAR ProcessorNumber
    )
/*++

Routine Description:

    Find one immutable baseline row by processor identity.

Arguments:

    ProcessorGroup - Windows processor group.
    ProcessorNumber - Processor number within the group.

Return Value:

    Baseline row or NULL.

--*/
{
    ULONG index = 0UL;

    /* Reject lookups until initialization has published the immutable array. */
    if (!g_KswordArkIdtBaseline.Initialized ||
        g_KswordArkIdtBaseline.Cpus == NULL) {
        return NULL;
    }

    /* Scan the bounded CPU array; the row count came from the kernel topology. */
    for (index = 0UL;
         index < g_KswordArkIdtBaseline.CpuCount;
         ++index) {
        PKSW_IDT_BASELINE_CPU row =
            &g_KswordArkIdtBaseline.Cpus[index];

        /* Return only a fully captured row with an exact group/number match. */
        if (row->Captured != 0U &&
            row->Group == ProcessorGroup &&
            row->Number == ProcessorNumber) {
            return row;
        }
    }

    /* No captured row matched the requested processor. */
    return NULL;
}

NTSTATUS
KswordARKIdtBaselineInitialize(
    VOID
    )
/*++

Routine Description:

    Capture every active processor's IDTR and up to 256 gate descriptors before
    the control device begins accepting requests.

Arguments:

    None.

Return Value:

    STATUS_SUCCESS or a bounded allocation/topology/capture error.

--*/
{
#if defined(_M_AMD64) || defined(_M_X64)
    ULONG activeCount = 0UL;
    SIZE_T allocationBytes = 0U;
    PKSW_IDT_BASELINE_CPU rows = NULL;
    ULONG globalIndex = 0UL;
    ULONG capturedCount = 0UL;

    /* Make repeated initialization idempotent. */
    if (g_KswordArkIdtBaseline.Initialized) {
        return STATUS_SUCCESS;
    }

    /* Query the exact active logical processor count across all groups. */
    activeCount = KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS);
    if (activeCount == 0UL ||
        activeCount > MAXULONG_PTR / sizeof(KSW_IDT_BASELINE_CPU)) {
        return STATUS_NOT_SUPPORTED;
    }

    /* Allocate one fixed 4 KiB descriptor snapshot per active CPU. */
    allocationBytes =
        (SIZE_T)activeCount * sizeof(KSW_IDT_BASELINE_CPU);
    rows = (PKSW_IDT_BASELINE_CPU)KswordARKAllocateNonPagedPool(
        allocationBytes,
        KSW_IDT_BASELINE_TAG);
    if (rows == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    /* Zero all rows before any processor-specific capture becomes visible. */
    RtlZeroMemory(rows, allocationBytes);

    /* Visit processors sequentially so the caller remains at PASSIVE_LEVEL. */
    for (globalIndex = 0UL;
         globalIndex < activeCount;
         ++globalIndex) {
        PROCESSOR_NUMBER processor;
        GROUP_AFFINITY targetAffinity;
        GROUP_AFFINITY previousAffinity;
        KSW_IDT_BASELINE_REGISTER idtr;
        PKSW_IDT_BASELINE_CPU row = &rows[capturedCount];
        ULONG vectorCount = 0UL;
        SIZE_T copyBytes = 0U;
        NTSTATUS processorStatus = STATUS_SUCCESS;

        /* Resolve the stable global topology index into group/number identity. */
        RtlZeroMemory(&processor, sizeof(processor));
        processorStatus =
            KeGetProcessorNumberFromIndex(globalIndex, &processor);
        if (!NT_SUCCESS(processorStatus) ||
            processor.Number >= sizeof(KAFFINITY) * 8UL) {
            continue;
        }

        /* Build a single-CPU group affinity for the read-only capture. */
        RtlZeroMemory(&targetAffinity, sizeof(targetAffinity));
        RtlZeroMemory(&previousAffinity, sizeof(previousAffinity));
        targetAffinity.Group = processor.Group;
        targetAffinity.Mask =
            ((KAFFINITY)1) << processor.Number;

        /* Execute SIDT and descriptor copying on the selected processor. */
        KeSetSystemGroupAffinityThread(
            &targetAffinity,
            &previousAffinity);
        RtlZeroMemory(&idtr, sizeof(idtr));
        __sidt(&idtr);

        /* Bound the captured descriptor count to the architectural maximum. */
        vectorCount =
            ((ULONG)idtr.Limit + 1UL) / KSW_IDT_BASELINE_ENTRY_BYTES;
        if (vectorCount > KSW_IDT_BASELINE_VECTOR_COUNT) {
            vectorCount = KSW_IDT_BASELINE_VECTOR_COUNT;
        }
        copyBytes =
            (SIZE_T)vectorCount * sizeof(KSW_IDT_BASELINE_ENTRY);

        /* Copy the selected CPU's IDT under exception protection. */
        __try {
            if (idtr.Base != 0U &&
                vectorCount != 0UL) {
                RtlCopyMemory(
                    row->Entries,
                    (const VOID*)idtr.Base,
                    copyBytes);
                row->Group = processor.Group;
                row->Number = processor.Number;
                row->VectorCount = vectorCount;
                row->Idtr = idtr;
                row->Captured = 1U;
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            row->Captured = 0U;
        }

        /* Restore the caller's original group affinity before continuing. */
        KeRevertToUserGroupAffinityThread(&previousAffinity);
        if (row->Captured != 0U) {
            capturedCount += 1UL;
        }
    }

    /* Reject an empty snapshot and release its private allocation. */
    if (capturedCount == 0UL) {
        ExFreePoolWithTag(rows, KSW_IDT_BASELINE_TAG);
        return STATUS_NOT_FOUND;
    }

    /* Publish the immutable state only after every successful row is complete. */
    RtlZeroMemory(
        &g_KswordArkIdtBaseline,
        sizeof(g_KswordArkIdtBaseline));
    g_KswordArkIdtBaseline.Cpus = rows;
    g_KswordArkIdtBaseline.CpuCount = capturedCount;
    g_KswordArkIdtBaseline.Generation = 1UL;
    g_KswordArkIdtBaseline.Initialized = TRUE;
    return STATUS_SUCCESS;
#else
    return STATUS_NOT_SUPPORTED;
#endif
}

VOID
KswordARKIdtBaselineUninitialize(
    VOID
    )
/*++

Routine Description:

    Unpublish and release the immutable IDT baseline at driver unload.

Arguments:

    None.

Return Value:

    None.

--*/
{
    PKSW_IDT_BASELINE_CPU rows = g_KswordArkIdtBaseline.Cpus;

    /* Unpublish state before freeing the private array. */
    RtlZeroMemory(
        &g_KswordArkIdtBaseline,
        sizeof(g_KswordArkIdtBaseline));

    /* Release only an allocation owned by this module. */
    if (rows != NULL) {
        ExFreePoolWithTag(rows, KSW_IDT_BASELINE_TAG);
    }
}

BOOLEAN
KswordARKIdtBaselineQuery(
    _In_ USHORT ProcessorGroup,
    _In_ UCHAR ProcessorNumber,
    _In_ UCHAR Vector,
    _Out_opt_ ULONGLONG* TableBaseOut,
    _Out_opt_ ULONG* TableLimitOut,
    _Out_opt_ ULONGLONG* EntryAddressOut,
    _Out_opt_ ULONGLONG* RawLowOut,
    _Out_opt_ ULONGLONG* RawHighOut,
    _Out_opt_ ULONGLONG* HandlerOut,
    _Out_opt_ ULONG* GenerationOut
    )
/*++

Routine Description:

    Return one descriptor from the immutable initialization snapshot.

Arguments:

    ProcessorGroup/ProcessorNumber/Vector - Exact descriptor identity.
    Remaining parameters - Optional typed baseline outputs.

Return Value:

    TRUE when the exact descriptor exists.

--*/
{
    PKSW_IDT_BASELINE_CPU row = NULL;
    const KSW_IDT_BASELINE_ENTRY* entry = NULL;
    ULONGLONG rawLow = 0ULL;
    ULONGLONG rawHigh = 0ULL;

    /* Resolve the requested processor against the immutable snapshot. */
    row = KswordARKIdtBaselineFindCpu(
        ProcessorGroup,
        ProcessorNumber);
    if (row == NULL || Vector >= row->VectorCount) {
        return FALSE;
    }

    /* Copy the fixed gate halves without unaligned integer dereferences. */
    entry = &row->Entries[Vector];
    RtlCopyMemory(&rawLow, entry, sizeof(rawLow));
    RtlCopyMemory(
        &rawHigh,
        (const UCHAR*)entry + sizeof(rawLow),
        sizeof(rawHigh));

    /* Populate only outputs explicitly requested by the caller. */
    if (TableBaseOut != NULL) {
        *TableBaseOut = (ULONGLONG)row->Idtr.Base;
    }
    if (TableLimitOut != NULL) {
        *TableLimitOut = row->Idtr.Limit;
    }
    if (EntryAddressOut != NULL) {
        *EntryAddressOut =
            (ULONGLONG)row->Idtr.Base +
            ((ULONGLONG)Vector * KSW_IDT_BASELINE_ENTRY_BYTES);
    }
    if (RawLowOut != NULL) {
        *RawLowOut = rawLow;
    }
    if (RawHighOut != NULL) {
        *RawHighOut = rawHigh;
    }
    if (HandlerOut != NULL) {
        *HandlerOut = KswordARKIdtBaselineHandler(entry);
    }
    if (GenerationOut != NULL) {
        *GenerationOut = g_KswordArkIdtBaseline.Generation;
    }
    return TRUE;
}

NTSTATUS
KswordARKIdtBaselineRestore(
    _In_ const KSWORD_ARK_RESTORE_IDT_BASELINE_REQUEST* Request,
    _Out_ KSWORD_ARK_RESTORE_IDT_BASELINE_RESPONSE* Response
    )
/*++

Routine Description:

    Restore one IDT descriptor using an aligned CMPXCHG16B after exact CPU,
    table, immutable baseline and expected-current validation.

Arguments:

    Request - Fixed protocol request with exact expected current descriptor.
    Response - Fixed result including before/baseline/after halves.

Return Value:

    STATUS_SUCCESS when Response is valid; semantic status is in Response.

--*/
{
#if defined(_M_AMD64) || defined(_M_X64)
    PKSW_IDT_BASELINE_CPU baselineCpu = NULL;
    const KSW_IDT_BASELINE_ENTRY* baselineEntry = NULL;
    PROCESSOR_NUMBER requestedProcessor;
    PROCESSOR_NUMBER processor;
    ULONG processorIndex = MAXULONG;
    GROUP_AFFINITY targetAffinity;
    GROUP_AFFINITY previousAffinity;
    KSW_IDT_BASELINE_REGISTER currentIdtr;
    volatile LONG64* destination = NULL;
    LONG64 comparand[2] = { 0, 0 };
    ULONGLONG currentLow = 0ULL;
    ULONGLONG currentHigh = 0ULL;
    ULONGLONG afterLow = 0ULL;
    ULONGLONG afterHigh = 0ULL;
    CHAR exchanged = 0;
    NTSTATUS status = STATUS_SUCCESS;

    /* Validate fixed protocol identity before touching processor affinity. */
    if (Request == NULL || Response == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    RtlZeroMemory(Response, sizeof(*Response));
    Response->version = KSWORD_ARK_KERNEL_BASELINE_PROTOCOL_VERSION;
    Response->size = sizeof(*Response);
    Response->status =
        KSWORD_ARK_IDT_RESTORE_STATUS_INVALID_REQUEST;
    if (Request->version != KSWORD_ARK_KERNEL_BASELINE_PROTOCOL_VERSION ||
        Request->size != sizeof(*Request) ||
        Request->confirmationToken !=
            KSWORD_ARK_IDT_RESTORE_CONFIRMATION_TOKEN) {
        return STATUS_SUCCESS;
    }

    /* Require the exact immutable processor/vector snapshot. */
    baselineCpu = KswordARKIdtBaselineFindCpu(
        Request->processorGroup,
        Request->processorNumber);
    if (baselineCpu == NULL ||
        Request->vector >= baselineCpu->VectorCount) {
        Response->status =
            KSWORD_ARK_IDT_RESTORE_STATUS_BASELINE_MISSING;
        Response->lastStatus = STATUS_NOT_FOUND;
        return STATUS_SUCCESS;
    }
    baselineEntry = &baselineCpu->Entries[Request->vector];
    Response->baselineGeneration =
        g_KswordArkIdtBaseline.Generation;
    RtlCopyMemory(
        &Response->baselineRawLow,
        baselineEntry,
        sizeof(Response->baselineRawLow));
    RtlCopyMemory(
        &Response->baselineRawHigh,
        (const UCHAR*)baselineEntry +
            sizeof(Response->baselineRawLow),
        sizeof(Response->baselineRawHigh));

    /* Resolve the processor identity again against the live topology. */
    RtlZeroMemory(&requestedProcessor, sizeof(requestedProcessor));
    RtlZeroMemory(&processor, sizeof(processor));
    requestedProcessor.Group = Request->processorGroup;
    requestedProcessor.Number = Request->processorNumber;
    processorIndex =
        KeGetProcessorIndexFromNumber(&requestedProcessor);
    if (processorIndex == MAXULONG) {
        Response->status =
            KSWORD_ARK_IDT_RESTORE_STATUS_CPU_UNAVAILABLE;
        Response->lastStatus = STATUS_NOT_FOUND;
        return STATUS_SUCCESS;
    }
    status = KeGetProcessorNumberFromIndex(
        processorIndex,
        &processor);
    if (!NT_SUCCESS(status) ||
        processor.Group != Request->processorGroup ||
        processor.Number != Request->processorNumber) {
        Response->status =
            KSWORD_ARK_IDT_RESTORE_STATUS_CPU_UNAVAILABLE;
        Response->lastStatus = status;
        return STATUS_SUCCESS;
    }

    /* Pin the current thread to the exact processor owning this IDT. */
    RtlZeroMemory(&targetAffinity, sizeof(targetAffinity));
    RtlZeroMemory(&previousAffinity, sizeof(previousAffinity));
    targetAffinity.Group = Request->processorGroup;
    targetAffinity.Mask =
        ((KAFFINITY)1) << Request->processorNumber;
    KeSetSystemGroupAffinityThread(
        &targetAffinity,
        &previousAffinity);

    /* Re-read IDTR and reject a table replacement since initialization. */
    RtlZeroMemory(&currentIdtr, sizeof(currentIdtr));
    __sidt(&currentIdtr);
    if (currentIdtr.Base != baselineCpu->Idtr.Base ||
        currentIdtr.Limit != baselineCpu->Idtr.Limit) {
        Response->status =
            KSWORD_ARK_IDT_RESTORE_STATUS_TABLE_CHANGED;
        Response->lastStatus = STATUS_REVISION_MISMATCH;
        KeRevertToUserGroupAffinityThread(&previousAffinity);
        return STATUS_SUCCESS;
    }

    /* Calculate and validate the naturally aligned 16-byte gate address. */
    Response->entryAddress =
        (ULONGLONG)currentIdtr.Base +
        ((ULONGLONG)Request->vector *
            KSW_IDT_BASELINE_ENTRY_BYTES);
    if ((Response->entryAddress &
            (KSW_IDT_BASELINE_ENTRY_BYTES - 1UL)) != 0ULL) {
        Response->status =
            KSWORD_ARK_IDT_RESTORE_STATUS_WRITE_FAILED;
        Response->lastStatus = STATUS_DATATYPE_MISALIGNMENT;
        KeRevertToUserGroupAffinityThread(&previousAffinity);
        return STATUS_SUCCESS;
    }
    destination =
        (volatile LONG64*)(ULONG_PTR)Response->entryAddress;

    /* Copy the live descriptor under exception protection. */
    __try {
        RtlCopyMemory(
            &currentLow,
            (const VOID*)destination,
            sizeof(currentLow));
        RtlCopyMemory(
            &currentHigh,
            (const UCHAR*)destination + sizeof(currentLow),
            sizeof(currentHigh));
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();
        Response->status =
            KSWORD_ARK_IDT_RESTORE_STATUS_WRITE_FAILED;
        Response->lastStatus = status;
        KeRevertToUserGroupAffinityThread(&previousAffinity);
        return STATUS_SUCCESS;
    }
    Response->beforeRawLow = currentLow;
    Response->beforeRawHigh = currentHigh;

    /* Compare both halves with the UI snapshot to prevent stale restoration. */
    if (currentLow != Request->expectedRawLow ||
        currentHigh != Request->expectedRawHigh) {
        Response->status =
            KSWORD_ARK_IDT_RESTORE_STATUS_CURRENT_MISMATCH;
        Response->lastStatus = STATUS_REVISION_MISMATCH;
        KeRevertToUserGroupAffinityThread(&previousAffinity);
        return STATUS_SUCCESS;
    }

    /* The non-force call is a read-only preflight used for the first prompt. */
    if ((Request->flags & KSWORD_ARK_IDT_RESTORE_FLAG_FORCE) == 0UL) {
        Response->status =
            KSWORD_ARK_IDT_RESTORE_STATUS_FORCE_REQUIRED;
        Response->lastStatus = STATUS_REQUEST_NOT_ACCEPTED;
        KeRevertToUserGroupAffinityThread(&previousAffinity);
        return STATUS_SUCCESS;
    }

    /* Atomically replace the complete gate only if both observed halves match. */
    comparand[0] = (LONG64)currentLow;
    comparand[1] = (LONG64)currentHigh;
    exchanged = _InterlockedCompareExchange128(
        destination,
        (LONG64)Response->baselineRawHigh,
        (LONG64)Response->baselineRawLow,
        comparand);
    KeMemoryBarrier();
    if (exchanged == 0) {
        Response->status =
            KSWORD_ARK_IDT_RESTORE_STATUS_CURRENT_MISMATCH;
        Response->lastStatus = STATUS_REVISION_MISMATCH;
        KeRevertToUserGroupAffinityThread(&previousAffinity);
        return STATUS_SUCCESS;
    }

    /* Read back both halves and require an exact baseline match. */
    __try {
        RtlCopyMemory(
            &afterLow,
            (const VOID*)destination,
            sizeof(afterLow));
        RtlCopyMemory(
            &afterHigh,
            (const UCHAR*)destination + sizeof(afterLow),
            sizeof(afterHigh));
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();
        Response->status =
            KSWORD_ARK_IDT_RESTORE_STATUS_VERIFY_FAILED;
        Response->lastStatus = status;
        KeRevertToUserGroupAffinityThread(&previousAffinity);
        return STATUS_SUCCESS;
    }
    Response->afterRawLow = afterLow;
    Response->afterRawHigh = afterHigh;
    if (afterLow != Response->baselineRawLow ||
        afterHigh != Response->baselineRawHigh) {
        Response->status =
            KSWORD_ARK_IDT_RESTORE_STATUS_VERIFY_FAILED;
        Response->lastStatus = STATUS_DATA_ERROR;
        KeRevertToUserGroupAffinityThread(&previousAffinity);
        return STATUS_SUCCESS;
    }

    /* Restore affinity after the atomic, verified update completes. */
    Response->status = KSWORD_ARK_IDT_RESTORE_STATUS_OK;
    Response->lastStatus = STATUS_SUCCESS;
    KeRevertToUserGroupAffinityThread(&previousAffinity);
    return STATUS_SUCCESS;
#else
    UNREFERENCED_PARAMETER(Request);
    if (Response != NULL) {
        RtlZeroMemory(Response, sizeof(*Response));
        Response->version =
            KSWORD_ARK_KERNEL_BASELINE_PROTOCOL_VERSION;
        Response->size = sizeof(*Response);
        Response->status =
            KSWORD_ARK_IDT_RESTORE_STATUS_CPU_UNAVAILABLE;
        Response->lastStatus = STATUS_NOT_SUPPORTED;
    }
    return STATUS_SUCCESS;
#endif
}
