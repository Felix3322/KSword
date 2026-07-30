/*++

Module Name:

    mutation_transaction.c

Abstract:

    Controlled kernel mutation transaction backend.

Environment:

    Kernel-mode Driver Framework

--*/

#include "mutation_transaction.h"
#include "ark/ark_dyndata.h"
#include "ark/ark_log.h"
#include "ark/ark_safety.h"

#include <ntstrsafe.h>

#ifndef STATUS_REQUEST_NOT_ACCEPTED
#define STATUS_REQUEST_NOT_ACCEPTED ((NTSTATUS)0xC00000D0L)
#endif

#define KSWORD_ARK_MUTATION_INITING 1L
#define KSWORD_ARK_MUTATION_READY 2L
#define KSWORD_ARK_MUTATION_FNV_OFFSET 14695981039346656037ULL
#define KSWORD_ARK_MUTATION_FNV_PRIME 1099511628211ULL
#define KSWORD_ARK_MUTATION_USER_TOP 0x00007FFFFFFFFFFFULL
#define KSWORD_ARK_MUTATION_KERNEL_BASE 0xFFFF800000000000ULL
#define KSWORD_ARK_MUTATION_TRANSACTION_TTL_SECONDS 120UL
#define KSWORD_ARK_MUTATION_TERMINAL_TTL_SECONDS 30UL

typedef struct _KSWORD_ARK_MUTATION_SLOT
{
    BOOLEAN InUse;
    BOOLEAN OperationBusy;
    BOOLEAN CommitAttempted;
    BOOLEAN CommitSucceeded;
    BOOLEAN RollbackAttempted;
    ULONG Flags;
    ULONG Status;
    ULONG TargetKind;
    ULONG OwnerProcessId;
    PEPROCESS OwnerProcessObject;
    PEPROCESS TargetProcessObject;
    ULONG ProcessId;
    ULONG Bytes;
    ULONG RiskFlags;
    NTSTATUS LastStatus;
    ULONGLONG TransactionId;
    ULONGLONG TargetAddress;
    ULONGLONG TargetContext;
    ULONGLONG BeforeHash;
    ULONGLONG AfterHash;
    ULONGLONG TimestampTick;
    UCHAR BeforeBytes[KSWORD_ARK_MUTATION_MAX_BYTES];
    UCHAR AfterBytes[KSWORD_ARK_MUTATION_MAX_BYTES];
} KSWORD_ARK_MUTATION_SLOT;

typedef struct _KSWORD_ARK_MUTATION_STATE
{
    EX_PUSH_LOCK Lock;
    ULONGLONG NextTransactionId;
    ULONGLONG NextAuditSequence;
    KSWORD_ARK_MUTATION_SLOT Slots[KSWORD_ARK_MUTATION_AUDIT_RING_CAPACITY];
    KSWORD_ARK_MUTATION_AUDIT_ENTRY Audit[KSWORD_ARK_MUTATION_AUDIT_RING_CAPACITY];
} KSWORD_ARK_MUTATION_STATE;

static KSWORD_ARK_MUTATION_STATE g_KswordArkMutationState;
static volatile LONG g_KswordArkMutationInitState;

NTSYSAPI NTSTATUS NTAPI PsLookupProcessByProcessId(_In_ HANDLE ProcessId, _Outptr_ PEPROCESS* Process);

static VOID
KswordARKMutationEnsureInitialized(VOID)
/*++ Routine Description:
     Input none; initializes global lock, transaction ids, and audit sequence once.
     Processing is interlocked and wait-free after initialization. Return none. --*/
{
    LONG oldState = InterlockedCompareExchange((volatile LONG*)&g_KswordArkMutationInitState, KSWORD_ARK_MUTATION_INITING, 0L);
    if (oldState == 0L) {
        RtlZeroMemory(&g_KswordArkMutationState, sizeof(g_KswordArkMutationState));
        ExInitializePushLock(&g_KswordArkMutationState.Lock);
        g_KswordArkMutationState.NextTransactionId = 1ULL;
        g_KswordArkMutationState.NextAuditSequence = 1ULL;
        InterlockedExchange((volatile LONG*)&g_KswordArkMutationInitState, KSWORD_ARK_MUTATION_READY);
        return;
    }
    while (InterlockedCompareExchange((volatile LONG*)&g_KswordArkMutationInitState, KSWORD_ARK_MUTATION_READY, KSWORD_ARK_MUTATION_READY) != KSWORD_ARK_MUTATION_READY) {
        YieldProcessor();
    }
}

VOID
KswordARKMutationInitialize(VOID)
/*++ Routine Description:
     Input none; exposes explicit initialization for future DriverEntry integration.
     Processing delegates to lazy init. Return none. --*/
{
    KswordARKMutationEnsureInitialized();
}

static VOID
KswordARKMutationClearSlotLocked(
    _Inout_ KSWORD_ARK_MUTATION_SLOT* Slot)
/*++ Routine Description:
     Clears one global transaction slot while the mutation lock is held. The
     global slot exclusively owns its process-object reference; stack snapshots
     copy the pointer only for comparison and never release it. --*/
{
    if (Slot == NULL) {
        return;
    }
    if (Slot->OwnerProcessObject != NULL) {
        ObDereferenceObject(Slot->OwnerProcessObject);
        Slot->OwnerProcessObject = NULL;
    }
    if (Slot->TargetProcessObject != NULL) {
        ObDereferenceObject(Slot->TargetProcessObject);
        Slot->TargetProcessObject = NULL;
    }
    RtlSecureZeroMemory(Slot, sizeof(*Slot));
}

VOID
KswordARKMutationUninitialize(VOID)
/*++ Routine Description:
     Releases all process-object references retained by mutation transactions
     after IOCTL dispatch has stopped during driver unload. --*/
{
    ULONG index = 0UL;

    if (InterlockedCompareExchange(
            (volatile LONG*)&g_KswordArkMutationInitState,
            KSWORD_ARK_MUTATION_READY,
            KSWORD_ARK_MUTATION_READY) !=
        KSWORD_ARK_MUTATION_READY) {
        return;
    }

    ExAcquirePushLockExclusive(&g_KswordArkMutationState.Lock);
    for (index = 0UL;
         index < KSWORD_ARK_MUTATION_AUDIT_RING_CAPACITY;
         index += 1UL) {
        KswordARKMutationClearSlotLocked(
            &g_KswordArkMutationState.Slots[index]);
    }
    ExReleasePushLockExclusive(&g_KswordArkMutationState.Lock);
}

static ULONGLONG
KswordARKMutationTick(VOID)
/*++ Routine Description:
     Input none; reads a monotonic kernel tick for audit timestamps. Returns tick. --*/
{
    LARGE_INTEGER tick;
    KeQueryTickCount(&tick);
    return (ULONGLONG)tick.QuadPart;
}

static ULONGLONG
KswordARKMutationSecondsToTicks(_In_ ULONG Seconds)
/*++ Routine Description:
     Converts a bounded wall-clock interval to KeQueryTickCount units. --*/
{
    const ULONGLONG increment100ns =
        (ULONGLONG)KeQueryTimeIncrement();
    const ULONGLONG interval100ns =
        (ULONGLONG)Seconds * 10000000ULL;

    if (increment100ns == 0ULL) {
        return 1ULL;
    }
    return (interval100ns + increment100ns - 1ULL) /
        increment100ns;
}

static VOID
KswordARKMutationExpireSlotsLocked(_In_ ULONGLONG NowTick)
/*++ Routine Description:
     Clears nonbusy expired transactions while the caller holds the mutation
     lock. Rolled-back terminal state is retained briefly so replay is rejected
     explicitly; prepared/committed state remains available long enough for one
     owner-bound rollback. --*/
{
    const ULONGLONG transactionTtl =
        KswordARKMutationSecondsToTicks(
            KSWORD_ARK_MUTATION_TRANSACTION_TTL_SECONDS);
    const ULONGLONG terminalTtl =
        KswordARKMutationSecondsToTicks(
            KSWORD_ARK_MUTATION_TERMINAL_TTL_SECONDS);
    ULONG index = 0UL;

    for (index = 0UL;
         index < KSWORD_ARK_MUTATION_AUDIT_RING_CAPACITY;
         index += 1UL) {
        KSWORD_ARK_MUTATION_SLOT* slot =
            &g_KswordArkMutationState.Slots[index];
        ULONGLONG ttl = transactionTtl;

        if (!slot->InUse || slot->OperationBusy) {
            continue;
        }
        if (slot->RollbackAttempted) {
            ttl = terminalTtl;
        }
        if ((NowTick - slot->TimestampTick) < ttl) {
            continue;
        }
        KswordARKMutationClearSlotLocked(slot);
    }
}

static ULONGLONG
KswordARKMutationHash(_In_reads_bytes_opt_(ByteCount) const UCHAR* Bytes, _In_ ULONG ByteCount)
/*++ Routine Description:
     Input is a bounded byte buffer; computes FNV-1a as a compact non-crypto
     before/after marker. Returns a 64-bit hash. --*/
{
    ULONGLONG hashValue = KSWORD_ARK_MUTATION_FNV_OFFSET;
    ULONG index = 0UL;
    if (Bytes == NULL || ByteCount == 0UL) {
        return hashValue;
    }
    for (index = 0UL; index < ByteCount; index += 1UL) {
        hashValue ^= (ULONGLONG)Bytes[index];
        hashValue *= KSWORD_ARK_MUTATION_FNV_PRIME;
    }
    return hashValue;
}

static BOOLEAN
KswordARKMutationOffsetPresent(_In_ ULONG Offset)
/*++ Routine Description:
     Input is a DynData offset; filters unavailable sentinels before private field
     access. Returns TRUE only for usable offsets. --*/
{
    return (Offset != KSW_DYN_OFFSET_UNAVAILABLE && Offset != 0x0000FFFFUL) ? TRUE : FALSE;
}

static BOOLEAN
KswordARKMutationKernelAddress(_In_ ULONGLONG Address)
/*++ Routine Description:
     Input is a virtual address integer; checks x64 canonical kernel half only.
     Returns TRUE for accepted kernel addresses. --*/
{
    if (Address <= KSWORD_ARK_MUTATION_USER_TOP) {
        return FALSE;
    }
    if (Address < KSWORD_ARK_MUTATION_KERNEL_BASE) {
        return FALSE;
    }
    return TRUE;
}

static BOOLEAN
KswordARKMutationRangeReadable(_In_ ULONGLONG Address, _In_ ULONG Bytes)
/*++ Routine Description:
     Inputs are address and byte count; verifies a canonical, non-wrapping small
     kernel range. MmCopyMemory performs the actual fault-contained read, so this
     predicate does not reject a valid pageable kernel mapping merely because it
     is not resident at this instant. Returns TRUE for a syntactically valid
     snapshot range. --*/
{
    /* Reject zero-length and protocol-oversized requests before address math. */
    if (Bytes == 0UL || Bytes > KSWORD_ARK_MUTATION_MAX_BYTES) {
        /* A transaction may never escape its fixed response and audit buffers. */
        return FALSE;
    }
    /* Reject unsigned wraparound at the end of the requested byte range. */
    if ((ULONGLONG)Bytes > (((ULONGLONG)-1) - Address + 1ULL)) {
        /* A wrapping target cannot be represented by one exact transaction. */
        return FALSE;
    }
    /* Both endpoints must stay inside the canonical x64 kernel half. */
    if (!KswordARKMutationKernelAddress(Address) || !KswordARKMutationKernelAddress(Address + (ULONGLONG)Bytes - 1ULL)) {
        /* User addresses and the noncanonical hole are outside this target kind. */
        return FALSE;
    }
    /* The caller must use MmCopyMemory or an exception-guarded locked MDL next. */
    return TRUE;
}

static NTSTATUS
KswordARKMutationReadKernelBytes(_In_ ULONGLONG Address, _Out_writes_bytes_(Bytes) UCHAR* Buffer, _In_ ULONG Bytes)
/*++ Routine Description:
     Inputs are kernel virtual address and byte count; copies a checked system
     range with MmCopyMemory virtual mode. Processing is read-only. Returns full
     copy status or a validation failure. --*/
{
    MM_COPY_ADDRESS copyAddress;
    SIZE_T copied = 0U;
    NTSTATUS status = STATUS_SUCCESS;
    if (Buffer == NULL || !KswordARKMutationRangeReadable(Address, Bytes)) {
        return STATUS_ACCESS_VIOLATION;
    }
    /* MmCopyMemory may fault pageable system addresses only at APC_LEVEL or below. */
    if (KeGetCurrentIrql() > APC_LEVEL) {
        /* Defer rather than touching a pageable target at elevated IRQL. */
        return STATUS_INVALID_DEVICE_STATE;
    }
    RtlZeroMemory(&copyAddress, sizeof(copyAddress));
    copyAddress.VirtualAddress = (PVOID)(ULONG_PTR)Address;
    status = MmCopyMemory(Buffer, copyAddress, (SIZE_T)Bytes, MM_COPY_MEMORY_VIRTUAL, &copied);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    return (copied == (SIZE_T)Bytes) ? STATUS_SUCCESS : STATUS_PARTIAL_COPY;
}

static NTSTATUS
KswordARKMutationWriteKernelBytes(
    _In_ ULONGLONG Address,
    _In_reads_bytes_(Bytes) const UCHAR* ExpectedBytes,
    _In_reads_bytes_(Bytes) const UCHAR* Buffer,
    _In_ ULONG Bytes
    )
/*++

Routine Description:

    Writes one previously snapshotted kernel virtual-address range through a
    temporary writable MDL alias.  The caller has already compared the current
    bytes with the PREPARE snapshot and evaluated the central safety policy.
    This path never clears CR0.WP and never leaves a writable mapping behind.

Arguments:

    Address - Canonical kernel virtual address captured by PREPARE.
    ExpectedBytes - Bytes that must still be present immediately before copy.
    Buffer - Replacement or rollback bytes owned by the transaction slot.
    Bytes - Bounded transaction length.

Return Value:

    STATUS_SUCCESS after the alias write is visible, or an allocation, probe,
    mapping, protection, or exception status.

--*/
{
    /* The MDL describes the exact caller-selected virtual byte range. */
    PMDL mdl = NULL;
    /* The temporary system mapping is the only address used for the write. */
    PVOID writableAlias = NULL;
    /* Track whether MmProbeAndLockPages completed before cleanup unlocks it. */
    BOOLEAN pagesLocked = FALSE;
    /* Invalidate all processor mappings only after the alias is removed. */
    BOOLEAN writeCompleted = FALSE;
    /* Preserve the first concrete failure for the transaction response. */
    NTSTATUS status = STATUS_SUCCESS;

    /* Reapply the same canonical, nonwrapping and length gate used by PREPARE. */
    if (ExpectedBytes == NULL
        || Buffer == NULL
        || !KswordARKMutationRangeReadable(Address, Bytes)) {
        /* Refuse an address that no longer satisfies the transaction boundary. */
        return STATUS_ACCESS_VIOLATION;
    }
    /* Page probing, locking and mapping are intentionally confined to PASSIVE. */
    if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
        /* The R3 caller can retry through a passive execution-level queue. */
        return STATUS_INVALID_DEVICE_STATE;
    }

    /* Probe operations raise for invalid mappings, so cleanup is exception safe. */
    __try {
        /* Allocate an MDL for the exact virtual range without attaching an IRP. */
        mdl = IoAllocateMdl(
            (PVOID)(ULONG_PTR)Address,
            Bytes,
            FALSE,
            FALSE,
            NULL);
        /* Allocation failure leaves the target untouched. */
        if (mdl == NULL) {
            /* Surface the resource failure to the audited transaction result. */
            status = STATUS_INSUFFICIENT_RESOURCES;
            /* Leave the guarded block through the common cleanup path. */
            __leave;
        }

        /*
         * Probe the original mapping only for read access so a normal read-only
         * image section (for example, kernel .text) is not rejected. The locked
         * PFNs are then exposed through a separate temporary writable alias.
         */
        MmProbeAndLockPages(mdl, KernelMode, IoReadAccess);
        /* Cleanup may now safely call MmUnlockPages. */
        pagesLocked = TRUE;

        /*
         * Build a distinct non-executable mapping so the original mapping's
         * execute permissions are not broadened and CR0.WP is never changed.
         */
        writableAlias = MmMapLockedPagesSpecifyCache(
            mdl,
            KernelMode,
            MmCached,
            NULL,
            FALSE,
            NormalPagePriority | MdlMappingNoExecute);
        /* A missing alias means no byte has been modified. */
        if (writableAlias == NULL) {
            /* Report a bounded allocation/mapping failure. */
            status = STATUS_INSUFFICIENT_RESOURCES;
            /* Leave the guarded block through the common cleanup path. */
            __leave;
        }

        /* Explicitly grant write access only to the temporary system alias. */
        status = MmProtectMdlSystemAddress(mdl, PAGE_READWRITE);
        /* Protection failure leaves the original target mapping unchanged. */
        if (!NT_SUCCESS(status)) {
            /* Leave the guarded block through the common cleanup path. */
            __leave;
        }

        /*
         * Narrow the compare/write race by checking through the locked alias.
         * Generic live kernel memory cannot provide a true multi-byte atomic
         * CAS, so a concurrent change after this comparison remains an
         * explicitly reported risk.
         */
        if (RtlCompareMemory(
                writableAlias,
                ExpectedBytes,
                Bytes) != Bytes) {
            status = STATUS_REVISION_MISMATCH;
            __leave;
        }

        /* Copy only the transaction's bounded replacement or rollback bytes. */
        RtlCopyMemory(writableAlias, Buffer, Bytes);
        /* Publish the alias copy before its mapping is removed. */
        KeMemoryBarrier();
        writeCompleted = TRUE;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        /* Convert a probe, map, protection, or copy exception to NTSTATUS. */
        status = GetExceptionCode();
    }

    /* Remove the writable alias immediately after the bounded copy attempt. */
    if (writableAlias != NULL) {
        /* Unmap only the alias created by MmMapLockedPagesSpecifyCache. */
        MmUnmapLockedPages(writableAlias, mdl);
        /* Prevent cleanup from observing a stale writable virtual address. */
        writableAlias = NULL;
    }
    if (NT_SUCCESS(status) &&
        writeCompleted &&
        mdl != NULL &&
        pagesLocked) {
        /*
         * KeInvalidateRangeAllCaches flushes this physical range for every
         * virtual mapping on every processor and completes before returning.
         * It provides fetch visibility, not execution quiescence or atomicity.
         */
        KeInvalidateRangeAllCaches(
            (PVOID)(ULONG_PTR)Address,
            Bytes);
        KeMemoryBarrier();
    }
    /* Release physical-page locks only when the probe completed successfully. */
    if (mdl != NULL && pagesLocked) {
        /* Restore the pages to their normal memory-manager lifecycle. */
        MmUnlockPages(mdl);
        /* Prevent any accidental double unlock in future cleanup edits. */
        pagesLocked = FALSE;
    }
    /* Free the MDL descriptor after mapping and locking state is gone. */
    if (mdl != NULL) {
        /* The MDL contains no caller-owned buffer that needs separate freeing. */
        IoFreeMdl(mdl);
        /* Clear the local pointer before returning the final status. */
        mdl = NULL;
    }

    /* The commit path performs a fresh read and exact byte verification next. */
    return status;
}

static NTSTATUS
KswordARKMutationReadPplBytes(_In_ PEPROCESS ProcessObject, _In_ const KSW_DYN_STATE* DynState, _Out_writes_bytes_(Bytes) UCHAR* Buffer, _In_ ULONG Bytes)
/*++ Routine Description:
     Inputs are EPROCESS, DynData, output buffer, and count. Processing reads
     logical Protection, SignatureLevel, SectionSignatureLevel bytes by DynData
     offsets without contiguous-layout assumptions. Returns NTSTATUS. --*/
{
    ULONG offsets[KSWORD_ARK_MUTATION_PROCESS_PROTECTION_MAX_BYTES] = { 0UL };
    ULONG index = 0UL;
    NTSTATUS status = STATUS_SUCCESS;
    if (ProcessObject == NULL || DynState == NULL || Buffer == NULL || Bytes == 0UL || Bytes > KSWORD_ARK_MUTATION_PROCESS_PROTECTION_MAX_BYTES) {
        return STATUS_INVALID_PARAMETER;
    }
    offsets[0] = DynState->Kernel.EpProtection;
    offsets[1] = DynState->Kernel.EpSignatureLevel;
    offsets[2] = DynState->Kernel.EpSectionSignatureLevel;
    __try {
        for (index = 0UL; index < Bytes; index += 1UL) {
            if (!KswordARKMutationOffsetPresent(offsets[index])) {
                status = STATUS_PROCEDURE_NOT_FOUND;
                break;
            }
            RtlCopyMemory(&Buffer[index], (PUCHAR)ProcessObject + offsets[index], sizeof(Buffer[index]));
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();
    }
    return status;
}

static NTSTATUS
KswordARKMutationWritePplBytes(_In_ PEPROCESS ProcessObject, _In_ const KSW_DYN_STATE* DynState, _In_reads_bytes_(Bytes) const UCHAR* ExpectedBytes, _In_reads_bytes_(Bytes) const UCHAR* Buffer, _In_ ULONG Bytes)
/*++ Routine Description:
     Inputs are EPROCESS, DynData, expected/source bytes, and count. Processing
     validates every DynData offset, compares each byte immediately before its
     individual write, verifies the full result, and best-effort compensates
     already-written fields after any partial failure. Multi-byte PPL updates are
     explicitly not atomic. Returns STATUS_PARTIAL_COPY whenever a write began
     but the requested final state was not fully verified. --*/
{
    ULONG offsets[KSWORD_ARK_MUTATION_PROCESS_PROTECTION_MAX_BYTES] = { 0UL };
    UCHAR current[KSWORD_ARK_MUTATION_PROCESS_PROTECTION_MAX_BYTES] = { 0U };
    UCHAR verify[KSWORD_ARK_MUTATION_PROCESS_PROTECTION_MAX_BYTES] = { 0U };
    ULONG index = 0UL;
    ULONG written = 0UL;
    NTSTATUS status = STATUS_SUCCESS;
    if (ProcessObject == NULL ||
        DynState == NULL ||
        ExpectedBytes == NULL ||
        Buffer == NULL ||
        Bytes == 0UL ||
        Bytes > KSWORD_ARK_MUTATION_PROCESS_PROTECTION_MAX_BYTES) {
        return STATUS_INVALID_PARAMETER;
    }
    offsets[0] = DynState->Kernel.EpProtection;
    offsets[1] = DynState->Kernel.EpSignatureLevel;
    offsets[2] = DynState->Kernel.EpSectionSignatureLevel;
    for (index = 0UL; index < Bytes; index += 1UL) {
        if (!KswordARKMutationOffsetPresent(offsets[index])) {
            return STATUS_PROCEDURE_NOT_FOUND;
        }
    }
    __try {
        /*
         * Snapshot all logical fields first, then repeat an individual compare
         * immediately before each byte write to narrow the concurrent-change
         * window without claiming a multi-byte atomic operation.
         */
        for (index = 0UL; index < Bytes; index += 1UL) {
            RtlCopyMemory(
                &current[index],
                (PUCHAR)ProcessObject + offsets[index],
                sizeof(current[index]));
        }
        if (RtlCompareMemory(
                current,
                ExpectedBytes,
                Bytes) != Bytes) {
            status = STATUS_REVISION_MISMATCH;
        }
        for (index = 0UL;
             NT_SUCCESS(status) && index < Bytes;
             index += 1UL) {
            UCHAR beforeWrite = 0U;
            RtlCopyMemory(
                &beforeWrite,
                (PUCHAR)ProcessObject + offsets[index],
                sizeof(beforeWrite));
            if (beforeWrite != ExpectedBytes[index]) {
                status = STATUS_REVISION_MISMATCH;
                break;
            }
            RtlCopyMemory(
                (PUCHAR)ProcessObject + offsets[index],
                &Buffer[index],
                sizeof(Buffer[index]));
            written = index + 1UL;
        }
        if (NT_SUCCESS(status)) {
            for (index = 0UL; index < Bytes; index += 1UL) {
                RtlCopyMemory(
                    &verify[index],
                    (PUCHAR)ProcessObject + offsets[index],
                    sizeof(verify[index]));
                if (verify[index] != Buffer[index]) {
                    status = STATUS_UNSUCCESSFUL;
                    break;
                }
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();
    }

    if (!NT_SUCCESS(status) && written != 0UL) {
        /*
         * Restore only bytes that still equal this transaction's requested
         * value. A third-party value is never overwritten during compensation.
         * A full reread follows even when one compensation step faults.
         */
        __try {
            for (index = 0UL; index < written; index += 1UL) {
                UCHAR observed = 0U;
                RtlCopyMemory(
                    &observed,
                    (PUCHAR)ProcessObject + offsets[index],
                    sizeof(observed));
                if (observed == Buffer[index]) {
                    RtlCopyMemory(
                        (PUCHAR)ProcessObject + offsets[index],
                        &ExpectedBytes[index],
                        sizeof(ExpectedBytes[index]));
                }
            }
            RtlZeroMemory(verify, sizeof(verify));
            for (index = 0UL; index < Bytes; index += 1UL) {
                RtlCopyMemory(
                    &verify[index],
                    (PUCHAR)ProcessObject + offsets[index],
                    sizeof(verify[index]));
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            RtlZeroMemory(verify, sizeof(verify));
        }
        return STATUS_PARTIAL_COPY;
    }
    return status;
}

static NTSTATUS
KswordARKMutationGetPplTarget(_In_ ULONG ProcessId, _In_ ULONG Bytes, _In_ ULONGLONG ExpectedAddress, _Out_ ULONGLONG* TargetAddressOut, _Out_ ULONGLONG* TargetContextOut, _Out_writes_bytes_(Bytes) UCHAR* CurrentBytesOut)
/*++ Routine Description:
     Inputs are PID, byte count, optional address, and outputs. Processing checks
     DynData capability, resolves EPROCESS, requires optional address to equal
     EPROCESS+EpProtection, and reads the snapshot. Returns NTSTATUS. --*/
{
    KSW_DYN_STATE dynState;
    PEPROCESS processObject = NULL;
    ULONGLONG processAddress = 0ULL;
    ULONGLONG protectionAddress = 0ULL;
    NTSTATUS status = STATUS_SUCCESS;
    if (ProcessId == 0UL || Bytes == 0UL || Bytes > KSWORD_ARK_MUTATION_PROCESS_PROTECTION_MAX_BYTES || TargetAddressOut == NULL || TargetContextOut == NULL || CurrentBytesOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    RtlZeroMemory(&dynState, sizeof(dynState));
    KswordARKDynDataSnapshot(&dynState);
    if ((dynState.CapabilityMask & KSW_CAP_PROCESS_PROTECTION_PATCH) != KSW_CAP_PROCESS_PROTECTION_PATCH) {
        return STATUS_NOT_SUPPORTED;
    }
    if (!KswordARKMutationOffsetPresent(dynState.Kernel.EpProtection) || !KswordARKMutationOffsetPresent(dynState.Kernel.EpSignatureLevel) || !KswordARKMutationOffsetPresent(dynState.Kernel.EpSectionSignatureLevel)) {
        return STATUS_PROCEDURE_NOT_FOUND;
    }
    status = PsLookupProcessByProcessId(ULongToHandle(ProcessId), &processObject);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    processAddress = (ULONGLONG)(ULONG_PTR)processObject;
    protectionAddress = processAddress + (ULONGLONG)dynState.Kernel.EpProtection;
    if (ExpectedAddress != 0ULL && ExpectedAddress != protectionAddress) {
        status = STATUS_INVALID_PARAMETER;
    }
    else {
        status = KswordARKMutationReadPplBytes(processObject, &dynState, CurrentBytesOut, Bytes);
    }
    if (NT_SUCCESS(status)) {
        *TargetAddressOut = protectionAddress;
        *TargetContextOut = processAddress;
    }
    ObDereferenceObject(processObject);
    return status;
}

static NTSTATUS
KswordARKMutationReadPplForSlot(_In_ const KSWORD_ARK_MUTATION_SLOT* Slot, _Out_writes_bytes_(Slot->Bytes) UCHAR* CurrentBytesOut)
/*++ Routine Description:
     Inputs are a slot and output buffer. Processing re-resolves PID, refreshes
     DynData, rejects PID reuse by EPROCESS/address mismatch, then reads bytes.
     Returns NTSTATUS. --*/
{
    KSW_DYN_STATE dynState;
    PEPROCESS processObject = NULL;
    ULONGLONG processAddress = 0ULL;
    ULONGLONG protectionAddress = 0ULL;
    NTSTATUS status = STATUS_SUCCESS;
    if (Slot == NULL || CurrentBytesOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    RtlZeroMemory(&dynState, sizeof(dynState));
    KswordARKDynDataSnapshot(&dynState);
    if ((dynState.CapabilityMask & KSW_CAP_PROCESS_PROTECTION_PATCH) != KSW_CAP_PROCESS_PROTECTION_PATCH) {
        return STATUS_NOT_SUPPORTED;
    }
    if (!KswordARKMutationOffsetPresent(dynState.Kernel.EpProtection) || !KswordARKMutationOffsetPresent(dynState.Kernel.EpSignatureLevel) || !KswordARKMutationOffsetPresent(dynState.Kernel.EpSectionSignatureLevel)) {
        return STATUS_PROCEDURE_NOT_FOUND;
    }
    status = PsLookupProcessByProcessId(ULongToHandle(Slot->ProcessId), &processObject);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    processAddress = (ULONGLONG)(ULONG_PTR)processObject;
    protectionAddress = processAddress + (ULONGLONG)dynState.Kernel.EpProtection;
    if (processObject != Slot->TargetProcessObject ||
        processAddress != Slot->TargetContext ||
        protectionAddress != Slot->TargetAddress) {
        status = STATUS_REVISION_MISMATCH;
    }
    else {
        status = KswordARKMutationReadPplBytes(processObject, &dynState, CurrentBytesOut, Slot->Bytes);
    }
    ObDereferenceObject(processObject);
    return status;
}

static NTSTATUS
KswordARKMutationWritePplForSlot(_In_ const KSWORD_ARK_MUTATION_SLOT* Slot, _In_reads_bytes_(Slot->Bytes) const UCHAR* ExpectedBytes, _In_reads_bytes_(Slot->Bytes) const UCHAR* Bytes)
/*++ Routine Description:
     Inputs are a slot and source bytes. Processing revalidates PID, DynData, and
     target address before writing PPL fields. Returns guarded write status. --*/
{
    KSW_DYN_STATE dynState;
    PEPROCESS processObject = NULL;
    ULONGLONG processAddress = 0ULL;
    ULONGLONG protectionAddress = 0ULL;
    NTSTATUS status = STATUS_SUCCESS;
    if (Slot == NULL ||
        ExpectedBytes == NULL ||
        Bytes == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    RtlZeroMemory(&dynState, sizeof(dynState));
    KswordARKDynDataSnapshot(&dynState);
    if ((dynState.CapabilityMask & KSW_CAP_PROCESS_PROTECTION_PATCH) != KSW_CAP_PROCESS_PROTECTION_PATCH) {
        return STATUS_NOT_SUPPORTED;
    }
    if (!KswordARKMutationOffsetPresent(dynState.Kernel.EpProtection) || !KswordARKMutationOffsetPresent(dynState.Kernel.EpSignatureLevel) || !KswordARKMutationOffsetPresent(dynState.Kernel.EpSectionSignatureLevel)) {
        return STATUS_PROCEDURE_NOT_FOUND;
    }
    status = PsLookupProcessByProcessId(ULongToHandle(Slot->ProcessId), &processObject);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    processAddress = (ULONGLONG)(ULONG_PTR)processObject;
    protectionAddress = processAddress + (ULONGLONG)dynState.Kernel.EpProtection;
    if (processObject != Slot->TargetProcessObject ||
        processAddress != Slot->TargetContext ||
        protectionAddress != Slot->TargetAddress) {
        status = STATUS_REVISION_MISMATCH;
    }
    else {
        status = KswordARKMutationWritePplBytes(
            processObject,
            &dynState,
            ExpectedBytes,
            Bytes,
            Slot->Bytes);
    }
    ObDereferenceObject(processObject);
    return status;
}

static NTSTATUS
KswordARKMutationReadSlotBytes(_In_ const KSWORD_ARK_MUTATION_SLOT* Slot, _Out_writes_bytes_(Slot->Bytes) UCHAR* CurrentBytesOut)
/*++ Routine Description:
     Inputs are prepared slot and output buffer. Processing dispatches to PPL or
     kernel snapshot readers. Returns target-specific read status. --*/
{
    if (Slot == NULL || CurrentBytesOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    if (Slot->TargetKind == KSWORD_ARK_MUTATION_TARGET_PROCESS_PROTECTION_BYTES) {
        return KswordARKMutationReadPplForSlot(Slot, CurrentBytesOut);
    }
    if (Slot->TargetKind == KSWORD_ARK_MUTATION_TARGET_KERNEL_VIRTUAL_BYTES_SMALL || Slot->TargetKind == KSWORD_ARK_MUTATION_TARGET_CALLBACK_ENTRY_UNLINK_PLAN) {
        return KswordARKMutationReadKernelBytes(Slot->TargetAddress, CurrentBytesOut, Slot->Bytes);
    }
    return STATUS_INVALID_PARAMETER;
}

static NTSTATUS
KswordARKMutationWriteSlotBytes(
    _In_ const KSWORD_ARK_MUTATION_SLOT* Slot,
    _In_reads_bytes_(Slot->Bytes) const UCHAR* ExpectedBytes,
    _In_reads_bytes_(Slot->Bytes) const UCHAR* Bytes)
/*++ Routine Description:
     Inputs are prepared slot and source bytes. Processing writes only supported
     guarded target kinds; all others fail closed. Returns NTSTATUS. --*/
{
    if (Slot == NULL || ExpectedBytes == NULL || Bytes == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    if (Slot->TargetKind == KSWORD_ARK_MUTATION_TARGET_PROCESS_PROTECTION_BYTES) {
        return KswordARKMutationWritePplForSlot(
            Slot,
            ExpectedBytes,
            Bytes);
    }
    if (Slot->TargetKind == KSWORD_ARK_MUTATION_TARGET_KERNEL_VIRTUAL_BYTES_SMALL) {
        return KswordARKMutationWriteKernelBytes(
            Slot->TargetAddress,
            ExpectedBytes,
            Bytes,
            Slot->Bytes);
    }
    return STATUS_NOT_SUPPORTED;
}

static ULONG
KswordARKMutationTargetRisk(_In_ ULONG TargetKind)
/*++ Routine Description:
     Input is target kind; maps it to stable audit risk flags. Returns bitmask. --*/
{
    if (TargetKind == KSWORD_ARK_MUTATION_TARGET_KERNEL_VIRTUAL_BYTES_SMALL) {
        return KSWORD_ARK_MUTATION_RISK_KERNEL_PATCH_SURFACE |
            KSWORD_ARK_MUTATION_RISK_CANONICAL_REQUIRED |
            KSWORD_ARK_MUTATION_RISK_SIZE_LIMITED |
            KSWORD_ARK_MUTATION_RISK_WRITABLE_MDL_ALIAS |
            KSWORD_ARK_MUTATION_RISK_EXECUTABLE_BYTES_MAY_BE_LIVE |
            KSWORD_ARK_MUTATION_RISK_WRITE_VERIFY_REQUIRED;
    }
    if (TargetKind == KSWORD_ARK_MUTATION_TARGET_PROCESS_PROTECTION_BYTES) {
        return KSWORD_ARK_MUTATION_RISK_PROCESS_PROTECTION_SURFACE | KSWORD_ARK_MUTATION_RISK_DYNDATA_REQUIRED | KSWORD_ARK_MUTATION_RISK_DYNDATA_CONFIRMED | KSWORD_ARK_MUTATION_RISK_SIZE_LIMITED;
    }
    if (TargetKind == KSWORD_ARK_MUTATION_TARGET_CALLBACK_ENTRY_UNLINK_PLAN) {
        return KSWORD_ARK_MUTATION_RISK_CALLBACK_UNLINK_SURFACE | KSWORD_ARK_MUTATION_RISK_PLAN_ONLY | KSWORD_ARK_MUTATION_RISK_WRITE_BLOCKED_BY_DESIGN | KSWORD_ARK_MUTATION_RISK_SIZE_LIMITED;
    }
    return KSWORD_ARK_MUTATION_RISK_NONE;
}

static ULONG
KswordARKMutationSafetyOp(_In_ ULONG TargetKind)
/*++ Routine Description:
     Input is target kind; maps it to central safety operation id. Returns id. --*/
{
    if (TargetKind == KSWORD_ARK_MUTATION_TARGET_KERNEL_VIRTUAL_BYTES_SMALL) {
        return KSWORD_ARK_SAFETY_OPERATION_KERNEL_PATCH;
    }
    if (TargetKind == KSWORD_ARK_MUTATION_TARGET_PROCESS_PROTECTION_BYTES) {
        return KSWORD_ARK_SAFETY_OPERATION_PROCESS_SET_PROTECTION;
    }
    if (TargetKind == KSWORD_ARK_MUTATION_TARGET_CALLBACK_ENTRY_UNLINK_PLAN) {
        return KSWORD_ARK_SAFETY_OPERATION_CALLBACK_REMOVE_EXTERNAL;
    }
    return KSWORD_ARK_SAFETY_OPERATION_NONE;
}

static ULONG
KswordARKMutationFailureStatus(_In_ NTSTATUS Status, _In_ ULONG DefaultStatus)
/*++ Routine Description:
     Inputs are NTSTATUS and fallback status; maps known failures into shared
     mutation status codes. Returns shared status. --*/
{
    if (Status == STATUS_REVISION_MISMATCH) {
        return KSWORD_ARK_MUTATION_STATUS_REJECTED_TARGET_CHANGED;
    }
    if (Status == STATUS_NOT_SUPPORTED) {
        return KSWORD_ARK_MUTATION_STATUS_REJECTED_UNSUPPORTED_TARGET;
    }
    if (Status == STATUS_NOT_FOUND) {
        return KSWORD_ARK_MUTATION_STATUS_REJECTED_NOT_FOUND;
    }
    if (Status == STATUS_DEVICE_BUSY) {
        return KSWORD_ARK_MUTATION_STATUS_REJECTED_BUSY;
    }
    return DefaultStatus;
}

static VOID
KswordARKMutationFillResponse(_Out_ KSWORD_ARK_MUTATION_RESPONSE* Response, _In_ const KSWORD_ARK_MUTATION_SLOT* Slot, _In_ ULONG Status, _In_ NTSTATUS LastStatus, _In_ ULONG RiskFlags)
/*++ Routine Description:
     Inputs are response, slot, status, NTSTATUS, and risk flags. Processing copies
     bounded transaction metadata and snapshots. Return none. --*/
{
    RtlZeroMemory(Response, sizeof(*Response));
    Response->size = sizeof(*Response);
    Response->version = KSWORD_ARK_MUTATION_PROTOCOL_VERSION;
    Response->status = Status;
    Response->targetKind = Slot->TargetKind;
    Response->processId = Slot->ProcessId;
    Response->bytes = Slot->Bytes;
    Response->riskFlags = RiskFlags;
    Response->lastStatus = LastStatus;
    Response->transactionId = Slot->TransactionId;
    Response->targetAddress = Slot->TargetAddress;
    Response->targetContext = Slot->TargetContext;
    Response->beforeHash = Slot->BeforeHash;
    Response->afterHash = Slot->AfterHash;
    Response->timestampTick = Slot->TimestampTick;
    RtlCopyMemory(Response->beforeBytes, Slot->BeforeBytes, sizeof(Response->beforeBytes));
    RtlCopyMemory(Response->afterBytes, Slot->AfterBytes, sizeof(Response->afterBytes));
}

static VOID
KswordARKMutationAuditLocked(_In_ ULONG Operation, _In_ const KSWORD_ARK_MUTATION_SLOT* Slot, _In_ ULONG Status, _In_ NTSTATUS LastStatus, _In_ ULONG Flags, _In_ ULONG RiskFlags, _In_reads_bytes_opt_(Slot->Bytes) const UCHAR* ByteData)
/*++ Routine Description:
     Inputs are event metadata and optional bytes. Processing appends one entry to
     the audit ring while caller holds the write lock. Return none. --*/
{
    ULONGLONG sequence = g_KswordArkMutationState.NextAuditSequence;
    ULONG index = (ULONG)(sequence % KSWORD_ARK_MUTATION_AUDIT_RING_CAPACITY);
    KSWORD_ARK_MUTATION_AUDIT_ENTRY* entry = &g_KswordArkMutationState.Audit[index];
    g_KswordArkMutationState.NextAuditSequence += 1ULL;
    RtlZeroMemory(entry, sizeof(*entry));
    entry->size = sizeof(*entry);
    entry->version = KSWORD_ARK_MUTATION_PROTOCOL_VERSION;
    entry->operation = Operation;
    entry->status = Status;
    entry->lastStatus = LastStatus;
    entry->targetKind = Slot->TargetKind;
    entry->riskFlags = RiskFlags;
    entry->flags = Flags;
    entry->processId = Slot->ProcessId;
    entry->bytes = Slot->Bytes;
    entry->transactionId = Slot->TransactionId;
    entry->sequence = sequence;
    entry->targetAddress = Slot->TargetAddress;
    entry->targetContext = Slot->TargetContext;
    entry->beforeHash = Slot->BeforeHash;
    entry->afterHash = Slot->AfterHash;
    entry->timestampTick = KswordARKMutationTick();
    if (ByteData != NULL && Slot->Bytes <= KSWORD_ARK_MUTATION_MAX_BYTES) {
        RtlCopyMemory(entry->byteData, ByteData, Slot->Bytes);
    }
}

static KSWORD_ARK_MUTATION_SLOT*
KswordARKMutationFindSlotLocked(_In_ ULONGLONG TransactionId)
/*++ Routine Description:
     Input is transaction id; scans active slots under caller-held lock. Returns
     matching slot pointer or NULL. --*/
{
    ULONG index = 0UL;
    if (TransactionId == 0ULL) {
        return NULL;
    }
    for (index = 0UL; index < KSWORD_ARK_MUTATION_AUDIT_RING_CAPACITY; index += 1UL) {
        if (g_KswordArkMutationState.Slots[index].InUse && g_KswordArkMutationState.Slots[index].TransactionId == TransactionId) {
            return &g_KswordArkMutationState.Slots[index];
        }
    }
    return NULL;
}

static NTSTATUS
KswordARKMutationValidatePrepare(_In_ const KSWORD_ARK_MUTATION_PREPARE_REQUEST* Request, _Out_ ULONG* ProtocolStatusOut, _Out_ ULONG* RiskFlagsOut)
/*++ Routine Description:
     Inputs are PREPARE request and output status fields. Processing validates
     size, version, flags, target kind, and length limits. Returns NTSTATUS. --*/
{
    if (ProtocolStatusOut == NULL || RiskFlagsOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *ProtocolStatusOut = KSWORD_ARK_MUTATION_STATUS_REJECTED_INVALID_REQUEST;
    *RiskFlagsOut = KSWORD_ARK_MUTATION_RISK_NONE;
    if (Request == NULL || Request->size < sizeof(KSWORD_ARK_MUTATION_PREPARE_REQUEST) || Request->version != KSWORD_ARK_MUTATION_PROTOCOL_VERSION || Request->reserved != 0UL || Request->reserved2 != 0UL) {
        return STATUS_INVALID_PARAMETER;
    }
    if ((Request->flags & ~(KSWORD_ARK_MUTATION_FLAG_FORCE | KSWORD_ARK_MUTATION_FLAG_UI_CONFIRMED | KSWORD_ARK_MUTATION_FLAG_DRY_RUN | KSWORD_ARK_MUTATION_FLAG_EXPECTED_BEFORE_PRESENT)) != 0UL) {
        return STATUS_INVALID_PARAMETER;
    }
    if (Request->targetKind != KSWORD_ARK_MUTATION_TARGET_KERNEL_VIRTUAL_BYTES_SMALL && Request->targetKind != KSWORD_ARK_MUTATION_TARGET_PROCESS_PROTECTION_BYTES && Request->targetKind != KSWORD_ARK_MUTATION_TARGET_CALLBACK_ENTRY_UNLINK_PLAN) {
        *ProtocolStatusOut = KSWORD_ARK_MUTATION_STATUS_REJECTED_UNKNOWN_TARGET;
        return STATUS_INVALID_PARAMETER;
    }
    if (Request->bytes == 0UL || Request->bytes > KSWORD_ARK_MUTATION_MAX_BYTES) {
        *ProtocolStatusOut = KSWORD_ARK_MUTATION_STATUS_REJECTED_SIZE_LIMIT;
        return STATUS_INVALID_PARAMETER;
    }
    if (Request->targetKind == KSWORD_ARK_MUTATION_TARGET_PROCESS_PROTECTION_BYTES && Request->bytes > KSWORD_ARK_MUTATION_PROCESS_PROTECTION_MAX_BYTES) {
        *ProtocolStatusOut = KSWORD_ARK_MUTATION_STATUS_REJECTED_SIZE_LIMIT;
        return STATUS_INVALID_PARAMETER;
    }
    *ProtocolStatusOut = KSWORD_ARK_MUTATION_STATUS_PREPARED;
    *RiskFlagsOut = KSWORD_ARK_MUTATION_RISK_READ_SNAPSHOT_TAKEN | KswordARKMutationTargetRisk(Request->targetKind);
    return STATUS_SUCCESS;
}

static NTSTATUS
KswordARKMutationPrepareSnapshot(_In_ const KSWORD_ARK_MUTATION_PREPARE_REQUEST* Request, _Out_ ULONGLONG* TargetAddressOut, _Out_ ULONGLONG* TargetContextOut, _Out_writes_bytes_(Request->bytes) UCHAR* BeforeBytesOut, _Out_ ULONG* ProtocolStatusOut, _Inout_ ULONG* RiskFlagsInOut)
/*++ Routine Description:
     Inputs are request and outputs. Processing validates target-specific address
     rules, reads before bytes, and checks optional expected-before. Returns status. --*/
{
    NTSTATUS status = STATUS_SUCCESS;
    if (Request == NULL || TargetAddressOut == NULL || TargetContextOut == NULL || BeforeBytesOut == NULL || ProtocolStatusOut == NULL || RiskFlagsInOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *TargetAddressOut = Request->targetAddress;
    *TargetContextOut = Request->targetContext;
    if (Request->targetKind == KSWORD_ARK_MUTATION_TARGET_PROCESS_PROTECTION_BYTES) {
        status = KswordARKMutationGetPplTarget(Request->processId, Request->bytes, Request->targetAddress, TargetAddressOut, TargetContextOut, BeforeBytesOut);
    }
    else if (Request->targetKind == KSWORD_ARK_MUTATION_TARGET_KERNEL_VIRTUAL_BYTES_SMALL) {
        status = KswordARKMutationReadKernelBytes(Request->targetAddress, BeforeBytesOut, Request->bytes);
    }
    else if (Request->targetKind == KSWORD_ARK_MUTATION_TARGET_CALLBACK_ENTRY_UNLINK_PLAN) {
        *RiskFlagsInOut |= KSWORD_ARK_MUTATION_RISK_PLAN_ONLY;
        status = KswordARKMutationReadKernelBytes(Request->targetAddress, BeforeBytesOut, Request->bytes);
    }
    else {
        *ProtocolStatusOut = KSWORD_ARK_MUTATION_STATUS_REJECTED_UNKNOWN_TARGET;
        return STATUS_INVALID_PARAMETER;
    }
    if (!NT_SUCCESS(status)) {
        *ProtocolStatusOut = KswordARKMutationFailureStatus(status, KSWORD_ARK_MUTATION_STATUS_READ_FAILED);
        return status;
    }
    if ((Request->flags & KSWORD_ARK_MUTATION_FLAG_EXPECTED_BEFORE_PRESENT) != 0UL && RtlCompareMemory(BeforeBytesOut, Request->expectedBeforeBytes, Request->bytes) != Request->bytes) {
        *RiskFlagsInOut |= KSWORD_ARK_MUTATION_RISK_BEFORE_MISMATCH;
        *ProtocolStatusOut = KSWORD_ARK_MUTATION_STATUS_REJECTED_BEFORE_MISMATCH;
        return STATUS_REVISION_MISMATCH;
    }
    *ProtocolStatusOut = KSWORD_ARK_MUTATION_STATUS_PREPARED;
    return STATUS_SUCCESS;
}

NTSTATUS
KswordARKMutationPrepare(_In_opt_ WDFDEVICE Device, _In_ ULONG RequestorProcessId, _In_ PEPROCESS RequestorProcessObject, _In_ const KSWORD_ARK_MUTATION_PREPARE_REQUEST* Request, _Out_writes_bytes_(OutputBufferLength) PVOID OutputBuffer, _In_ size_t OutputBufferLength, _Out_ size_t* BytesWrittenOut)
/*++ Routine Description:
     Inputs are device, PREPARE request, output buffer, and length. Processing
     validates target, snapshots before bytes, assigns transactionId, and records
     audit without writing target memory. Returns NTSTATUS and response bytes. --*/
{
    KSWORD_ARK_MUTATION_RESPONSE* response = NULL;
    KSWORD_ARK_MUTATION_SLOT slot;
    KSWORD_ARK_MUTATION_SLOT* storedSlot = NULL;
    PEPROCESS targetProcessObject = NULL;
    ULONG protocolStatus = KSWORD_ARK_MUTATION_STATUS_UNKNOWN;
    ULONG riskFlags = KSWORD_ARK_MUTATION_RISK_NONE;
    ULONG index = 0UL;
    NTSTATUS status = STATUS_SUCCESS;
    KswordARKMutationEnsureInitialized();
    if (BytesWrittenOut == NULL ||
        OutputBuffer == NULL ||
        RequestorProcessId == 0UL ||
        RequestorProcessObject == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *BytesWrittenOut = 0U;
    if (OutputBufferLength < sizeof(KSWORD_ARK_MUTATION_RESPONSE)) {
        return STATUS_BUFFER_TOO_SMALL;
    }
    RtlZeroMemory(OutputBuffer, OutputBufferLength);
    response = (KSWORD_ARK_MUTATION_RESPONSE*)OutputBuffer;
    RtlZeroMemory(&slot, sizeof(slot));
    status = KswordARKMutationValidatePrepare(Request, &protocolStatus, &riskFlags);
    if (NT_SUCCESS(status)) {
        status = KswordARKMutationPrepareSnapshot(Request, &slot.TargetAddress, &slot.TargetContext, slot.BeforeBytes, &protocolStatus, &riskFlags);
    }
    slot.InUse = TRUE;
    slot.Flags = (Request != NULL) ? Request->flags : 0UL;
    slot.Status = protocolStatus;
    slot.TargetKind = (Request != NULL) ? Request->targetKind : KSWORD_ARK_MUTATION_TARGET_UNKNOWN;
    slot.OwnerProcessId = RequestorProcessId;
    slot.OwnerProcessObject = RequestorProcessObject;
    slot.ProcessId = (Request != NULL) ? Request->processId : 0UL;
    slot.Bytes = (Request != NULL && Request->bytes <= KSWORD_ARK_MUTATION_MAX_BYTES) ? Request->bytes : 0UL;
    slot.RiskFlags = riskFlags;
    slot.LastStatus = status;
    slot.TimestampTick = KswordARKMutationTick();
    if (Request != NULL && slot.Bytes != 0UL) {
        RtlCopyMemory(slot.AfterBytes, Request->afterBytes, slot.Bytes);
    }
    slot.BeforeHash = KswordARKMutationHash(slot.BeforeBytes, slot.Bytes);
    slot.AfterHash = KswordARKMutationHash(slot.AfterBytes, slot.Bytes);
    if (NT_SUCCESS(status)) {
        ExAcquirePushLockExclusive(&g_KswordArkMutationState.Lock);
        KswordARKMutationExpireSlotsLocked(
            KswordARKMutationTick());
        slot.TransactionId = g_KswordArkMutationState.NextTransactionId;
        g_KswordArkMutationState.NextTransactionId += 1ULL;
        if (g_KswordArkMutationState.NextTransactionId == 0ULL) {
            g_KswordArkMutationState.NextTransactionId = 1ULL;
        }
        index = (ULONG)(slot.TransactionId % KSWORD_ARK_MUTATION_AUDIT_RING_CAPACITY);
        /*
         * An active transaction is never replaced merely because the ring
         * wrapped. Expiration above creates reusable slots; if all 64 slots
         * are still live, PREPARE fails closed with BUSY.
         */
        {
            ULONG probe = 0UL;
            storedSlot = NULL;
            for (probe = 0UL;
                 probe < KSWORD_ARK_MUTATION_AUDIT_RING_CAPACITY;
                 probe += 1UL) {
                ULONG candidate =
                    (index + probe)
                    % KSWORD_ARK_MUTATION_AUDIT_RING_CAPACITY;
                if (!g_KswordArkMutationState.Slots[candidate].InUse) {
                    index = candidate;
                    storedSlot =
                        &g_KswordArkMutationState.Slots[candidate];
                    break;
                }
            }
        }
        if (storedSlot == NULL) {
            slot.TransactionId = 0ULL;
            slot.Status = KSWORD_ARK_MUTATION_STATUS_REJECTED_BUSY;
            slot.LastStatus = STATUS_DEVICE_BUSY;
            protocolStatus = slot.Status;
            status = slot.LastStatus;
            ExReleasePushLockExclusive(&g_KswordArkMutationState.Lock);
            KswordARKMutationFillResponse(
                response,
                &slot,
                protocolStatus,
                status,
                riskFlags);
            *BytesWrittenOut = sizeof(*response);
            return status;
        }
        if (slot.TargetKind ==
            KSWORD_ARK_MUTATION_TARGET_PROCESS_PROTECTION_BYTES) {
            status = PsLookupProcessByProcessId(
                ULongToHandle(slot.ProcessId),
                &targetProcessObject);
            if (!NT_SUCCESS(status) ||
                targetProcessObject == NULL ||
                (ULONGLONG)(ULONG_PTR)targetProcessObject !=
                    slot.TargetContext) {
                if (targetProcessObject != NULL) {
                    ObDereferenceObject(targetProcessObject);
                    targetProcessObject = NULL;
                }
                slot.TransactionId = 0ULL;
                slot.Status =
                    KSWORD_ARK_MUTATION_STATUS_REJECTED_TARGET_CHANGED;
                slot.LastStatus = NT_SUCCESS(status)
                    ? STATUS_REVISION_MISMATCH
                    : status;
                slot.RiskFlags |=
                    KSWORD_ARK_MUTATION_RISK_TARGET_CHANGED;
                protocolStatus = slot.Status;
                status = slot.LastStatus;
                ExReleasePushLockExclusive(
                    &g_KswordArkMutationState.Lock);
                KswordARKMutationFillResponse(
                    response,
                    &slot,
                    protocolStatus,
                    status,
                    slot.RiskFlags);
                *BytesWrittenOut = sizeof(*response);
                return status;
            }
            /*
             * PsLookupProcessByProcessId returned the reference that the
             * global slot will own. Keeping the object alive prevents the old
             * EPROCESS address from being recycled into a same-PID target.
             */
            slot.TargetProcessObject = targetProcessObject;
        }
        /*
         * Only the global slot owns this reference. Stack copies carry the
         * pointer solely for identity comparison and never release it.
         */
        KswordARKMutationClearSlotLocked(storedSlot);
        ObReferenceObject(RequestorProcessObject);
        *storedSlot = slot;
        KswordARKMutationAuditLocked(KSWORD_ARK_MUTATION_OPERATION_PREPARE, storedSlot, KSWORD_ARK_MUTATION_STATUS_PREPARED, STATUS_SUCCESS, Request->flags, storedSlot->RiskFlags, storedSlot->BeforeBytes);
        ExReleasePushLockExclusive(&g_KswordArkMutationState.Lock);
    }
    KswordARKMutationFillResponse(response, &slot, protocolStatus, status, riskFlags);
    *BytesWrittenOut = sizeof(*response);
    if (Device != NULL) {
        CHAR message[KSWORD_ARK_LOG_ENTRY_MAX_BYTES] = { 0 };
        if (NT_SUCCESS(RtlStringCbPrintfA(message, sizeof(message), "Mutation prepare: tx=%I64u kind=%lu target=0x%I64X bytes=%lu status=%lu last=0x%08X.", response->transactionId, (unsigned long)response->targetKind, response->targetAddress, (unsigned long)response->bytes, (unsigned long)response->status, (unsigned int)response->lastStatus))) {
            (VOID)KswordARKDriverEnqueueLogFrame(Device, NT_SUCCESS(status) ? "Info" : "Warn", message);
        }
    }
    return NT_SUCCESS(status) ? STATUS_SUCCESS : status;
}

static NTSTATUS
KswordARKMutationSafety(_In_opt_ WDFDEVICE Device, _In_ const KSWORD_ARK_MUTATION_SLOT* Slot, _In_ ULONG RequestFlags)
/*++ Routine Description:
     Inputs are optional device, transaction slot, and request flags. Processing
     maps target kind to safety policy and forwards the explicit UI_CONFIRMED
     bit independently of FORCE. Returns policy status. --*/
{
    KSWORD_ARK_SAFETY_CONTEXT context;
    ULONG operation = KSWORD_ARK_SAFETY_OPERATION_NONE;
    if (Slot == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    operation = KswordARKMutationSafetyOp(Slot->TargetKind);
    if (operation == KSWORD_ARK_SAFETY_OPERATION_NONE) {
        return STATUS_INVALID_PARAMETER;
    }
    RtlZeroMemory(&context, sizeof(context));
    context.Operation = operation;
    context.TargetProcessId = Slot->ProcessId;
    context.ContextFlags =
        ((RequestFlags & KSWORD_ARK_MUTATION_FLAG_UI_CONFIRMED) != 0UL)
        ? KSWORD_ARK_SAFETY_CONTEXT_FLAG_UI_CONFIRMED
        : 0UL;
    return KswordARKSafetyEvaluate(Device, &context);
}

static NTSTATUS
KswordARKMutationCommitRollback(_In_opt_ WDFDEVICE Device, _In_ ULONG RequestorProcessId, _In_ PEPROCESS RequestorProcessObject, _In_ const KSWORD_ARK_MUTATION_TRANSACTION_REQUEST* Request, _Out_writes_bytes_(OutputBufferLength) PVOID OutputBuffer, _In_ size_t OutputBufferLength, _Out_ size_t* BytesWrittenOut, _In_ BOOLEAN Rollback)
/*++ Routine Description:
     Inputs are device, transaction request, output buffer, and rollback selector.
     Processing loads PREPARE state by transactionId, dry-runs without FORCE,
     enforces before-match and safety policy with FORCE, performs supported writes,
     verifies, and appends audit. Returns response status. --*/
{
    KSWORD_ARK_MUTATION_RESPONSE* response = NULL;
    KSWORD_ARK_MUTATION_SLOT slot;
    KSWORD_ARK_MUTATION_SLOT* storedSlot = NULL;
    UCHAR current[KSWORD_ARK_MUTATION_MAX_BYTES] = { 0U };
    UCHAR verify[KSWORD_ARK_MUTATION_MAX_BYTES] = { 0U };
    const UCHAR* desired = NULL;
    ULONG eventCode = Rollback ? KSWORD_ARK_MUTATION_OPERATION_ROLLBACK : KSWORD_ARK_MUTATION_OPERATION_COMMIT;
    ULONG statusCode = KSWORD_ARK_MUTATION_STATUS_UNKNOWN;
    ULONG riskFlags = KSWORD_ARK_MUTATION_RISK_NONE;
    NTSTATUS status = STATUS_SUCCESS;
    NTSTATUS lastStatus = STATUS_SUCCESS;
    BOOLEAN operationClaimed = FALSE;
    BOOLEAN operationBusy = FALSE;
    BOOLEAN ownerMismatch = FALSE;
    BOOLEAN stateRejected = FALSE;
    BOOLEAN dryRun = FALSE;
    BOOLEAN writeAttemptStarted = FALSE;
    BOOLEAN rollbackCompletedWithoutWrite = FALSE;
    KswordARKMutationEnsureInitialized();
    if (BytesWrittenOut == NULL ||
        OutputBuffer == NULL ||
        RequestorProcessId == 0UL ||
        RequestorProcessObject == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *BytesWrittenOut = 0U;
    if (OutputBufferLength < sizeof(KSWORD_ARK_MUTATION_RESPONSE)) {
        return STATUS_BUFFER_TOO_SMALL;
    }
    if (Request == NULL || Request->size < sizeof(KSWORD_ARK_MUTATION_TRANSACTION_REQUEST) || Request->version != KSWORD_ARK_MUTATION_PROTOCOL_VERSION || Request->reserved != 0UL || Request->transactionId == 0ULL || ((Request->flags & ~(KSWORD_ARK_MUTATION_FLAG_FORCE | KSWORD_ARK_MUTATION_FLAG_UI_CONFIRMED | KSWORD_ARK_MUTATION_FLAG_DRY_RUN)) != 0UL)) {
        return STATUS_INVALID_PARAMETER;
    }
    dryRun =
        ((Request->flags & KSWORD_ARK_MUTATION_FLAG_DRY_RUN) != 0UL)
        ? TRUE
        : FALSE;
    RtlZeroMemory(OutputBuffer, OutputBufferLength);
    response = (KSWORD_ARK_MUTATION_RESPONSE*)OutputBuffer;
    RtlZeroMemory(&slot, sizeof(slot));
    ExAcquirePushLockExclusive(&g_KswordArkMutationState.Lock);
    KswordARKMutationExpireSlotsLocked(
        KswordARKMutationTick());
    storedSlot = KswordARKMutationFindSlotLocked(Request->transactionId);
    if (storedSlot != NULL) {
        if (storedSlot->OwnerProcessObject != RequestorProcessObject) {
            ownerMismatch = TRUE;
            KswordARKMutationAuditLocked(
                eventCode,
                storedSlot,
                KSWORD_ARK_MUTATION_STATUS_REJECTED_SAFETY_POLICY,
                STATUS_ACCESS_DENIED,
                Request->flags,
                storedSlot->RiskFlags |
                    KSWORD_ARK_MUTATION_RISK_POLICY_DENIED,
                NULL);
        }
        else if (storedSlot->OperationBusy) {
            slot = *storedSlot;
            operationBusy = TRUE;
        }
        else if (storedSlot->RollbackAttempted ||
                 (!Rollback && storedSlot->CommitAttempted) ||
                 (Rollback && !storedSlot->CommitAttempted)) {
            slot = *storedSlot;
            stateRejected = TRUE;
        }
        else {
            storedSlot->OperationBusy = TRUE;
            slot = *storedSlot;
            operationClaimed = TRUE;
        }
    }
    ExReleasePushLockExclusive(&g_KswordArkMutationState.Lock);
    if (storedSlot == NULL) {
        slot.TransactionId = Request->transactionId;
        KswordARKMutationFillResponse(response, &slot, KSWORD_ARK_MUTATION_STATUS_REJECTED_NOT_FOUND, STATUS_NOT_FOUND, KSWORD_ARK_MUTATION_RISK_NONE);
        *BytesWrittenOut = sizeof(*response);
        return STATUS_SUCCESS;
    }
    if (ownerMismatch) {
        RtlZeroMemory(&slot, sizeof(slot));
        slot.TransactionId = Request->transactionId;
        KswordARKMutationFillResponse(
            response,
            &slot,
            KSWORD_ARK_MUTATION_STATUS_REJECTED_SAFETY_POLICY,
            STATUS_ACCESS_DENIED,
            KSWORD_ARK_MUTATION_RISK_POLICY_DENIED);
        *BytesWrittenOut = sizeof(*response);
        return STATUS_SUCCESS;
    }
    if (operationBusy) {
        slot.Status = KSWORD_ARK_MUTATION_STATUS_REJECTED_BUSY;
        slot.LastStatus = STATUS_DEVICE_BUSY;
        slot.TimestampTick = KswordARKMutationTick();
        ExAcquirePushLockExclusive(&g_KswordArkMutationState.Lock);
        KswordARKMutationAuditLocked(
            eventCode,
            &slot,
            slot.Status,
            slot.LastStatus,
            Request->flags,
            slot.RiskFlags,
            NULL);
        ExReleasePushLockExclusive(&g_KswordArkMutationState.Lock);
        KswordARKMutationFillResponse(
            response,
            &slot,
            slot.Status,
            slot.LastStatus,
            slot.RiskFlags);
        *BytesWrittenOut = sizeof(*response);
        return STATUS_SUCCESS;
    }
    if (stateRejected) {
        const ULONG rejectedRisk =
            slot.RiskFlags |
            KSWORD_ARK_MUTATION_RISK_POLICY_DENIED;
        ExAcquirePushLockExclusive(
            &g_KswordArkMutationState.Lock);
        storedSlot = KswordARKMutationFindSlotLocked(
            Request->transactionId);
        if (storedSlot != NULL &&
            storedSlot->OwnerProcessObject == RequestorProcessObject) {
            KswordARKMutationAuditLocked(
                eventCode,
                storedSlot,
                KSWORD_ARK_MUTATION_STATUS_REJECTED_INVALID_REQUEST,
                STATUS_INVALID_DEVICE_STATE,
                Request->flags,
                rejectedRisk,
                NULL);
        }
        ExReleasePushLockExclusive(
            &g_KswordArkMutationState.Lock);
        KswordARKMutationFillResponse(
            response,
            &slot,
            KSWORD_ARK_MUTATION_STATUS_REJECTED_INVALID_REQUEST,
            STATUS_INVALID_DEVICE_STATE,
            rejectedRisk);
        *BytesWrittenOut = sizeof(*response);
        return STATUS_SUCCESS;
    }
    desired = Rollback ? slot.BeforeBytes : slot.AfterBytes;
    riskFlags = slot.RiskFlags;
    if (dryRun ||
        (Request->flags & KSWORD_ARK_MUTATION_FLAG_FORCE) == 0UL) {
        riskFlags |= KSWORD_ARK_MUTATION_RISK_DRY_RUN;
        if ((Request->flags &
             KSWORD_ARK_MUTATION_FLAG_FORCE) == 0UL) {
            riskFlags |=
                KSWORD_ARK_MUTATION_RISK_FORCE_REQUIRED;
        }
        statusCode = KSWORD_ARK_MUTATION_STATUS_DRY_RUN;
        lastStatus = STATUS_REQUEST_NOT_ACCEPTED;
    }
    else {
        riskFlags |= KSWORD_ARK_MUTATION_RISK_FORCE_USED | KSWORD_ARK_MUTATION_RISK_POLICY_REQUIRED;
        status = KswordARKMutationReadSlotBytes(&slot, current);
        if (!NT_SUCCESS(status)) {
            riskFlags |= (status == STATUS_REVISION_MISMATCH) ? KSWORD_ARK_MUTATION_RISK_TARGET_CHANGED : 0UL;
            statusCode = KswordARKMutationFailureStatus(status, KSWORD_ARK_MUTATION_STATUS_READ_FAILED);
            lastStatus = status;
        }
        else if (Rollback && RtlCompareMemory(current, slot.BeforeBytes, slot.Bytes) == slot.Bytes) {
            riskFlags |= KSWORD_ARK_MUTATION_RISK_ROLLBACK_IDEMPOTENT;
            statusCode = KSWORD_ARK_MUTATION_STATUS_ALREADY_AT_BEFORE;
            lastStatus = STATUS_SUCCESS;
            rollbackCompletedWithoutWrite = TRUE;
        }
        else if (Rollback && RtlCompareMemory(current, slot.AfterBytes, slot.Bytes) != slot.Bytes) {
            /*
             * Rollback is another expected-before conditional operation.  It is
             * not a multi-byte atomic CAS: a third party may have changed the
             * target after COMMIT, so restoring stale bytes would overwrite
             * evidence or live state that this transaction does not own.
             */
            riskFlags |= KSWORD_ARK_MUTATION_RISK_TARGET_CHANGED;
            statusCode = KSWORD_ARK_MUTATION_STATUS_REJECTED_TARGET_CHANGED;
            lastStatus = STATUS_REVISION_MISMATCH;
        }
        else if (!Rollback && RtlCompareMemory(current, slot.BeforeBytes, slot.Bytes) != slot.Bytes) {
            riskFlags |= KSWORD_ARK_MUTATION_RISK_BEFORE_MISMATCH;
            statusCode = KSWORD_ARK_MUTATION_STATUS_REJECTED_BEFORE_MISMATCH;
            lastStatus = STATUS_REVISION_MISMATCH;
        }
        else if (slot.TargetKind == KSWORD_ARK_MUTATION_TARGET_CALLBACK_ENTRY_UNLINK_PLAN) {
            riskFlags |= KSWORD_ARK_MUTATION_RISK_PLAN_ONLY | KSWORD_ARK_MUTATION_RISK_WRITE_BLOCKED_BY_DESIGN;
            statusCode = KSWORD_ARK_MUTATION_STATUS_REJECTED_PLAN_ONLY;
            lastStatus = STATUS_NOT_SUPPORTED;
        }
        else {
            status = KswordARKMutationSafety(Device, &slot, Request->flags);
            if (!NT_SUCCESS(status)) {
                riskFlags |= KSWORD_ARK_MUTATION_RISK_POLICY_DENIED;
                statusCode = KSWORD_ARK_MUTATION_STATUS_REJECTED_SAFETY_POLICY;
                lastStatus = status;
            }
            else {
                ExAcquirePushLockExclusive(
                    &g_KswordArkMutationState.Lock);
                storedSlot = KswordARKMutationFindSlotLocked(
                    Request->transactionId);
                if (storedSlot == NULL ||
                    storedSlot->OwnerProcessObject !=
                        RequestorProcessObject ||
                    !storedSlot->OperationBusy ||
                    (Rollback
                        ? storedSlot->RollbackAttempted
                        : storedSlot->CommitAttempted)) {
                    status = STATUS_INVALID_DEVICE_STATE;
                }
                else {
                    if (Rollback) {
                        storedSlot->RollbackAttempted = TRUE;
                        slot.RollbackAttempted = TRUE;
                    }
                    else {
                        storedSlot->CommitAttempted = TRUE;
                        slot.CommitAttempted = TRUE;
                    }
                    writeAttemptStarted = TRUE;
                }
                ExReleasePushLockExclusive(
                    &g_KswordArkMutationState.Lock);
                if (!writeAttemptStarted) {
                    statusCode =
                        KSWORD_ARK_MUTATION_STATUS_REJECTED_INVALID_REQUEST;
                    lastStatus = status;
                }
                else {
                    status = KswordARKMutationWriteSlotBytes(
                        &slot,
                        current,
                        desired);
                    if (!NT_SUCCESS(status)) {
                        if (status == STATUS_REVISION_MISMATCH) {
                            riskFlags |= KSWORD_ARK_MUTATION_RISK_TARGET_CHANGED;
                        }
                        statusCode = KswordARKMutationFailureStatus(status, KSWORD_ARK_MUTATION_STATUS_WRITE_FAILED);
                        lastStatus = status;
                    }
                    else {
                        status = KswordARKMutationReadSlotBytes(&slot, verify);
                        if (!NT_SUCCESS(status)) {
                            statusCode = KSWORD_ARK_MUTATION_STATUS_READ_FAILED;
                            lastStatus = status;
                        }
                        else if (RtlCompareMemory(verify, desired, slot.Bytes) != slot.Bytes) {
                            statusCode = KSWORD_ARK_MUTATION_STATUS_WRITE_FAILED;
                            lastStatus = STATUS_UNSUCCESSFUL;
                        }
                        else {
                            statusCode = Rollback ? KSWORD_ARK_MUTATION_STATUS_ROLLED_BACK : KSWORD_ARK_MUTATION_STATUS_COMMITTED;
                            lastStatus = STATUS_SUCCESS;
                        }
                    }
                }
            }
        }
    }
    slot.Status = statusCode;
    slot.RiskFlags = riskFlags;
    slot.LastStatus = lastStatus;
    slot.TimestampTick = KswordARKMutationTick();
    ExAcquirePushLockExclusive(&g_KswordArkMutationState.Lock);
    storedSlot = KswordARKMutationFindSlotLocked(Request->transactionId);
    if (storedSlot != NULL && operationClaimed) {
        storedSlot->Status = slot.Status;
        storedSlot->RiskFlags = slot.RiskFlags;
        storedSlot->LastStatus = slot.LastStatus;
        storedSlot->TimestampTick = slot.TimestampTick;
        if (rollbackCompletedWithoutWrite) {
            storedSlot->RollbackAttempted = TRUE;
        }
        if (!Rollback &&
            statusCode ==
                KSWORD_ARK_MUTATION_STATUS_COMMITTED) {
            storedSlot->CommitSucceeded = TRUE;
        }
        storedSlot->OperationBusy = FALSE;
        KswordARKMutationAuditLocked(eventCode, storedSlot, statusCode, lastStatus, Request->flags, riskFlags, desired);
    }
    ExReleasePushLockExclusive(&g_KswordArkMutationState.Lock);
    KswordARKMutationFillResponse(response, &slot, statusCode, lastStatus, riskFlags);
    *BytesWrittenOut = sizeof(*response);
    if (Device != NULL) {
        CHAR message[KSWORD_ARK_LOG_ENTRY_MAX_BYTES] = { 0 };
        if (NT_SUCCESS(RtlStringCbPrintfA(message, sizeof(message), "Mutation %s: tx=%I64u kind=%lu status=%lu last=0x%08X.", Rollback ? "rollback" : "commit", response->transactionId, (unsigned long)response->targetKind, (unsigned long)response->status, (unsigned int)response->lastStatus))) {
            (VOID)KswordARKDriverEnqueueLogFrame(Device, (response->status == KSWORD_ARK_MUTATION_STATUS_COMMITTED || response->status == KSWORD_ARK_MUTATION_STATUS_ROLLED_BACK || response->status == KSWORD_ARK_MUTATION_STATUS_ALREADY_AT_BEFORE) ? "Info" : "Warn", message);
        }
    }
    return STATUS_SUCCESS;
}

NTSTATUS
KswordARKMutationCommit(_In_opt_ WDFDEVICE Device, _In_ ULONG RequestorProcessId, _In_ PEPROCESS RequestorProcessObject, _In_ const KSWORD_ARK_MUTATION_TRANSACTION_REQUEST* Request, _Out_writes_bytes_(OutputBufferLength) PVOID OutputBuffer, _In_ size_t OutputBufferLength, _Out_ size_t* BytesWrittenOut)
/*++ Routine Description:
     Inputs are device, transaction request, and output buffer. Processing commits
     only by transactionId through shared commit/rollback logic. Returns NTSTATUS. --*/
{
    return KswordARKMutationCommitRollback(Device, RequestorProcessId, RequestorProcessObject, Request, OutputBuffer, OutputBufferLength, BytesWrittenOut, FALSE);
}

NTSTATUS
KswordARKMutationRollback(_In_opt_ WDFDEVICE Device, _In_ ULONG RequestorProcessId, _In_ PEPROCESS RequestorProcessObject, _In_ const KSWORD_ARK_MUTATION_TRANSACTION_REQUEST* Request, _Out_writes_bytes_(OutputBufferLength) PVOID OutputBuffer, _In_ size_t OutputBufferLength, _Out_ size_t* BytesWrittenOut)
/*++ Routine Description:
     Inputs are device, transaction request, and output buffer. Processing restores
     the before snapshot when needed and reports idempotent success if already
     restored. Returns NTSTATUS. --*/
{
    return KswordARKMutationCommitRollback(Device, RequestorProcessId, RequestorProcessObject, Request, OutputBuffer, OutputBufferLength, BytesWrittenOut, TRUE);
}

NTSTATUS
KswordARKMutationQueryAudit(_Out_writes_bytes_(OutputBufferLength) PVOID OutputBuffer, _In_ size_t OutputBufferLength, _In_opt_ const KSWORD_ARK_MUTATION_QUERY_AUDIT_REQUEST* Request, _Out_ size_t* BytesWrittenOut)
/*++ Routine Description:
     Inputs are output buffer, length, optional query request, and byte counter.
     Processing copies recent audit entries from the ring; byteData is redacted
     unless INCLUDE_BYTES is set. Returns NTSTATUS and response bytes. --*/
{
    KSWORD_ARK_MUTATION_QUERY_AUDIT_RESPONSE* response = NULL;
    ULONGLONG startSequence = 0ULL;
    ULONGLONG oldestSequence = 0ULL;
    ULONGLONG nextSequence = 0ULL;
    ULONGLONG sequence = 0ULL;
    ULONG capacity = 0UL;
    ULONG maxEntries = KSWORD_ARK_MUTATION_AUDIT_RING_CAPACITY;
    ULONG returned = 0UL;
    ULONG total = 0UL;
    ULONG lost = 0UL;
    BOOLEAN includeBytes = FALSE;
    KswordARKMutationEnsureInitialized();
    if (OutputBuffer == NULL || BytesWrittenOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *BytesWrittenOut = 0U;
    if (OutputBufferLength < KSWORD_ARK_MUTATION_AUDIT_RESPONSE_HEADER_SIZE) {
        return STATUS_BUFFER_TOO_SMALL;
    }
    if (Request != NULL) {
        if (Request->size < sizeof(KSWORD_ARK_MUTATION_QUERY_AUDIT_REQUEST) || Request->version != KSWORD_ARK_MUTATION_PROTOCOL_VERSION || ((Request->flags & ~KSWORD_ARK_MUTATION_QUERY_AUDIT_FLAG_INCLUDE_BYTES) != 0UL)) {
            return STATUS_INVALID_PARAMETER;
        }
        if (Request->maxEntries != 0UL && Request->maxEntries < maxEntries) {
            maxEntries = Request->maxEntries;
        }
        startSequence = Request->startSequence;
        includeBytes = ((Request->flags & KSWORD_ARK_MUTATION_QUERY_AUDIT_FLAG_INCLUDE_BYTES) != 0UL) ? TRUE : FALSE;
    }
    RtlZeroMemory(OutputBuffer, OutputBufferLength);
    response = (KSWORD_ARK_MUTATION_QUERY_AUDIT_RESPONSE*)OutputBuffer;
    response->size = KSWORD_ARK_MUTATION_AUDIT_RESPONSE_HEADER_SIZE;
    response->version = KSWORD_ARK_MUTATION_PROTOCOL_VERSION;
    response->entrySize = sizeof(KSWORD_ARK_MUTATION_AUDIT_ENTRY);
    capacity = (ULONG)((OutputBufferLength - KSWORD_ARK_MUTATION_AUDIT_RESPONSE_HEADER_SIZE) / sizeof(KSWORD_ARK_MUTATION_AUDIT_ENTRY));
    if (capacity < maxEntries) {
        maxEntries = capacity;
    }
    ExAcquirePushLockExclusive(&g_KswordArkMutationState.Lock);
    KswordARKMutationExpireSlotsLocked(
        KswordARKMutationTick());
    nextSequence = g_KswordArkMutationState.NextAuditSequence;
    oldestSequence = (nextSequence > KSWORD_ARK_MUTATION_AUDIT_RING_CAPACITY) ? (nextSequence - KSWORD_ARK_MUTATION_AUDIT_RING_CAPACITY) : 1ULL;
    if (startSequence == 0ULL || startSequence < oldestSequence) {
        if (startSequence != 0ULL && startSequence < oldestSequence) {
            lost = (ULONG)(oldestSequence - startSequence);
        }
        startSequence = oldestSequence;
    }
    if (nextSequence > oldestSequence) {
        total = (ULONG)(nextSequence - oldestSequence);
    }
    for (sequence = startSequence; sequence < nextSequence && returned < maxEntries; sequence += 1ULL) {
        ULONG auditIndex = (ULONG)(sequence % KSWORD_ARK_MUTATION_AUDIT_RING_CAPACITY);
        const KSWORD_ARK_MUTATION_AUDIT_ENTRY* source = &g_KswordArkMutationState.Audit[auditIndex];
        KSWORD_ARK_MUTATION_AUDIT_ENTRY* destination = &response->entries[returned];
        if (source->sequence != sequence) {
            continue;
        }
        RtlCopyMemory(destination, source, sizeof(*destination));
        if (!includeBytes) {
            RtlZeroMemory(destination->byteData, sizeof(destination->byteData));
        }
        returned += 1UL;
    }
    ExReleasePushLockExclusive(&g_KswordArkMutationState.Lock);
    response->totalCount = total;
    response->returnedCount = returned;
    response->lostCount = lost;
    response->oldestSequence = oldestSequence;
    response->nextSequence = nextSequence;
    *BytesWrittenOut = KSWORD_ARK_MUTATION_AUDIT_RESPONSE_HEADER_SIZE + ((size_t)returned * sizeof(KSWORD_ARK_MUTATION_AUDIT_ENTRY));
    return STATUS_SUCCESS;
}
