#include "controller.h"

/* Append one immutable operation record to the fixed nonpaged audit ring. */
VOID
KsccAuditAppend(
    _Inout_ KSCC_DEVICE_CONTEXT* Context,
    _In_ ULONGLONG SessionId,
    _In_ ULONGLONG Offset,
    _In_ ULONG Operation,
    _In_ ULONG Flags,
    _In_ ULONG RiskFlags,
    _In_ ULONG Length,
    _In_ ULONG BytesTransferred,
    _In_ ULONG Status,
    _In_ NTSTATUS LastStatus,
    _In_reads_(KSWORD_ARK_STORAGE_CONTROLLER_HASH_BYTES) const UCHAR* BeforeHash,
    _In_reads_(KSWORD_ARK_STORAGE_CONTROLLER_HASH_BYTES) const UCHAR* AfterHash)
{
    KIRQL irql;
    KSWORD_ARK_STORAGE_CONTROLLER_AUDIT_ROW* row;
    PACCESS_TOKEN token;
    PTOKEN_USER tokenUser;
    NTSTATUS tokenStatus;
    UCHAR actorSidHash[KSWORD_ARK_STORAGE_CONTROLLER_HASH_BYTES];
    UCHAR mediaIdentityHash[KSWORD_ARK_STORAGE_CONTROLLER_HASH_BYTES];
    UCHAR mediaIdentity[
        sizeof(Context->Model) +
        sizeof(Context->Serial)];

    /*
     * Bind the audit record to the caller without retaining a readable SID.
     * The token query runs before releasing the operation's process context.
     */
    token = PsReferencePrimaryToken(PsGetCurrentProcess());
    tokenUser = NULL;
    RtlZeroMemory(actorSidHash, sizeof(actorSidHash));
    tokenStatus = SeQueryInformationToken(
        token,
        TokenUser,
        (PVOID*)&tokenUser);
    if (NT_SUCCESS(tokenStatus) &&
        tokenUser != NULL &&
        RtlValidSid(tokenUser->User.Sid)) {
        KsccSha256(
            (const UCHAR*)tokenUser->User.Sid,
            RtlLengthSid(tokenUser->User.Sid),
            actorSidHash);
    }
    if (tokenUser != NULL) {
        ExFreePool(tokenUser);
    }
    PsDereferencePrimaryToken(token);

    /*
     * Bind the row to the identified device as well as its session.  Hashing
     * avoids exposing the complete serial in each audit row.
     */
    RtlCopyMemory(mediaIdentity, Context->Model, sizeof(Context->Model));
    RtlCopyMemory(
        mediaIdentity + sizeof(Context->Model),
        Context->Serial,
        sizeof(Context->Serial));
    KsccSha256(
        mediaIdentity,
        sizeof(mediaIdentity),
        mediaIdentityHash);
    RtlSecureZeroMemory(mediaIdentity, sizeof(mediaIdentity));

    /*
     * Only the fixed-size copy and ring-index update execute under the spin
     * lock; token queries and hashing above remain at the caller's PASSIVE IRQL.
     */
    KeAcquireSpinLock(&Context->Audit.Lock, &irql);
    row = &Context->Audit.Rows[Context->Audit.NextIndex];
    RtlZeroMemory(row, sizeof(*row));
    Context->Audit.Sequence += 1ULL;
    row->sequence = Context->Audit.Sequence;
    row->timestampTicks = KeQueryInterruptTime();
    row->sessionId = SessionId;
    row->offset = Offset;
    row->processId = HandleToULong(PsGetCurrentProcessId());
    row->operation = Operation;
    row->flags = Flags;
    row->riskFlags = RiskFlags;
    row->length = Length;
    row->bytesTransferred = BytesTransferred;
    row->status = Status;
    row->lastStatus = LastStatus;
    RtlCopyMemory(row->beforeHash, BeforeHash, sizeof(row->beforeHash));
    RtlCopyMemory(row->afterHash, AfterHash, sizeof(row->afterHash));
    RtlCopyMemory(row->actorSidHash, actorSidHash, sizeof(row->actorSidHash));
    RtlCopyMemory(
        row->mediaIdentityHash,
        mediaIdentityHash,
        sizeof(row->mediaIdentityHash));
    Context->Audit.NextIndex =
        (Context->Audit.NextIndex + 1U) %
        KSWORD_ARK_STORAGE_CONTROLLER_AUDIT_ROWS;
    if (Context->Audit.Count < KSWORD_ARK_STORAGE_CONTROLLER_AUDIT_ROWS) {
        Context->Audit.Count += 1U;
    }
    KeReleaseSpinLock(&Context->Audit.Lock, irql);
}
