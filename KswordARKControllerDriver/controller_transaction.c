#include "controller.h"

/* Compare two SHA-256 values without leaving early on the first difference. */
static BOOLEAN
KsccHashEqual(
    _In_reads_(KSWORD_ARK_STORAGE_CONTROLLER_HASH_BYTES) const UCHAR* Left,
    _In_reads_(KSWORD_ARK_STORAGE_CONTROLLER_HASH_BYTES) const UCHAR* Right)
{
    UCHAR difference;
    ULONG index;

    difference = 0U;
    for (index = 0U; index < KSWORD_ARK_STORAGE_CONTROLLER_HASH_BYTES; ++index) {
        difference |= Left[index] ^ Right[index];
    }
    return difference == 0U;
}

/* Map hardware and transaction failures into the stable protocol status set. */
static ULONG
KsccTransferProtocolStatus(
    _In_ NTSTATUS Status)
{
    if (NT_SUCCESS(Status)) {
        return KSWORD_ARK_STORAGE_CONTROLLER_STATUS_OK;
    }
    if (Status == STATUS_NOT_SUPPORTED) {
        return KSWORD_ARK_STORAGE_CONTROLLER_STATUS_NOT_SUPPORTED;
    }
    if (Status == STATUS_DEVICE_NOT_READY) {
        return KSWORD_ARK_STORAGE_CONTROLLER_STATUS_NOT_READY;
    }
    if (Status == STATUS_IO_TIMEOUT) {
        return KSWORD_ARK_STORAGE_CONTROLLER_STATUS_TIMEOUT;
    }
    if (Status == STATUS_DATATYPE_MISALIGNMENT) {
        return KSWORD_ARK_STORAGE_CONTROLLER_STATUS_ALIGNMENT_REQUIRED;
    }
    if (Status == STATUS_INVALID_BUFFER_SIZE) {
        return KSWORD_ARK_STORAGE_CONTROLLER_STATUS_BUFFER_TOO_SMALL;
    }
    if (Status == STATUS_REVISION_MISMATCH) {
        return KSWORD_ARK_STORAGE_CONTROLLER_STATUS_GENERATION_MISMATCH;
    }
    if (Status == STATUS_CONTEXT_MISMATCH) {
        return KSWORD_ARK_STORAGE_CONTROLLER_STATUS_SESSION_MISMATCH;
    }
    if (Status == STATUS_DATA_ERROR) {
        return KSWORD_ARK_STORAGE_CONTROLLER_STATUS_BEFORE_MISMATCH;
    }
    if (Status == STATUS_CRC_ERROR) {
        return KSWORD_ARK_STORAGE_CONTROLLER_STATUS_VERIFY_FAILED;
    }
    if (Status == STATUS_ACCESS_DENIED) {
        return KSWORD_ARK_STORAGE_CONTROLLER_STATUS_CONFIRMATION_REQUIRED;
    }
    if (Status == STATUS_INVALID_PARAMETER) {
        return KSWORD_ARK_STORAGE_CONTROLLER_STATUS_INVALID_REQUEST;
    }
    return KSWORD_ARK_STORAGE_CONTROLLER_STATUS_IO_FAILED;
}

/* Validate immutable session, generation, range, and alignment transaction keys. */
static NTSTATUS
KsccValidateTransfer(
    _In_ KSCC_DEVICE_CONTEXT* Context,
    _In_ const KSWORD_ARK_TRANSFER_STORAGE_CONTROLLER_REQUEST* Input)
{
    if (!Context->Prepared || !Context->Acquired || Context->RequiresReset) {
        return STATUS_DEVICE_NOT_READY;
    }
    if (Input->sessionId != Context->SessionId) {
        return STATUS_CONTEXT_MISMATCH;
    }
    if (Input->expectedGeneration != Context->Generation) {
        return STATUS_REVISION_MISMATCH;
    }
    if (Input->length == 0U ||
        Input->length > Context->MaximumTransferBytes ||
        Input->length > KSCC_BACKUP_BYTES) {
        return STATUS_INVALID_BUFFER_SIZE;
    }
    if (Input->operation == KSWORD_ARK_STORAGE_CONTROLLER_TRANSFER_WRITE &&
        (Input->flags &
         KSWORD_ARK_STORAGE_CONTROLLER_TRANSFER_FLAG_FUA) != 0U &&
        (Context->Capabilities &
         KSWORD_ARK_STORAGE_CONTROLLER_CAP_FUA) == 0U) {
        return STATUS_NOT_SUPPORTED;
    }
    if ((Input->offset % Context->LogicalSectorSize) != 0ULL ||
        (Input->length % Context->LogicalSectorSize) != 0U) {
        return STATUS_DATATYPE_MISALIGNMENT;
    }
    if (Input->offset >= Context->CapacityBytes ||
        Input->length > Context->CapacityBytes - Input->offset) {
        return STATUS_INVALID_PARAMETER;
    }
    return STATUS_SUCCESS;
}

/*
 * Process read/write/rollback as compare-before-write transactions.  Write
 * success requires a post-write reread and hash equality; the original bytes
 * remain available for one explicit rollback.
 */
VOID
KsccHandleTransfer(
    _In_ WDFREQUEST Request,
    _Inout_ KSCC_DEVICE_CONTEXT* Context)
{
    KSWORD_ARK_TRANSFER_STORAGE_CONTROLLER_REQUEST* input;
    KSWORD_ARK_TRANSFER_STORAGE_CONTROLLER_REQUEST inputCopy;
    KSWORD_ARK_TRANSFER_STORAGE_CONTROLLER_RESPONSE* output;
    size_t inputLength;
    size_t outputLength;
    size_t requiredInput;
    size_t requiredOutput;
    const UCHAR* writeData;
    UCHAR* work;
    UCHAR* stagedBefore;
    UCHAR beforeHash[KSWORD_ARK_STORAGE_CONTROLLER_HASH_BYTES];
    UCHAR desiredHash[KSWORD_ARK_STORAGE_CONTROLLER_HASH_BYTES];
    UCHAR afterHash[KSWORD_ARK_STORAGE_CONTROLLER_HASH_BYTES];
    ULONG controllerStatus;
    ULONG bytesTransferred;
    ULONG riskFlags;
    NTSTATUS status;
    BOOLEAN writeAttempted;

    status = WdfRequestRetrieveInputBuffer(
        Request,
        KSWORD_ARK_TRANSFER_STORAGE_CONTROLLER_REQUEST_HEADER_SIZE,
        (PVOID*)&input,
        &inputLength);
    if (!NT_SUCCESS(status)) {
        WdfRequestComplete(Request, status);
        return;
    }
    if (input->version != KSWORD_ARK_STORAGE_CONTROLLER_PROTOCOL_VERSION ||
        input->size < (ULONG)KSWORD_ARK_TRANSFER_STORAGE_CONTROLLER_REQUEST_HEADER_SIZE) {
        WdfRequestComplete(Request, STATUS_INVALID_PARAMETER);
        return;
    }
    if (input->operation < KSWORD_ARK_STORAGE_CONTROLLER_TRANSFER_READ ||
        input->operation > KSWORD_ARK_STORAGE_CONTROLLER_TRANSFER_ROLLBACK ||
        input->length == 0U ||
        input->length > KSWORD_ARK_STORAGE_CONTROLLER_MAX_TRANSFER_BYTES ||
        input->length > KSCC_BACKUP_BYTES) {
        WdfRequestComplete(Request, STATUS_INVALID_PARAMETER);
        return;
    }
    if ((input->flags & ~(
            KSWORD_ARK_STORAGE_CONTROLLER_TRANSFER_FLAG_FUA |
            KSWORD_ARK_STORAGE_CONTROLLER_TRANSFER_FLAG_FLUSH |
            KSWORD_ARK_STORAGE_CONTROLLER_TRANSFER_FLAG_VERIFY |
            KSWORD_ARK_STORAGE_CONTROLLER_TRANSFER_FLAG_FORCE |
            KSWORD_ARK_STORAGE_CONTROLLER_TRANSFER_FLAG_ALLOW_SYSTEM_DISK |
            KSWORD_ARK_STORAGE_CONTROLLER_TRANSFER_FLAG_UI_CONFIRMED |
            KSWORD_ARK_STORAGE_CONTROLLER_TRANSFER_FLAG_EXPECT_BEFORE_HASH)) != 0U ||
        input->timeoutMilliseconds > 60000U) {
        WdfRequestComplete(Request, STATUS_INVALID_PARAMETER);
        return;
    }
    if ((input->operation == KSWORD_ARK_STORAGE_CONTROLLER_TRANSFER_READ &&
         (input->flags != 0U || input->confirmationToken != 0U)) ||
        (input->operation == KSWORD_ARK_STORAGE_CONTROLLER_TRANSFER_WRITE &&
         (input->flags & KSWORD_ARK_STORAGE_CONTROLLER_TRANSFER_FLAG_FORCE) != 0U) ||
        (input->operation == KSWORD_ARK_STORAGE_CONTROLLER_TRANSFER_ROLLBACK &&
         (input->flags & (
             KSWORD_ARK_STORAGE_CONTROLLER_TRANSFER_FLAG_FUA |
             KSWORD_ARK_STORAGE_CONTROLLER_TRANSFER_FLAG_FORCE |
             KSWORD_ARK_STORAGE_CONTROLLER_TRANSFER_FLAG_EXPECT_BEFORE_HASH)) != 0U)) {
        WdfRequestComplete(Request, STATUS_INVALID_PARAMETER);
        return;
    }
    RtlZeroMemory(&inputCopy, sizeof(inputCopy));
    RtlCopyMemory(
        &inputCopy,
        input,
        KSWORD_ARK_TRANSFER_STORAGE_CONTROLLER_REQUEST_HEADER_SIZE);
    writeData = input->data;
    input = &inputCopy;
    if (input->operation == KSWORD_ARK_STORAGE_CONTROLLER_TRANSFER_WRITE) {
        /*
         * Every write is followed by an explicit cache flush even when a
         * caller omitted the advisory protocol flag.
         */
        input->flags |=
            KSWORD_ARK_STORAGE_CONTROLLER_TRANSFER_FLAG_FLUSH;
    }

    requiredInput = KSWORD_ARK_TRANSFER_STORAGE_CONTROLLER_REQUEST_HEADER_SIZE;
    if (input->operation == KSWORD_ARK_STORAGE_CONTROLLER_TRANSFER_WRITE) {
        requiredInput += input->length;
    }
    if (inputLength < requiredInput) {
        WdfRequestComplete(Request, STATUS_BUFFER_TOO_SMALL);
        return;
    }
    requiredOutput = KSWORD_ARK_TRANSFER_STORAGE_CONTROLLER_RESPONSE_HEADER_SIZE;
    if (input->operation == KSWORD_ARK_STORAGE_CONTROLLER_TRANSFER_READ) {
        requiredOutput += input->length;
    }
    status = WdfRequestRetrieveOutputBuffer(
        Request,
        requiredOutput,
        (PVOID*)&output,
        &outputLength);
    if (!NT_SUCCESS(status)) {
        WdfRequestComplete(Request, status);
        return;
    }

    work = ExAllocatePool2(POOL_FLAG_NON_PAGED, input->length, KSCC_POOL_TAG);
    if (work == NULL) {
        WdfRequestComplete(Request, STATUS_INSUFFICIENT_RESOURCES);
        return;
    }
    stagedBefore = NULL;
    if (input->operation == KSWORD_ARK_STORAGE_CONTROLLER_TRANSFER_WRITE) {
        stagedBefore = ExAllocatePool2(
            POOL_FLAG_NON_PAGED,
            input->length,
            KSCC_POOL_TAG);
        if (stagedBefore == NULL) {
            ExFreePoolWithTag(work, KSCC_POOL_TAG);
            WdfRequestComplete(Request, STATUS_INSUFFICIENT_RESOURCES);
            return;
        }
        RtlCopyMemory(work, writeData, input->length);
        KsccSha256(work, input->length, desiredHash);
    } else {
        RtlZeroMemory(desiredHash, sizeof(desiredHash));
    }

    WdfWaitLockAcquire(Context->IoLock, NULL);
    RtlZeroMemory(beforeHash, sizeof(beforeHash));
    RtlZeroMemory(afterHash, sizeof(afterHash));
    controllerStatus = 0U;
    bytesTransferred = 0U;
    riskFlags = Context->RiskFlags;
    writeAttempted = FALSE;
    status = KsccValidateTransfer(Context, input);
    if (!NT_SUCCESS(status)) {
        goto Complete;
    }

    if (input->operation != KSWORD_ARK_STORAGE_CONTROLLER_TRANSFER_READ) {
        riskFlags |= KSWORD_ARK_STORAGE_CONTROLLER_RISK_WRITE;
        if (input->confirmationToken !=
                KSWORD_ARK_STORAGE_CONTROLLER_CONFIRMATION_TOKEN ||
            (input->flags &
             KSWORD_ARK_STORAGE_CONTROLLER_TRANSFER_FLAG_UI_CONFIRMED) == 0U) {
            status = STATUS_ACCESS_DENIED;
            goto Complete;
        }
    }

    if (input->operation == KSWORD_ARK_STORAGE_CONTROLLER_TRANSFER_READ) {
        status = KsccHardwareTransfer(
            Context,
            FALSE,
            input->offset,
            work,
            input->length,
            input->flags,
            input->timeoutMilliseconds,
            &controllerStatus);
        if (NT_SUCCESS(status)) {
            bytesTransferred = input->length;
            KsccSha256(work, input->length, afterHash);
        }
    } else if (input->operation == KSWORD_ARK_STORAGE_CONTROLLER_TRANSFER_WRITE) {
        status = KsccHardwareTransfer(
            Context,
            FALSE,
            input->offset,
            stagedBefore,
            input->length,
            0U,
            input->timeoutMilliseconds,
            &controllerStatus);
        if (!NT_SUCCESS(status)) {
            goto Complete;
        }
        KsccSha256(stagedBefore, input->length, beforeHash);
        if ((input->flags &
             KSWORD_ARK_STORAGE_CONTROLLER_TRANSFER_FLAG_EXPECT_BEFORE_HASH) != 0U &&
            !KsccHashEqual(beforeHash, input->expectedBeforeHash)) {
            riskFlags |= KSWORD_ARK_STORAGE_CONTROLLER_RISK_BEFORE_MISMATCH;
            status = STATUS_DATA_ERROR;
            goto Complete;
        }

        /*
         * Replace any older recovery record before the first write command.
         * From this point onward every post-write failure retains only this
         * operation's original bytes and intended-after hash.
         */
        if (Context->RollbackValid &&
            Context->RollbackLength <= KSCC_BACKUP_BYTES) {
            RtlSecureZeroMemory(
                Context->Rollback,
                Context->RollbackLength);
        }
        RtlCopyMemory(Context->Rollback, stagedBefore, input->length);
        Context->RollbackLength = input->length;
        Context->RollbackOffset = input->offset;
        Context->RollbackSessionId = input->sessionId;
        RtlCopyMemory(
            Context->RollbackBeforeHash,
            beforeHash,
            sizeof(Context->RollbackBeforeHash));
        RtlCopyMemory(
            Context->RollbackAfterHash,
            desiredHash,
            sizeof(Context->RollbackAfterHash));
        Context->RollbackValid = TRUE;
        /*
         * Once the first media-write command is attempted, the prior
         * generation can no longer describe the observable device state.
         * Advance before dispatch so timeout and verification failures also
         * return a conservative generation.
         */
        Context->Generation += 1U;
        writeAttempted = TRUE;
        status = KsccHardwareTransfer(
            Context,
            TRUE,
            input->offset,
            work,
            input->length,
            input->flags,
            input->timeoutMilliseconds,
            &controllerStatus);
        if (!NT_SUCCESS(status)) {
            goto Complete;
        }
        /*
         * Every issued write must complete an explicit cache flush before
         * reread verification, including commands that also used FUA.
         */
        status = KsccHardwareFlush(
            Context,
            input->timeoutMilliseconds,
            &controllerStatus);
        if (!NT_SUCCESS(status)) {
            riskFlags |= KSWORD_ARK_STORAGE_CONTROLLER_RISK_VERIFY_FAILED;
            goto Complete;
        }
        status = KsccHardwareTransfer(
            Context,
            FALSE,
            input->offset,
            work,
            input->length,
            0U,
            input->timeoutMilliseconds,
            &controllerStatus);
        if (!NT_SUCCESS(status)) {
            riskFlags |= KSWORD_ARK_STORAGE_CONTROLLER_RISK_VERIFY_FAILED;
            goto Complete;
        }
        KsccSha256(work, input->length, afterHash);
        if (!KsccHashEqual(afterHash, desiredHash)) {
            riskFlags |= KSWORD_ARK_STORAGE_CONTROLLER_RISK_VERIFY_FAILED;
            RtlCopyMemory(
                Context->RollbackAfterHash,
                afterHash,
                sizeof(Context->RollbackAfterHash));
            status = STATUS_CRC_ERROR;
            goto Complete;
        }
        bytesTransferred = input->length;
    } else if (input->operation ==
               KSWORD_ARK_STORAGE_CONTROLLER_TRANSFER_ROLLBACK) {
        if (!Context->RollbackValid ||
            Context->RollbackSessionId != input->sessionId ||
            Context->RollbackOffset != input->offset ||
            Context->RollbackLength != input->length) {
            status = STATUS_NOT_FOUND;
            goto Complete;
        }
        status = KsccHardwareTransfer(
            Context,
            FALSE,
            input->offset,
            work,
            input->length,
            0U,
            input->timeoutMilliseconds,
            &controllerStatus);
        if (!NT_SUCCESS(status)) {
            goto Complete;
        }
        KsccSha256(work, input->length, beforeHash);
        if (!KsccHashEqual(beforeHash, Context->RollbackAfterHash)) {
            riskFlags |= KSWORD_ARK_STORAGE_CONTROLLER_RISK_BEFORE_MISMATCH;
            status = STATUS_DATA_ERROR;
            goto Complete;
        }
        Context->Generation += 1U;
        writeAttempted = TRUE;
        status = KsccHardwareTransfer(
            Context,
            TRUE,
            input->offset,
            Context->Rollback,
            input->length,
            input->flags,
            input->timeoutMilliseconds,
            &controllerStatus);
        if (!NT_SUCCESS(status)) {
            goto Complete;
        }
        status = KsccHardwareFlush(
            Context,
            input->timeoutMilliseconds,
            &controllerStatus);
        if (!NT_SUCCESS(status)) {
            riskFlags |= KSWORD_ARK_STORAGE_CONTROLLER_RISK_VERIFY_FAILED;
            goto Complete;
        }
        status = KsccHardwareTransfer(
            Context,
            FALSE,
            input->offset,
            work,
            input->length,
            0U,
            input->timeoutMilliseconds,
            &controllerStatus);
        if (!NT_SUCCESS(status)) {
            riskFlags |= KSWORD_ARK_STORAGE_CONTROLLER_RISK_VERIFY_FAILED;
            goto Complete;
        }
        KsccSha256(work, input->length, afterHash);
        if (!KsccHashEqual(afterHash, Context->RollbackBeforeHash)) {
            riskFlags |= KSWORD_ARK_STORAGE_CONTROLLER_RISK_VERIFY_FAILED;
            status = STATUS_CRC_ERROR;
            goto Complete;
        }
        Context->RollbackValid = FALSE;
        Context->RollbackSessionId = 0ULL;
        bytesTransferred = input->length;
    } else {
        status = STATUS_INVALID_PARAMETER;
    }

Complete:
    if (status == STATUS_IO_TIMEOUT) {
        riskFlags |= KSWORD_ARK_STORAGE_CONTROLLER_RISK_TIMEOUT;
    }
    if (writeAttempted && !NT_SUCCESS(status)) {
        /*
         * The recovery snapshot intentionally remains valid.  Persist the
         * uncertainty beyond this response so a later query cannot present a
         * clean controller after flush/reread/hash verification failed.
         */
        riskFlags |=
            KSWORD_ARK_STORAGE_CONTROLLER_RISK_WRITE |
            KSWORD_ARK_STORAGE_CONTROLLER_RISK_NO_RECOVERY_GUARANTEE;
        Context->RiskFlags |= riskFlags;
        Context->LastControllerStatus = controllerStatus;
        Context->LastStatus = status;
    }
    RtlZeroMemory(output, requiredOutput);
    output->version = KSWORD_ARK_STORAGE_CONTROLLER_PROTOCOL_VERSION;
    output->size = (ULONG)requiredOutput;
    output->status = status == STATUS_NOT_FOUND
        ? KSWORD_ARK_STORAGE_CONTROLLER_STATUS_RECOVERY_UNAVAILABLE
        : KsccTransferProtocolStatus(status);
    output->riskFlags = riskFlags;
    output->operation = input->operation;
    output->bytesTransferred = bytesTransferred;
    output->generation = Context->Generation;
    output->controllerStatus = controllerStatus;
    output->lastStatus = status;
    output->sessionId = Context->SessionId;
    output->offset = input->offset;
    RtlCopyMemory(output->beforeHash, beforeHash, sizeof(output->beforeHash));
    RtlCopyMemory(output->afterHash, afterHash, sizeof(output->afterHash));
    if (NT_SUCCESS(status) &&
        input->operation == KSWORD_ARK_STORAGE_CONTROLLER_TRANSFER_READ) {
        RtlCopyMemory(output->data, work, input->length);
    }
    KsccAuditAppend(
        Context,
        input->sessionId,
        input->offset,
        input->operation,
        input->flags,
        riskFlags,
        input->length,
        bytesTransferred,
        output->status,
        status,
        beforeHash,
        afterHash);
    WdfWaitLockRelease(Context->IoLock);
    if (stagedBefore != NULL) {
        RtlSecureZeroMemory(stagedBefore, input->length);
        ExFreePoolWithTag(stagedBefore, KSCC_POOL_TAG);
    }
    ExFreePoolWithTag(work, KSCC_POOL_TAG);
    WdfRequestCompleteWithInformation(Request, STATUS_SUCCESS, requiredOutput);
}
