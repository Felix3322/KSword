#include "controller.h"

/*
 * The IOCTL dispatcher only routes protocol operations.  All ownership,
 * transaction, hardware, and audit policy remains in the module handlers.
 */
VOID
KsccEvtIoDeviceControl(
    _In_ WDFQUEUE Queue,
    _In_ WDFREQUEST Request,
    _In_ size_t OutputBufferLength,
    _In_ size_t InputBufferLength,
    _In_ ULONG IoControlCode)
{
    KSCC_DEVICE_CONTEXT* context;

    UNREFERENCED_PARAMETER(OutputBufferLength);
    UNREFERENCED_PARAMETER(InputBufferLength);
    context = KsccGetContext(WdfIoQueueGetDevice(Queue));
    switch (IoControlCode) {
    case IOCTL_KSWORD_ARK_QUERY_STORAGE_CONTROLLER:
        KsccHandleQuery(Request, context);
        return;
    case IOCTL_KSWORD_ARK_CONTROL_STORAGE_CONTROLLER:
        KsccHandleControl(Request, context);
        return;
    case IOCTL_KSWORD_ARK_TRANSFER_STORAGE_CONTROLLER:
        KsccHandleTransfer(Request, context);
        return;
    case IOCTL_KSWORD_ARK_QUERY_STORAGE_CONTROLLER_AUDIT:
        KsccHandleAudit(Request, context);
        return;
    default:
        WdfRequestComplete(Request, STATUS_INVALID_DEVICE_REQUEST);
        return;
    }
}

/* Translate an NTSTATUS into the stable controller-protocol status domain. */
static ULONG
KsccProtocolStatus(
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
    if (Status == STATUS_DEVICE_BUSY) {
        return KSWORD_ARK_STORAGE_CONTROLLER_STATUS_BUSY;
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
    if (Status == STATUS_INVALID_PARAMETER) {
        return KSWORD_ARK_STORAGE_CONTROLLER_STATUS_INVALID_REQUEST;
    }
    return KSWORD_ARK_STORAGE_CONTROLLER_STATUS_IO_FAILED;
}

/* Return the current exclusive resource, queue, media, and risk state. */
VOID
KsccHandleQuery(
    _In_ WDFREQUEST Request,
    _In_ KSCC_DEVICE_CONTEXT* Context)
{
    KSWORD_ARK_QUERY_STORAGE_CONTROLLER_REQUEST* input;
    KSWORD_ARK_QUERY_STORAGE_CONTROLLER_RESPONSE* output;
    size_t inputLength;
    size_t outputLength;
    NTSTATUS status;

    status = WdfRequestRetrieveInputBuffer(
        Request,
        sizeof(*input),
        (PVOID*)&input,
        &inputLength);
    if (!NT_SUCCESS(status)) {
        WdfRequestComplete(Request, status);
        return;
    }
    status = WdfRequestRetrieveOutputBuffer(
        Request,
        sizeof(*output),
        (PVOID*)&output,
        &outputLength);
    if (!NT_SUCCESS(status)) {
        WdfRequestComplete(Request, status);
        return;
    }
    if (input->version != KSWORD_ARK_STORAGE_CONTROLLER_PROTOCOL_VERSION ||
        input->size < sizeof(*input) ||
        input->flags != 0U ||
        input->reserved != 0U) {
        WdfRequestComplete(Request, STATUS_INVALID_PARAMETER);
        return;
    }

    RtlZeroMemory(output, sizeof(*output));
    output->version = KSWORD_ARK_STORAGE_CONTROLLER_PROTOCOL_VERSION;
    output->size = sizeof(*output);
    output->status = Context->Prepared && !Context->RequiresReset
        ? KSWORD_ARK_STORAGE_CONTROLLER_STATUS_OK
        : KSWORD_ARK_STORAGE_CONTROLLER_STATUS_NOT_READY;
    output->controllerType = Context->ControllerType;
    output->capabilityFlags = Context->Capabilities;
    output->riskFlags = Context->RiskFlags;
    output->ownership = Context->Ownership;
    output->coherency = Context->Coherency;
    output->generation = Context->Generation;
    output->controllerIndex = KSWORD_ARK_STORAGE_CONTROLLER_INDEX_UNAVAILABLE;
    output->portOrNamespace = Context->PortOrNamespace;
    output->logicalSectorSize = Context->LogicalSectorSize;
    output->physicalSectorSize = Context->PhysicalSectorSize;
    output->maximumTransferBytes = Context->MaximumTransferBytes;
    output->pciSegment = Context->PciSegment;
    output->pciBus = Context->PciBus;
    output->pciDevice = Context->PciDevice;
    output->pciFunction = Context->PciFunction;
    output->lastControllerStatus = Context->LastControllerStatus;
    output->lastStatus = Context->LastStatus;
    output->capacityBytes = Context->CapacityBytes;
    output->activeSessionId = Context->SessionId;
    RtlCopyMemory(output->model, Context->Model, sizeof(output->model));
    RtlCopyMemory(output->serial, Context->Serial, sizeof(output->serial));
    RtlCopyMemory(output->detail, Context->Detail, sizeof(output->detail));
    if (Context->RequiresReset) {
        RtlStringCchCopyW(
            output->detail,
            KSWORD_ARK_STORAGE_CONTROLLER_DETAIL_CHARS,
            L"Controller timeout; queue state is unprovable and reset is required");
    }
    WdfRequestCompleteWithInformation(Request, STATUS_SUCCESS, sizeof(*output));
}

/* Handle exclusive session acquisition, release, and explicit controller reset. */
VOID
KsccHandleControl(
    _In_ WDFREQUEST Request,
    _Inout_ KSCC_DEVICE_CONTEXT* Context)
{
    KSWORD_ARK_CONTROL_STORAGE_CONTROLLER_REQUEST* input;
    KSWORD_ARK_CONTROL_STORAGE_CONTROLLER_REQUEST inputCopy;
    KSWORD_ARK_CONTROL_STORAGE_CONTROLLER_RESPONSE* output;
    size_t length;
    NTSTATUS status;
    NTSTATUS stopStatus;
    ULONG oldGeneration;

    status = WdfRequestRetrieveInputBuffer(
        Request,
        sizeof(*input),
        (PVOID*)&input,
        &length);
    if (!NT_SUCCESS(status)) {
        WdfRequestComplete(Request, status);
        return;
    }
    status = WdfRequestRetrieveOutputBuffer(
        Request,
        sizeof(*output),
        (PVOID*)&output,
        &length);
    if (!NT_SUCCESS(status)) {
        WdfRequestComplete(Request, status);
        return;
    }
    inputCopy = *input;
    input = &inputCopy;

    RtlZeroMemory(output, sizeof(*output));
    output->version = KSWORD_ARK_STORAGE_CONTROLLER_PROTOCOL_VERSION;
    output->size = sizeof(*output);
    if (input->version != KSWORD_ARK_STORAGE_CONTROLLER_PROTOCOL_VERSION ||
        input->size < sizeof(*input) ||
        input->reserved != 0U ||
        (input->flags & ~(
            KSWORD_ARK_STORAGE_CONTROLLER_CONTROL_FLAG_EXCLUSIVE |
            KSWORD_ARK_STORAGE_CONTROLLER_CONTROL_FLAG_FORCE_LIVE_UNSAFE |
            KSWORD_ARK_STORAGE_CONTROLLER_CONTROL_FLAG_ALLOW_SYSTEM_DISK |
            KSWORD_ARK_STORAGE_CONTROLLER_CONTROL_FLAG_UI_CONFIRMED)) != 0U ||
        input->timeoutMilliseconds > 60000U) {
        output->status = KSWORD_ARK_STORAGE_CONTROLLER_STATUS_INVALID_REQUEST;
        WdfRequestCompleteWithInformation(Request, STATUS_SUCCESS, sizeof(*output));
        return;
    }

    WdfWaitLockAcquire(Context->IoLock, NULL);
    oldGeneration = Context->Generation;
    status = STATUS_SUCCESS;
    if (!Context->Prepared &&
        !(input->command == KSWORD_ARK_STORAGE_CONTROLLER_CONTROL_RESET &&
          Context->ResourcesPrepared)) {
        status = STATUS_DEVICE_NOT_READY;
    } else if ((input->flags &
                KSWORD_ARK_STORAGE_CONTROLLER_CONTROL_FLAG_FORCE_LIVE_UNSAFE) != 0U &&
               (input->flags &
                KSWORD_ARK_STORAGE_CONTROLLER_CONTROL_FLAG_EXCLUSIVE) == 0U) {
        /*
         * A live shared controller cannot lawfully reach this function driver.
         * Report the research state without touching registers or fabricating
         * coherence.
         */
        output->riskFlags =
            KSWORD_ARK_STORAGE_CONTROLLER_RISK_SHARED_OWNER |
            KSWORD_ARK_STORAGE_CONTROLLER_RISK_COHERENCY_UNPROVABLE |
            KSWORD_ARK_STORAGE_CONTROLLER_RISK_NO_RECOVERY_GUARANTEE |
            KSWORD_ARK_STORAGE_CONTROLLER_RISK_FORCE_USED;
        output->ownership = KSWORD_ARK_STORAGE_OWNERSHIP_SHARED_UNSUPPORTED;
        output->coherency = KSWORD_ARK_STORAGE_COHERENCY_UNPROVABLE;
        status = STATUS_NOT_SUPPORTED;
    } else if (input->command == KSWORD_ARK_STORAGE_CONTROLLER_CONTROL_ACQUIRE) {
        if (Context->RequiresReset) {
            status = STATUS_DEVICE_NOT_READY;
        } else if (input->confirmationToken !=
                KSWORD_ARK_STORAGE_CONTROLLER_CONFIRMATION_TOKEN ||
            (input->flags &
             KSWORD_ARK_STORAGE_CONTROLLER_CONTROL_FLAG_UI_CONFIRMED) == 0U ||
            (input->flags &
             KSWORD_ARK_STORAGE_CONTROLLER_CONTROL_FLAG_EXCLUSIVE) == 0U) {
            output->status =
                KSWORD_ARK_STORAGE_CONTROLLER_STATUS_CONFIRMATION_REQUIRED;
            status = STATUS_ACCESS_DENIED;
        } else if (Context->Acquired) {
            status = STATUS_DEVICE_BUSY;
        } else if (input->expectedGeneration != Context->Generation) {
            status = STATUS_REVISION_MISMATCH;
        } else {
            LARGE_INTEGER counter;

            counter = KeQueryPerformanceCounter(NULL);
            Context->SessionId =
                ((ULONGLONG)counter.QuadPart ^
                 (ULONGLONG)(ULONG_PTR)Context ^
                 ((ULONGLONG)Context->Generation << 32U)) | 1ULL;
            Context->Acquired = TRUE;
            Context->Generation += 1U;
        }
    } else if (input->command == KSWORD_ARK_STORAGE_CONTROLLER_CONTROL_RELEASE) {
        if (!Context->Acquired ||
            input->expectedSessionId != Context->SessionId) {
            status = STATUS_CONTEXT_MISMATCH;
        } else if (input->expectedGeneration != Context->Generation) {
            status = STATUS_REVISION_MISMATCH;
        } else {
            if (Context->RollbackValid &&
                Context->RollbackLength <= KSCC_BACKUP_BYTES) {
                RtlSecureZeroMemory(
                    Context->Rollback,
                    Context->RollbackLength);
            }
            Context->RollbackValid = FALSE;
            Context->RollbackLength = 0U;
            Context->RollbackOffset = 0ULL;
            Context->RollbackSessionId = 0ULL;
            RtlZeroMemory(
                Context->RollbackBeforeHash,
                sizeof(Context->RollbackBeforeHash));
            RtlZeroMemory(
                Context->RollbackAfterHash,
                sizeof(Context->RollbackAfterHash));
            Context->Acquired = FALSE;
            Context->SessionId = 0ULL;
            Context->Generation += 1U;
        }
    } else if (input->command == KSWORD_ARK_STORAGE_CONTROLLER_CONTROL_RESET) {
        if (Context->ControllerType !=
            KSWORD_ARK_STORAGE_CONTROLLER_TYPE_NVME) {
            status = STATUS_NOT_SUPPORTED;
        } else if (input->expectedGeneration != Context->Generation) {
            status = STATUS_REVISION_MISMATCH;
        } else if ((Context->Acquired &&
             input->expectedSessionId != Context->SessionId) ||
            (!Context->Acquired &&
             (!Context->RequiresReset || input->expectedSessionId != 0ULL))) {
            status = STATUS_CONTEXT_MISMATCH;
        } else if (input->confirmationToken !=
                       KSWORD_ARK_STORAGE_CONTROLLER_CONFIRMATION_TOKEN ||
                   (input->flags &
                    KSWORD_ARK_STORAGE_CONTROLLER_CONTROL_FLAG_UI_CONFIRMED) == 0U) {
            output->status =
                KSWORD_ARK_STORAGE_CONTROLLER_STATUS_CONFIRMATION_REQUIRED;
            status = STATUS_ACCESS_DENIED;
        } else {
            Context->Prepared = FALSE;
            Context->Acquired = FALSE;
            Context->SessionId = 0ULL;
            Context->Generation += 1U;
            stopStatus = Context->HardwareActivated
                ? KsccStopController(Context)
                : STATUS_SUCCESS;
            if (!NT_SUCCESS(stopStatus)) {
                Context->RequiresReset = TRUE;
                Context->RiskFlags |=
                    KSWORD_ARK_STORAGE_CONTROLLER_RISK_CONTROLLER_RESET |
                    KSWORD_ARK_STORAGE_CONTROLLER_RISK_NO_RECOVERY_GUARANTEE;
                status = stopStatus;
            } else {
                if (Context->Rollback != NULL) {
                    RtlSecureZeroMemory(
                        Context->Rollback,
                        KSCC_BACKUP_BYTES);
                }
                Context->RollbackValid = FALSE;
                Context->RollbackLength = 0U;
                Context->RollbackOffset = 0ULL;
                Context->RollbackSessionId = 0ULL;
                RtlZeroMemory(
                    Context->RollbackBeforeHash,
                    sizeof(Context->RollbackBeforeHash));
                RtlZeroMemory(
                    Context->RollbackAfterHash,
                    sizeof(Context->RollbackAfterHash));
                KsccResetIdentity(Context);
                status = KsccDetectAndInitialize(Context);
                if (NT_SUCCESS(status)) {
                    Context->Prepared = TRUE;
                    Context->Ownership =
                        KSWORD_ARK_STORAGE_OWNERSHIP_EXCLUSIVE;
                    Context->Coherency =
                        KSWORD_ARK_STORAGE_COHERENCY_EXCLUSIVE;
                    Context->Capabilities |=
                        KSWORD_ARK_STORAGE_CONTROLLER_CAP_EXCLUSIVE |
                        KSWORD_ARK_STORAGE_CONTROLLER_CAP_AUDIT |
                        KSWORD_ARK_STORAGE_CONTROLLER_CAP_WRITE_VERIFY |
                        KSWORD_ARK_STORAGE_CONTROLLER_CAP_ROLLBACK;
                    Context->RiskFlags |=
                        KSWORD_ARK_STORAGE_CONTROLLER_RISK_CONTROLLER_RESET;
                } else {
                    if (Context->HardwareActivated) {
                        stopStatus = KsccStopController(Context);
                        if (!NT_SUCCESS(stopStatus)) {
                            status = stopStatus;
                        }
                    }
                    Context->Prepared = FALSE;
                    Context->RequiresReset = TRUE;
                    Context->RiskFlags |=
                        KSWORD_ARK_STORAGE_CONTROLLER_RISK_CONTROLLER_RESET |
                        KSWORD_ARK_STORAGE_CONTROLLER_RISK_NO_RECOVERY_GUARANTEE;
                }
            }
            output->riskFlags = Context->RiskFlags;
        }
    } else {
        status = STATUS_INVALID_PARAMETER;
    }

    if (output->status == 0U) {
        output->status = status == STATUS_ACCESS_DENIED
            ? KSWORD_ARK_STORAGE_CONTROLLER_STATUS_CONFIRMATION_REQUIRED
            : KsccProtocolStatus(status);
    }
    output->oldGeneration = oldGeneration;
    output->newGeneration = Context->Generation;
    output->ownership = output->ownership == 0U
        ? Context->Ownership
        : output->ownership;
    output->coherency = output->coherency == 0U
        ? Context->Coherency
        : output->coherency;
    output->lastStatus = status;
    output->sessionId = Context->SessionId;
    Context->LastStatus = status;
    WdfWaitLockRelease(Context->IoLock);
    WdfRequestCompleteWithInformation(Request, STATUS_SUCCESS, sizeof(*output));
}

/* Return a stable copy of ring-buffer audit rows newer than the given sequence. */
VOID
KsccHandleAudit(
    _In_ WDFREQUEST Request,
    _In_ KSCC_DEVICE_CONTEXT* Context)
{
    KSWORD_ARK_QUERY_STORAGE_CONTROLLER_AUDIT_REQUEST* input;
    KSWORD_ARK_QUERY_STORAGE_CONTROLLER_AUDIT_REQUEST inputCopy;
    KSWORD_ARK_QUERY_STORAGE_CONTROLLER_AUDIT_RESPONSE* output;
    size_t length;
    KIRQL irql;
    ULONG available;
    ULONG maximum;
    ULONG copied;
    ULONG logicalIndex;
    NTSTATUS status;

    status = WdfRequestRetrieveInputBuffer(
        Request,
        sizeof(*input),
        (PVOID*)&input,
        &length);
    if (!NT_SUCCESS(status)) {
        WdfRequestComplete(Request, status);
        return;
    }
    status = WdfRequestRetrieveOutputBuffer(
        Request,
        sizeof(*output),
        (PVOID*)&output,
        &length);
    if (!NT_SUCCESS(status)) {
        WdfRequestComplete(Request, status);
        return;
    }
    inputCopy = *input;
    input = &inputCopy;
    RtlZeroMemory(output, sizeof(*output));
    output->version = KSWORD_ARK_STORAGE_CONTROLLER_PROTOCOL_VERSION;
    output->size = sizeof(*output);
    if (input->version != KSWORD_ARK_STORAGE_CONTROLLER_PROTOCOL_VERSION ||
        input->size < sizeof(*input) ||
        input->reserved != 0U) {
        output->status = KSWORD_ARK_STORAGE_CONTROLLER_STATUS_INVALID_REQUEST;
        WdfRequestCompleteWithInformation(Request, STATUS_SUCCESS, sizeof(*output));
        return;
    }

    maximum = input->maximumRows;
    if (maximum == 0U || maximum > KSWORD_ARK_STORAGE_CONTROLLER_AUDIT_ROWS) {
        maximum = KSWORD_ARK_STORAGE_CONTROLLER_AUDIT_ROWS;
    }
    copied = 0U;
    available = 0U;
    KeAcquireSpinLock((PKSPIN_LOCK)&Context->Audit.Lock, &irql);
    for (logicalIndex = 0U; logicalIndex < Context->Audit.Count; ++logicalIndex) {
        ULONG physicalIndex;
        const KSWORD_ARK_STORAGE_CONTROLLER_AUDIT_ROW* row;

        physicalIndex =
            (Context->Audit.NextIndex +
             KSWORD_ARK_STORAGE_CONTROLLER_AUDIT_ROWS -
             Context->Audit.Count +
             logicalIndex) %
            KSWORD_ARK_STORAGE_CONTROLLER_AUDIT_ROWS;
        row = &Context->Audit.Rows[physicalIndex];
        if (row->sequence <= input->afterSequence) {
            continue;
        }
        available += 1U;
        if (copied < maximum) {
            output->rows[copied] = *row;
            copied += 1U;
        }
    }
    output->newestSequence = Context->Audit.Sequence;
    KeReleaseSpinLock((PKSPIN_LOCK)&Context->Audit.Lock, irql);
    output->status = KSWORD_ARK_STORAGE_CONTROLLER_STATUS_OK;
    output->rowCount = copied;
    output->availableCount = available;
    output->truncated = available > copied ? 1U : 0U;
    WdfRequestCompleteWithInformation(Request, STATUS_SUCCESS, sizeof(*output));
}
