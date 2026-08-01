/*++

Module Name:

    kernel_idt_baseline_ioctl.c

Abstract:

    WDF adapter for safety-gated, compare-and-swap IDT baseline restoration.

Environment:

    Kernel-mode Driver Framework.

--*/

#include "kernel_idt_baseline.h"
#include "../../dispatch/ioctl_validation.h"

NTSTATUS
KswordARKKernelIoctlRestoreIdtBaseline(
    _In_ WDFDEVICE Device,
    _In_ WDFREQUEST Request,
    _In_ size_t InputBufferLength,
    _In_ size_t OutputBufferLength,
    _Out_ size_t* BytesReturned
    )
/*++

Routine Description:

    Validate fixed buffers and write access, evaluate the central kernel-patch
    policy for force requests, then invoke the atomic IDT backend.

Arguments:

    Device/Request - WDF dispatch objects.
    InputBufferLength/OutputBufferLength - Dispatcher lengths.
    BytesReturned - Fixed response completion size.

Return Value:

    NTSTATUS from validation, policy, or the backend.

--*/
{
    PVOID inputBuffer = NULL;
    PVOID outputBuffer = NULL;
    size_t actualInputLength = 0U;
    size_t actualOutputLength = 0U;
    NTSTATUS status = STATUS_SUCCESS;
    KSWORD_ARK_RESTORE_IDT_BASELINE_REQUEST restoreRequestSnapshot = { 0 };
    const KSWORD_ARK_RESTORE_IDT_BASELINE_REQUEST* restoreRequest = NULL;
    KSWORD_ARK_RESTORE_IDT_BASELINE_RESPONSE* restoreResponse = NULL;

    /* Reject an invalid completion-size contract. */
    if (BytesReturned == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *BytesReturned = 0U;

    /* Every IDT restore request requires a FILE_WRITE_ACCESS handle. */
    status = KswordARKValidateDeviceIoControlWriteAccess(Request);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    /* Retrieve and validate the complete fixed request. */
    status = WdfRequestRetrieveInputBuffer(
        Request,
        sizeof(KSWORD_ARK_RESTORE_IDT_BASELINE_REQUEST),
        &inputBuffer,
        &actualInputLength);
    if (!NT_SUCCESS(status) ||
        InputBufferLength <
            sizeof(KSWORD_ARK_RESTORE_IDT_BASELINE_REQUEST) ||
        actualInputLength <
            sizeof(KSWORD_ARK_RESTORE_IDT_BASELINE_REQUEST)) {
        return NT_SUCCESS(status)
            ? STATUS_INFO_LENGTH_MISMATCH
            : status;
    }
    /* Preserve METHOD_BUFFERED input before output retrieval exposes the same system buffer. */
    RtlCopyMemory(
        &restoreRequestSnapshot,
        inputBuffer,
        sizeof(restoreRequestSnapshot));

    /* Retrieve and validate the complete fixed response. */
    status = WdfRequestRetrieveOutputBuffer(
        Request,
        sizeof(KSWORD_ARK_RESTORE_IDT_BASELINE_RESPONSE),
        &outputBuffer,
        &actualOutputLength);
    if (!NT_SUCCESS(status) ||
        OutputBufferLength <
            sizeof(KSWORD_ARK_RESTORE_IDT_BASELINE_RESPONSE) ||
        actualOutputLength <
            sizeof(KSWORD_ARK_RESTORE_IDT_BASELINE_RESPONSE)) {
        return NT_SUCCESS(status)
            ? STATUS_BUFFER_TOO_SMALL
            : status;
    }

    /* Bind typed views only after both buffers pass their fixed-size checks. */
    restoreRequest = &restoreRequestSnapshot;
    restoreResponse =
        (KSWORD_ARK_RESTORE_IDT_BASELINE_RESPONSE*)outputBuffer;

    /* Reject force mutations without the explicit UI-confirmed flag. */
    if ((restoreRequest->flags &
            KSWORD_ARK_IDT_RESTORE_FLAG_FORCE) != 0UL) {
        KSWORD_ARK_SAFETY_CONTEXT safetyContext = { 0 };

        /* Reuse the central critical kernel-patch policy class. */
        safetyContext.Operation =
            KSWORD_ARK_SAFETY_OPERATION_KERNEL_PATCH;
        safetyContext.ContextFlags =
            (restoreRequest->flags &
                KSWORD_ARK_IDT_RESTORE_FLAG_UI_CONFIRMED) != 0UL
            ? KSWORD_ARK_SAFETY_CONTEXT_FLAG_UI_CONFIRMED
            : 0UL;
        safetyContext.TargetText =
            L"Atomic IDT descriptor baseline restore";
        safetyContext.TargetTextChars =
            (USHORT)(RTL_NUMBER_OF(
                L"Atomic IDT descriptor baseline restore") - 1U);

        /* Stop before processor-affinity or descriptor access on policy denial. */
        status = KswordARKSafetyEvaluate(Device, &safetyContext);
        if (!NT_SUCCESS(status)) {
            RtlZeroMemory(restoreResponse, sizeof(*restoreResponse));
            restoreResponse->version =
                KSWORD_ARK_KERNEL_BASELINE_PROTOCOL_VERSION;
            restoreResponse->size = sizeof(*restoreResponse);
            restoreResponse->status =
                KSWORD_ARK_IDT_RESTORE_STATUS_WRITE_FAILED;
            restoreResponse->lastStatus = status;
            *BytesReturned = sizeof(*restoreResponse);
            return status;
        }
    }

    /* Execute read-only preflight or atomic force restoration. */
    status = KswordARKIdtBaselineRestore(
        restoreRequest,
        restoreResponse);
    *BytesReturned = sizeof(*restoreResponse);
    return status;
}
