/*++

Module Name:

    hvm_ioctl.c

Abstract:

    WDF adapters for HVM capability queries and safety-gated lifecycle control.

Environment:

    Kernel-mode Driver Framework.

--*/

#include "hvm_runtime.h"
#include "../../dispatch/ioctl_validation.h"

NTSTATUS
KswordARKHvmIoctlQuery(
    _In_ WDFDEVICE Device,
    _In_ WDFREQUEST Request,
    _In_ size_t InputBufferLength,
    _In_ size_t OutputBufferLength,
    _Out_ size_t* BytesReturned
    )
{
    PVOID inputBuffer = NULL;
    PVOID outputBuffer = NULL;
    size_t actualInputLength = 0U;
    size_t actualOutputLength = 0U;
    NTSTATUS status = STATUS_SUCCESS;
    const KSWORD_ARK_QUERY_HVM_REQUEST* queryRequest = NULL;

    /* The dispatcher requires an explicit completion size on every path. */
    UNREFERENCED_PARAMETER(Device);
    if (BytesReturned == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *BytesReturned = 0U;

    /* Retrieve and validate the versioned fixed query request. */
    status = WdfRequestRetrieveInputBuffer(
        Request,
        sizeof(KSWORD_ARK_QUERY_HVM_REQUEST),
        &inputBuffer,
        &actualInputLength);
    if (!NT_SUCCESS(status) ||
        InputBufferLength < sizeof(KSWORD_ARK_QUERY_HVM_REQUEST) ||
        actualInputLength < sizeof(KSWORD_ARK_QUERY_HVM_REQUEST)) {
        return NT_SUCCESS(status)
            ? STATUS_INFO_LENGTH_MISMATCH
            : status;
    }
    queryRequest = (const KSWORD_ARK_QUERY_HVM_REQUEST*)inputBuffer;
    if (queryRequest->version != KSWORD_ARK_HVM_PROTOCOL_VERSION ||
        queryRequest->size != sizeof(*queryRequest)) {
        return STATUS_REVISION_MISMATCH;
    }

    /* Retrieve the complete fixed status response. */
    status = WdfRequestRetrieveOutputBuffer(
        Request,
        sizeof(KSWORD_ARK_QUERY_HVM_RESPONSE),
        &outputBuffer,
        &actualOutputLength);
    if (!NT_SUCCESS(status) ||
        OutputBufferLength < sizeof(KSWORD_ARK_QUERY_HVM_RESPONSE) ||
        actualOutputLength < sizeof(KSWORD_ARK_QUERY_HVM_RESPONSE)) {
        return NT_SUCCESS(status)
            ? STATUS_BUFFER_TOO_SMALL
            : status;
    }

    /* Snapshot the backend without changing VMX or EPT state. */
    status = KswordARKHvmQuery(
        (KSWORD_ARK_QUERY_HVM_RESPONSE*)outputBuffer);
    if (NT_SUCCESS(status)) {
        *BytesReturned = sizeof(KSWORD_ARK_QUERY_HVM_RESPONSE);
    }
    return status;
}

NTSTATUS
KswordARKHvmIoctlControl(
    _In_ WDFDEVICE Device,
    _In_ WDFREQUEST Request,
    _In_ size_t InputBufferLength,
    _In_ size_t OutputBufferLength,
    _Out_ size_t* BytesReturned
    )
{
    PVOID inputBuffer = NULL;
    PVOID outputBuffer = NULL;
    size_t actualInputLength = 0U;
    size_t actualOutputLength = 0U;
    NTSTATUS status = STATUS_SUCCESS;
    const KSWORD_ARK_CONTROL_HVM_REQUEST* controlRequest = NULL;
    KSWORD_ARK_CONTROL_HVM_RESPONSE* controlResponse = NULL;

    /* Reject an invalid completion contract before touching request buffers. */
    if (BytesReturned == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *BytesReturned = 0U;

    /* Lifecycle mutations require a write-authorized device handle. */
    status = KswordARKValidateDeviceIoControlWriteAccess(Request);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    /* Retrieve both fixed protocol buffers before evaluating policy. */
    status = WdfRequestRetrieveInputBuffer(
        Request,
        sizeof(KSWORD_ARK_CONTROL_HVM_REQUEST),
        &inputBuffer,
        &actualInputLength);
    if (!NT_SUCCESS(status) ||
        InputBufferLength < sizeof(KSWORD_ARK_CONTROL_HVM_REQUEST) ||
        actualInputLength < sizeof(KSWORD_ARK_CONTROL_HVM_REQUEST)) {
        return NT_SUCCESS(status)
            ? STATUS_INFO_LENGTH_MISMATCH
            : status;
    }
    status = WdfRequestRetrieveOutputBuffer(
        Request,
        sizeof(KSWORD_ARK_CONTROL_HVM_RESPONSE),
        &outputBuffer,
        &actualOutputLength);
    if (!NT_SUCCESS(status) ||
        OutputBufferLength < sizeof(KSWORD_ARK_CONTROL_HVM_RESPONSE) ||
        actualOutputLength < sizeof(KSWORD_ARK_CONTROL_HVM_RESPONSE)) {
        return NT_SUCCESS(status)
            ? STATUS_BUFFER_TOO_SMALL
            : status;
    }
    controlRequest =
        (const KSWORD_ARK_CONTROL_HVM_REQUEST*)inputBuffer;
    controlResponse =
        (KSWORD_ARK_CONTROL_HVM_RESPONSE*)outputBuffer;

    /*
     * Preparing VMX pages is reversible allocation work.  The actual VMX
     * transition receives the central critical kernel-patch policy gate.
     */
    if (controlRequest->command ==
        KSWORD_ARK_HVM_CONTROL_SELF_TEST) {
        KSWORD_ARK_SAFETY_CONTEXT safetyContext = { 0 };

        /* Bind policy auditing to the exact high-risk operation class. */
        safetyContext.Operation =
            KSWORD_ARK_SAFETY_OPERATION_KERNEL_PATCH;
        safetyContext.ContextFlags =
            (controlRequest->flags &
                KSWORD_ARK_HVM_CONTROL_FLAG_UI_CONFIRMED) != 0UL
            ? KSWORD_ARK_SAFETY_CONTEXT_FLAG_UI_CONFIRMED
            : 0UL;
        safetyContext.TargetText =
            L"Per-processor VT-x VMXON and VMXOFF self-test";
        safetyContext.TargetTextChars =
            (USHORT)(RTL_NUMBER_OF(
                L"Per-processor VT-x VMXON and VMXOFF self-test") - 1U);
        status = KswordARKSafetyEvaluate(Device, &safetyContext);
        if (!NT_SUCCESS(status)) {
            RtlZeroMemory(controlResponse, sizeof(*controlResponse));
            controlResponse->version =
                KSWORD_ARK_HVM_PROTOCOL_VERSION;
            controlResponse->size = sizeof(*controlResponse);
            controlResponse->status =
                KSWORD_ARK_HVM_CONTROL_STATUS_CONFIRMATION_REQUIRED;
            controlResponse->lastStatus = status;
            *BytesReturned = sizeof(*controlResponse);
            return status;
        }
    }

    /* Execute the versioned lifecycle command and return its stable summary. */
    status = KswordARKHvmControl(controlRequest, controlResponse);
    *BytesReturned = sizeof(*controlResponse);
    return status;
}
