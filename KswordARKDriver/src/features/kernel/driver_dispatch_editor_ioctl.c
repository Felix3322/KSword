/*++

Module Name:

    driver_dispatch_editor_ioctl.c

Abstract:

    IOCTL boundary for the generic DriverObject MajorFunction editor.

--*/

#include "ark/ark_driver.h"
#include "../../dispatch/ioctl_validation.h"

#include <ntstrsafe.h>

static VOID
KswordARKDriverDispatchLogResult(
    _In_ WDFDEVICE Device,
    _In_ const KSWORD_ARK_DRIVER_DISPATCH_RESPONSE* Response
    )
{
    CHAR message[KSWORD_ARK_LOG_ENTRY_MAX_BYTES] = { 0 };
    NTSTATUS status = STATUS_SUCCESS;

    if (Response == NULL) {
        return;
    }
    status = RtlStringCbPrintfA(
        message,
        sizeof(message),
        "R0 driver-dispatch: action=%lu major=0x%02lX status=0x%08X "
        "driver=0x%I64X current=0x%I64X original=0x%I64X applied=0x%I64X "
        "requested=0x%I64X generation=%lu flags=0x%08X.",
        (unsigned long)Response->action,
        (unsigned long)Response->majorFunction,
        (unsigned int)Response->lastStatus,
        Response->driverObjectAddress,
        Response->currentDispatchAddress,
        Response->originalDispatchAddress,
        Response->appliedDispatchAddress,
        Response->requestedDispatchAddress,
        (unsigned long)Response->generation,
        (unsigned int)Response->responseFlags);
    if (NT_SUCCESS(status)) {
        (VOID)KswordARKDriverEnqueueLogFrame(
            Device,
            NT_SUCCESS((NTSTATUS)Response->lastStatus) ? "Warn" : "Error",
            message);
    }
}

NTSTATUS
KswordARKKernelIoctlControlDriverDispatch(
    _In_ WDFDEVICE Device,
    _In_ WDFREQUEST Request,
    _In_ size_t InputBufferLength,
    _In_ size_t OutputBufferLength,
    _Out_ size_t* BytesReturned
    )
{
    KSWORD_ARK_DRIVER_DISPATCH_REQUEST* inputBuffer = NULL;
    KSWORD_ARK_DRIVER_DISPATCH_RESPONSE* outputBuffer = NULL;
    KSWORD_ARK_DRIVER_DISPATCH_REQUEST requestSnapshot;
    size_t actualInputLength = 0U;
    size_t actualOutputLength = 0U;
    NTSTATUS status = STATUS_SUCCESS;

    UNREFERENCED_PARAMETER(InputBufferLength);
    UNREFERENCED_PARAMETER(OutputBufferLength);

    if (BytesReturned == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *BytesReturned = 0U;
    if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
        return STATUS_INVALID_DEVICE_STATE;
    }
    status = KswordARKValidateDeviceIoControlWriteAccess(Request);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    status = KswordARKRetrieveRequiredInputBuffer(
        Request,
        sizeof(requestSnapshot),
        (PVOID*)&inputBuffer,
        &actualInputLength);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    RtlCopyMemory(&requestSnapshot, inputBuffer, sizeof(requestSnapshot));
    status = KswordARKRetrieveRequiredOutputBuffer(
        Request,
        sizeof(*outputBuffer),
        (PVOID*)&outputBuffer,
        &actualOutputLength);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    RtlZeroMemory(outputBuffer, sizeof(*outputBuffer));
    *BytesReturned = sizeof(*outputBuffer);

    status = KswordARKDriverControlDispatch(&requestSnapshot, outputBuffer);
    KswordARKDriverDispatchLogResult(Device, outputBuffer);
    UNREFERENCED_PARAMETER(status);
    return STATUS_SUCCESS;
}
