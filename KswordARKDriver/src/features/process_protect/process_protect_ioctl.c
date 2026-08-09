/*++

Module Name:

    process_protect_ioctl.c

Abstract:

    Dispatch-layer IOCTL handlers for handle-callback based process protection.

Environment:

    Kernel-mode Driver Framework

--*/

#include "ark/ark_driver.h"
#include "../../dispatch/ioctl_validation.h"

#include <ntstrsafe.h>
#include <stdarg.h>

static VOID
KswordARKProcessProtectIoctlLog(
    _In_ WDFDEVICE Device,
    _In_z_ PCSTR LevelText,
    _In_z_ _Printf_format_string_ PCSTR FormatText,
    ...
    )
{
    CHAR logMessage[KSWORD_ARK_LOG_ENTRY_MAX_BYTES] = { 0 };
    va_list arguments;

    va_start(arguments, FormatText);
    if (NT_SUCCESS(RtlStringCbVPrintfA(logMessage, sizeof(logMessage), FormatText, arguments))) {
        (void)KswordARKDriverEnqueueLogFrame(Device, LevelText, logMessage);
    }
    va_end(arguments);
}

NTSTATUS
KswordARKProcessProtectIoctlSetConfigHandler(
    _In_ WDFDEVICE Device,
    _In_ WDFREQUEST Request,
    _In_ size_t InputBufferLength,
    _In_ size_t OutputBufferLength,
    _Out_ size_t* BytesReturned
    )
/*++

Routine Description:

    Handle IOCTL_KSWORD_ARK_SET_PROCESS_PROTECT_CONFIG. Installing a protection
    config changes how every process/thread handle in the system is granted, so
    it goes through the same write-access and safety-policy gates as the other
    callback-behavior mutations.

Arguments:

    Device - WDF device used for safety evaluation and audit logging.
    Request - Current IOCTL request carrying the fixed config packet.
    InputBufferLength - Config packet length.
    OutputBufferLength - Caller output length; unused for this IOCTL.
    BytesReturned - Receives the consumed input byte count on success.

Return Value:

    NTSTATUS from the safety gate, access validation or the protection runtime.

--*/
{
    NTSTATUS status;
    UNREFERENCED_PARAMETER(OutputBufferLength);

    if (BytesReturned == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *BytesReturned = 0;

    {
        KSWORD_ARK_SAFETY_CONTEXT safetyContext;
        RtlZeroMemory(&safetyContext, sizeof(safetyContext));
        safetyContext.Operation = KSWORD_ARK_SAFETY_OPERATION_CALLBACK_SET_RULES;
        safetyContext.TargetProcessId = 0UL;
        safetyContext.ContextFlags = KSWORD_ARK_SAFETY_CONTEXT_FLAG_UI_CONFIRMED;
        status = KswordARKSafetyEvaluate(Device, &safetyContext);
        if (!NT_SUCCESS(status)) {
            KswordARKProcessProtectIoctlLog(Device, "Warn", "Process protection config denied by safety policy, status=0x%08X.", (unsigned int)status);
            return status;
        }
    }

    status = KswordARKValidateDeviceIoControlWriteAccess(Request);
    if (!NT_SUCCESS(status)) {
        KswordARKProcessProtectIoctlLog(Device, "Warn", "Process protection config denied: write access required, status=0x%08X.", (unsigned int)status);
        return status;
    }

    status = KswordARKProcessProtectIoctlSetConfig(Request, InputBufferLength, BytesReturned);
    if (!NT_SUCCESS(status)) {
        KswordARKProcessProtectIoctlLog(Device, "Warn", "Process protection config apply failed, status=0x%08X.", (unsigned int)status);
    }
    return status;
}

NTSTATUS
KswordARKProcessProtectIoctlQueryStateHandler(
    _In_ WDFDEVICE Device,
    _In_ WDFREQUEST Request,
    _In_ size_t InputBufferLength,
    _In_ size_t OutputBufferLength,
    _Out_ size_t* BytesReturned
    )
/*++

Routine Description:

    Handle IOCTL_KSWORD_ARK_QUERY_PROCESS_PROTECT_STATE. The operation is
    read-only and returns the active config plus runtime counters.

Arguments:

    Device - WDF device used for diagnostic logging.
    Request - Current IOCTL request.
    InputBufferLength - Caller input length; unused for this IOCTL.
    OutputBufferLength - State response buffer length.
    BytesReturned - Receives the response byte count.

Return Value:

    NTSTATUS from KswordARKProcessProtectIoctlQueryState.

--*/
{
    NTSTATUS status;
    UNREFERENCED_PARAMETER(InputBufferLength);

    if (BytesReturned == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *BytesReturned = 0;

    status = KswordARKProcessProtectIoctlQueryState(Request, OutputBufferLength, BytesReturned);
    if (!NT_SUCCESS(status)) {
        KswordARKProcessProtectIoctlLog(Device, "Warn", "Process protection state query failed, status=0x%08X.", (unsigned int)status);
    }
    return status;
}
