/*++

Module Name:

    callback_remove_external.c

Abstract:

    Implements IOCTL for removing external notify callbacks by callback function address.

Environment:

    Kernel-mode Driver Framework

--*/

#include "callback_internal.h"

typedef VOID
(*KSWORD_ARK_PROCESS_NOTIFY_EX)(
    _Inout_ PEPROCESS Process,
    _In_ HANDLE ProcessId,
    _Inout_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo
    );

typedef VOID
(*KSWORD_ARK_THREAD_NOTIFY)(
    _In_ HANDLE ProcessId,
    _In_ HANDLE ThreadId,
    _In_ BOOLEAN Create
    );

typedef VOID
(*KSWORD_ARK_IMAGE_NOTIFY)(
    _In_opt_ PUNICODE_STRING FullImageName,
    _In_ HANDLE ProcessId,
    _In_ PIMAGE_INFO ImageInfo
    );

NTSTATUS
KswordARKCallbackIoctlRemoveExternalCallback(
    _In_ WDFREQUEST Request,
    _In_ size_t InputBufferLength,
    _In_ size_t OutputBufferLength,
    _Out_ size_t* CompleteBytesOut
    )
{
    NTSTATUS status = STATUS_SUCCESS;
    PVOID inputBuffer = NULL;
    PVOID outputBuffer = NULL;
    size_t inputBufferLength = 0;
    size_t outputBufferLength = 0;
    KSWORD_ARK_REMOVE_EXTERNAL_CALLBACK_REQUEST* requestPacket = NULL;
    KSWORD_ARK_REMOVE_EXTERNAL_CALLBACK_RESPONSE* responsePacket = NULL;
    PVOID callbackPointer = NULL;
    KSWORD_ARK_PROCESS_NOTIFY_EX processNotify = NULL;
    KSWORD_ARK_THREAD_NOTIFY threadNotify = NULL;
    KSWORD_ARK_IMAGE_NOTIFY imageNotify = NULL;

    if (CompleteBytesOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *CompleteBytesOut = 0U;

    if (InputBufferLength < sizeof(KSWORD_ARK_REMOVE_EXTERNAL_CALLBACK_REQUEST) ||
        OutputBufferLength < sizeof(KSWORD_ARK_REMOVE_EXTERNAL_CALLBACK_RESPONSE)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    status = WdfRequestRetrieveInputBuffer(
        Request,
        sizeof(KSWORD_ARK_REMOVE_EXTERNAL_CALLBACK_REQUEST),
        &inputBuffer,
        &inputBufferLength);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = WdfRequestRetrieveOutputBuffer(
        Request,
        sizeof(KSWORD_ARK_REMOVE_EXTERNAL_CALLBACK_RESPONSE),
        &outputBuffer,
        &outputBufferLength);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    requestPacket = (KSWORD_ARK_REMOVE_EXTERNAL_CALLBACK_REQUEST*)inputBuffer;
    responsePacket = (KSWORD_ARK_REMOVE_EXTERNAL_CALLBACK_RESPONSE*)outputBuffer;

    if (requestPacket->size < sizeof(KSWORD_ARK_REMOVE_EXTERNAL_CALLBACK_REQUEST) ||
        requestPacket->callbackAddress == 0ULL ||
        requestPacket->flags != KSWORD_ARK_EXTERNAL_CALLBACK_REMOVE_FLAG_NONE) {
        return STATUS_INVALID_PARAMETER;
    }

    RtlZeroMemory(responsePacket, sizeof(KSWORD_ARK_REMOVE_EXTERNAL_CALLBACK_RESPONSE));
    responsePacket->size = sizeof(KSWORD_ARK_REMOVE_EXTERNAL_CALLBACK_RESPONSE);
    responsePacket->version = requestPacket->version;
    responsePacket->callbackClass = requestPacket->callbackClass;
    responsePacket->callbackAddress = requestPacket->callbackAddress;
    callbackPointer = (PVOID)(ULONG_PTR)requestPacket->callbackAddress;

    switch (requestPacket->callbackClass) {
    case KSWORD_ARK_EXTERNAL_CALLBACK_REMOVE_TYPE_PROCESS:
        RtlCopyMemory(&processNotify, &callbackPointer, sizeof(processNotify));
        status = PsSetCreateProcessNotifyRoutineEx(
            processNotify,
            TRUE);
        break;

    case KSWORD_ARK_EXTERNAL_CALLBACK_REMOVE_TYPE_THREAD:
        RtlCopyMemory(&threadNotify, &callbackPointer, sizeof(threadNotify));
        status = PsRemoveCreateThreadNotifyRoutine(
            threadNotify);
        break;

    case KSWORD_ARK_EXTERNAL_CALLBACK_REMOVE_TYPE_IMAGE:
        RtlCopyMemory(&imageNotify, &callbackPointer, sizeof(imageNotify));
        status = PsRemoveLoadImageNotifyRoutine(
            imageNotify);
        break;

    default:
        status = STATUS_INVALID_PARAMETER;
        break;
    }

    responsePacket->ntstatus = status;
    *CompleteBytesOut = sizeof(KSWORD_ARK_REMOVE_EXTERNAL_CALLBACK_RESPONSE);

    KswordArkCallbackLogFormat(
        NT_SUCCESS(status) ? "Info" : "Warn",
        "External callback remove request: class=%lu, callback=0x%llX, status=0x%08lX.",
        (unsigned long)requestPacket->callbackClass,
        requestPacket->callbackAddress,
        (unsigned long)status);

    return status;
}
