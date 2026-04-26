/*++

Module Name:

    callback_remove_external.c

Abstract:

    Implements IOCTL for removing external notify callbacks by callback function address.

Environment:

    Kernel-mode Driver Framework

--*/

#include "callback_internal.h"

typedef struct _KSWORD_ARK_SYSTEM_MODULE_ENTRY
{
    HANDLE Section;
    PVOID MappedBase;
    PVOID ImageBase;
    ULONG ImageSize;
    ULONG Flags;
    USHORT LoadOrderIndex;
    USHORT InitOrderIndex;
    USHORT LoadCount;
    USHORT OffsetToFileName;
    UCHAR FullPathName[256];
} KSWORD_ARK_SYSTEM_MODULE_ENTRY;

typedef struct _KSWORD_ARK_SYSTEM_MODULE_INFORMATION
{
    ULONG NumberOfModules;
    KSWORD_ARK_SYSTEM_MODULE_ENTRY Modules[1];
} KSWORD_ARK_SYSTEM_MODULE_INFORMATION;

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

_Must_inspect_result_
static
NTSTATUS
KswordArkCallbackResolveModuleByAddress(
    _In_ ULONG64 callbackAddress,
    _Out_writes_(modulePathChars) PWCHAR modulePathBuffer,
    _In_ size_t modulePathChars,
    _Out_opt_ ULONG64* moduleBaseOut,
    _Out_opt_ ULONG* moduleSizeOut
    )
{
    NTSTATUS status = STATUS_SUCCESS;
    ULONG requiredBytes = 0;
    KSWORD_ARK_SYSTEM_MODULE_INFORMATION* moduleInfo = NULL;
    ULONG moduleIndex = 0;
    PVOID callbackPointer = (PVOID)(ULONG_PTR)callbackAddress;

    if (modulePathBuffer == NULL || modulePathChars == 0U) {
        return STATUS_INVALID_PARAMETER;
    }
    modulePathBuffer[0] = L'\0';
    if (moduleBaseOut != NULL) {
        *moduleBaseOut = 0ULL;
    }
    if (moduleSizeOut != NULL) {
        *moduleSizeOut = 0UL;
    }

    status = ZwQuerySystemInformation(SystemModuleInformation, NULL, 0UL, &requiredBytes);
    if (status != STATUS_INFO_LENGTH_MISMATCH || requiredBytes == 0UL) {
        return STATUS_UNSUCCESSFUL;
    }

    moduleInfo = (KSWORD_ARK_SYSTEM_MODULE_INFORMATION*)KswordArkAllocateNonPaged(
        requiredBytes,
        KSWORD_ARK_CALLBACK_TAG_RUNTIME);
    if (moduleInfo == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    status = ZwQuerySystemInformation(
        SystemModuleInformation,
        moduleInfo,
        requiredBytes,
        &requiredBytes);
    if (!NT_SUCCESS(status)) {
        ExFreePool(moduleInfo);
        return status;
    }

    for (moduleIndex = 0; moduleIndex < moduleInfo->NumberOfModules; ++moduleIndex) {
        const KSWORD_ARK_SYSTEM_MODULE_ENTRY* moduleEntry =
            (const KSWORD_ARK_SYSTEM_MODULE_ENTRY*)&moduleInfo->Modules[moduleIndex];
        const ULONG64 moduleBase = (ULONG64)(ULONG_PTR)moduleEntry->ImageBase;
        const ULONG64 moduleEnd = moduleBase + (ULONG64)moduleEntry->ImageSize;
        if ((ULONG64)(ULONG_PTR)callbackPointer < moduleBase || (ULONG64)(ULONG_PTR)callbackPointer >= moduleEnd) {
            continue;
        }

        if (moduleBaseOut != NULL) {
            *moduleBaseOut = moduleBase;
        }
        if (moduleSizeOut != NULL) {
            *moduleSizeOut = moduleEntry->ImageSize;
        }
        (VOID)RtlStringCbPrintfW(
            modulePathBuffer,
            modulePathChars * sizeof(WCHAR),
            L"%S",
            moduleEntry->FullPathName);
        ExFreePool(moduleInfo);
        return STATUS_SUCCESS;
    }

    ExFreePool(moduleInfo);
    return STATUS_NOT_FOUND;
}

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
    ULONG64 moduleBase = 0ULL;
    ULONG moduleSize = 0UL;

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
        requestPacket->version != KSWORD_ARK_EXTERNAL_CALLBACK_REMOVE_PROTOCOL_VERSION ||
        requestPacket->callbackAddress == 0ULL ||
        requestPacket->flags != KSWORD_ARK_EXTERNAL_CALLBACK_REMOVE_FLAG_NONE) {
        return STATUS_INVALID_PARAMETER;
    }

    RtlZeroMemory(responsePacket, sizeof(KSWORD_ARK_REMOVE_EXTERNAL_CALLBACK_RESPONSE));
    responsePacket->size = sizeof(KSWORD_ARK_REMOVE_EXTERNAL_CALLBACK_RESPONSE);
    responsePacket->version = requestPacket->version;
    responsePacket->callbackClass = requestPacket->callbackClass;
    responsePacket->callbackAddress = requestPacket->callbackAddress;
    responsePacket->moduleBase = 0ULL;
    responsePacket->moduleSize = 0UL;
    responsePacket->mappingFlags = 0UL;
    callbackPointer = (PVOID)(ULONG_PTR)requestPacket->callbackAddress;
    (VOID)KswordArkCallbackResolveModuleByAddress(
        requestPacket->callbackAddress,
        responsePacket->modulePath,
        RTL_NUMBER_OF(responsePacket->modulePath),
        &moduleBase,
        &moduleSize);
    responsePacket->moduleBase = moduleBase;
    responsePacket->moduleSize = moduleSize;
    if (responsePacket->modulePath[0] != L'\0') {
        responsePacket->mappingFlags = 1UL;
    }

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

    case KSWORD_ARK_EXTERNAL_CALLBACK_REMOVE_TYPE_OBJECT:
    case KSWORD_ARK_EXTERNAL_CALLBACK_REMOVE_TYPE_REGISTRY:
    case KSWORD_ARK_EXTERNAL_CALLBACK_REMOVE_TYPE_MINIFILTER:
    case KSWORD_ARK_EXTERNAL_CALLBACK_REMOVE_TYPE_WFP_CALLOUT:
    case KSWORD_ARK_EXTERNAL_CALLBACK_REMOVE_TYPE_ETW_PROVIDER:
        status = STATUS_NOT_SUPPORTED;
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
