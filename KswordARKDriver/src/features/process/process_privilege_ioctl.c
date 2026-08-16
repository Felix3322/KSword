/*++

Module Name:

    process_privilege_ioctl.c

Abstract:

    IOCTL handlers for documented process-token privilege operations.

Environment:

    Kernel-mode Driver Framework, PASSIVE_LEVEL.

--*/

#include "ark/ark_driver.h"
#include "../../dispatch/ioctl_validation.h"

static size_t
KswordARKProcessTokenPrivilegeResponseHeaderSize(VOID)
{
    return KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_RESPONSE_HEADER_SIZE;
}

NTSTATUS
KswordARKProcessIoctlQueryTokenPrivileges(
    _In_ WDFDEVICE Device,
    _In_ WDFREQUEST Request,
    _In_ size_t InputBufferLength,
    _In_ size_t OutputBufferLength,
    _Out_ size_t* BytesReturned
    )
{
    KSWORD_ARK_QUERY_PROCESS_TOKEN_PRIVILEGES_REQUEST requestSnapshot;
    KSWORD_ARK_QUERY_PROCESS_TOKEN_PRIVILEGES_RESPONSE* response = NULL;
    PVOID inputBuffer = NULL;
    PVOID outputBuffer = NULL;
    size_t actualInputLength = 0U;
    size_t actualOutputLength = 0U;
    size_t responseHeaderSize = KswordARKProcessTokenPrivilegeResponseHeaderSize();
    size_t entryCapacity = 0U;
    ULONG totalCount = 0UL;
    ULONG returnedCount = 0UL;
    NTSTATUS status = STATUS_SUCCESS;
    NTSTATUS operationStatus = STATUS_SUCCESS;

    UNREFERENCED_PARAMETER(Device);
    UNREFERENCED_PARAMETER(InputBufferLength);
    UNREFERENCED_PARAMETER(OutputBufferLength);

    if (BytesReturned == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *BytesReturned = 0U;

    status = KswordARKRetrieveRequiredInputBuffer(
        Request,
        sizeof(requestSnapshot),
        &inputBuffer,
        &actualInputLength);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    RtlCopyMemory(&requestSnapshot, inputBuffer, sizeof(requestSnapshot));

    status = KswordARKRetrieveRequiredOutputBuffer(
        Request,
        responseHeaderSize,
        &outputBuffer,
        &actualOutputLength);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    response = (KSWORD_ARK_QUERY_PROCESS_TOKEN_PRIVILEGES_RESPONSE*)outputBuffer;
    RtlZeroMemory(response, responseHeaderSize);
    response->size = (ULONG)responseHeaderSize;
    response->version = KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_PROTOCOL_VERSION;
    response->processId = requestSnapshot.processId;
    response->status = KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_STATUS_FAILED;
    response->entrySize = sizeof(KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_ENTRY);
    response->lastStatus = STATUS_INVALID_PARAMETER;
    *BytesReturned = responseHeaderSize;

    if (requestSnapshot.size != sizeof(requestSnapshot) ||
        requestSnapshot.version != KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_PROTOCOL_VERSION ||
        requestSnapshot.flags != 0UL) {
        return STATUS_SUCCESS;
    }

    status = KswordARKValidateUserPid(requestSnapshot.processId);
    if (!NT_SUCCESS(status)) {
        response->lastStatus = status;
        return STATUS_SUCCESS;
    }

    entryCapacity = (actualOutputLength - responseHeaderSize) /
        sizeof(KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_ENTRY);
    if (entryCapacity > KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_MAX_ENTRIES) {
        entryCapacity = KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_MAX_ENTRIES;
    }

    operationStatus = KswordARKDriverQueryProcessTokenPrivilegesByPid(
        requestSnapshot.processId,
        response->entries,
        (ULONG)entryCapacity,
        &totalCount,
        &returnedCount);

    response->totalCount = totalCount;
    response->returnedCount = returnedCount;
    response->lastStatus = operationStatus;
    if (operationStatus == STATUS_BUFFER_OVERFLOW) {
        response->status = KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_STATUS_PARTIAL;
    }
    else if (NT_SUCCESS(operationStatus)) {
        response->status = KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_STATUS_OK;
    }

    *BytesReturned = responseHeaderSize +
        ((size_t)returnedCount * sizeof(KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_ENTRY));
    response->size = (ULONG)*BytesReturned;
    return STATUS_SUCCESS;
}

NTSTATUS
KswordARKProcessIoctlAdjustTokenPrivilege(
    _In_ WDFDEVICE Device,
    _In_ WDFREQUEST Request,
    _In_ size_t InputBufferLength,
    _In_ size_t OutputBufferLength,
    _Out_ size_t* BytesReturned
    )
{
    KSWORD_ARK_ADJUST_PROCESS_TOKEN_PRIVILEGE_REQUEST requestSnapshot;
    KSWORD_ARK_ADJUST_PROCESS_TOKEN_PRIVILEGE_RESPONSE* response = NULL;
    KSWORD_ARK_SAFETY_CONTEXT safetyContext;
    PVOID inputBuffer = NULL;
    PVOID outputBuffer = NULL;
    size_t actualInputLength = 0U;
    size_t actualOutputLength = 0U;
    LUID privilegeLuid;
    NTSTATUS status = STATUS_SUCCESS;
    NTSTATUS operationStatus = STATUS_SUCCESS;

    UNREFERENCED_PARAMETER(InputBufferLength);
    UNREFERENCED_PARAMETER(OutputBufferLength);

    if (BytesReturned == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *BytesReturned = 0U;

    status = KswordARKValidateDeviceIoControlWriteAccess(Request);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = KswordARKRetrieveRequiredInputBuffer(
        Request,
        sizeof(requestSnapshot),
        &inputBuffer,
        &actualInputLength);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    RtlCopyMemory(&requestSnapshot, inputBuffer, sizeof(requestSnapshot));

    status = KswordARKRetrieveRequiredOutputBuffer(
        Request,
        sizeof(*response),
        &outputBuffer,
        &actualOutputLength);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    response = (KSWORD_ARK_ADJUST_PROCESS_TOKEN_PRIVILEGE_RESPONSE*)outputBuffer;
    RtlZeroMemory(response, sizeof(*response));
    response->size = sizeof(*response);
    response->version = KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_PROTOCOL_VERSION;
    response->processId = requestSnapshot.processId;
    response->luidLowPart = requestSnapshot.luidLowPart;
    response->luidHighPart = requestSnapshot.luidHighPart;
    response->action = requestSnapshot.action;
    response->status = KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_STATUS_FAILED;
    response->lastStatus = STATUS_INVALID_PARAMETER;
    *BytesReturned = sizeof(*response);

    if (requestSnapshot.size != sizeof(requestSnapshot) ||
        requestSnapshot.version != KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_PROTOCOL_VERSION ||
        requestSnapshot.reserved != 0UL ||
        requestSnapshot.flags != KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_FLAG_UI_CONFIRMED ||
        (requestSnapshot.action != KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_ACTION_ENABLE &&
         requestSnapshot.action != KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_ACTION_DISABLE)) {
        return STATUS_SUCCESS;
    }

    status = KswordARKValidateUserPid(requestSnapshot.processId);
    if (!NT_SUCCESS(status)) {
        response->lastStatus = status;
        return STATUS_SUCCESS;
    }

    RtlZeroMemory(&safetyContext, sizeof(safetyContext));
    safetyContext.Operation = KSWORD_ARK_SAFETY_OPERATION_PROCESS_SET_PROTECTION;
    safetyContext.TargetProcessId = requestSnapshot.processId;
    safetyContext.ContextFlags = KSWORD_ARK_SAFETY_CONTEXT_FLAG_UI_CONFIRMED;
    status = KswordARKSafetyEvaluate(Device, &safetyContext);
    if (!NT_SUCCESS(status)) {
        response->lastStatus = status;
        return STATUS_SUCCESS;
    }

    privilegeLuid.LowPart = requestSnapshot.luidLowPart;
    privilegeLuid.HighPart = requestSnapshot.luidHighPart;
    operationStatus = KswordARKDriverAdjustProcessTokenPrivilegeByPid(
        requestSnapshot.processId,
        privilegeLuid,
        requestSnapshot.action == KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_ACTION_ENABLE);
    response->lastStatus = operationStatus;
    response->status = NT_SUCCESS(operationStatus)
        ? KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_STATUS_OK
        : KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_STATUS_FAILED;

    return STATUS_SUCCESS;
}
