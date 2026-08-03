/*++

Module Name:

    storage_forensics_ioctl.c

Abstract:

    WDF IOCTL adapters for bounded physical-disk backend discovery, reading,
    and safety-gated writing.

Environment:

    Kernel-mode Driver Framework.

--*/

#include "ark/ark_driver.h"
#include "../../dispatch/ioctl_validation.h"
#include "../../platform/pool_compat.h"

#include <ntstrsafe.h>

/* Tag nonpaged snapshots of variable raw-disk write requests. */
#define KSW_STORAGE_FORENSICS_IOCTL_POOL_TAG 'ifSK'

/* Lock the fixed read-request ABI used by both R3 and R0. */
C_ASSERT(sizeof(KSWORD_ARK_RAW_DISK_READ_REQUEST) == 40U);
/* Lock the payload offset rather than the padded structure size. */
C_ASSERT(KSWORD_ARK_RAW_DISK_READ_RESPONSE_HEADER_SIZE == 32U);
/* Lock the variable write-request payload offset. */
C_ASSERT(KSWORD_ARK_RAW_DISK_WRITE_REQUEST_HEADER_SIZE == 40U);

NTSTATUS
KswordARKStorageIoctlQueryRawDiskBackend(
    _In_ WDFDEVICE Device,
    _In_ WDFREQUEST Request,
    _In_ size_t InputBufferLength,
    _In_ size_t OutputBufferLength,
    _Out_ size_t* BytesReturned
    )
/*++

Routine Description:

    Validates and forwards a fixed raw-disk backend capability query.

--*/
{
    /* This read-only handler does not require the WDF device after dispatch. */
    UNREFERENCED_PARAMETER(Device);
    /* The dispatcher-provided output length is revalidated by WDF retrieval. */
    UNREFERENCED_PARAMETER(OutputBufferLength);

    /* Reject a missing completion-count pointer. */
    if (BytesReturned == NULL) {
        /* The handler contract was invalid. */
        return STATUS_INVALID_PARAMETER;
    }

    /* Clear the completion count for every failure path. */
    *BytesReturned = 0U;
    /* Retrieve the complete fixed request from the METHOD_BUFFERED system buffer. */
    PVOID inputBuffer = NULL;
    /* Receive the actual WDF input length for strict validation. */
    size_t actualInputLength = 0U;
    /* Require the exact fixed request header. */
    NTSTATUS status = WdfRequestRetrieveInputBuffer(
        Request,
        sizeof(KSWORD_ARK_QUERY_RAW_DISK_BACKEND_REQUEST),
        &inputBuffer,
        &actualInputLength);

    /* Reject missing or truncated input before parsing fields. */
    if (!NT_SUCCESS(status)
        || InputBufferLength < sizeof(KSWORD_ARK_QUERY_RAW_DISK_BACKEND_REQUEST)
        || actualInputLength < sizeof(KSWORD_ARK_QUERY_RAW_DISK_BACKEND_REQUEST)) {
        /* Preserve the WDF failure or normalize a dispatcher length mismatch. */
        return NT_SUCCESS(status) ? STATUS_INFO_LENGTH_MISMATCH : status;
    }

    /* Snapshot input before METHOD_BUFFERED response writes can overwrite it. */
    KSWORD_ARK_QUERY_RAW_DISK_BACKEND_REQUEST requestSnapshot;
    /* Preserve every fixed request field in independent stack storage. */
    RtlCopyMemory(&requestSnapshot, inputBuffer, sizeof(requestSnapshot));

    /* Retrieve the fixed response buffer. */
    PVOID outputBuffer = NULL;
    /* Receive the actual WDF output length. */
    size_t actualOutputLength = 0U;
    /* Require the complete fixed capability response. */
    status = WdfRequestRetrieveOutputBuffer(
        Request,
        sizeof(KSWORD_ARK_QUERY_RAW_DISK_BACKEND_RESPONSE),
        &outputBuffer,
        &actualOutputLength);

    /* Reject an undersized response buffer. */
    if (!NT_SUCCESS(status)
        || actualOutputLength < sizeof(KSWORD_ARK_QUERY_RAW_DISK_BACKEND_RESPONSE)) {
        /* Preserve the WDF retrieval status. */
        return NT_SUCCESS(status) ? STATUS_BUFFER_TOO_SMALL : status;
    }

    /* Execute the read-only capability query. */
    status = KswordARKStorageQueryRawDiskBackend(
        &requestSnapshot,
        (KSWORD_ARK_QUERY_RAW_DISK_BACKEND_RESPONSE*)outputBuffer);
    /* Return the initialized response even when the selected backend is unavailable. */
    *BytesReturned = sizeof(KSWORD_ARK_QUERY_RAW_DISK_BACKEND_RESPONSE);
    /* Propagate the feature result. */
    return status;
}

NTSTATUS
KswordARKStorageIoctlReadRawDisk(
    _In_ WDFDEVICE Device,
    _In_ WDFREQUEST Request,
    _In_ size_t InputBufferLength,
    _In_ size_t OutputBufferLength,
    _Out_ size_t* BytesReturned
    )
/*++

Routine Description:

    Validates and forwards one bounded raw-disk read request.

--*/
{
    /* This read-only handler does not require the WDF device after dispatch. */
    UNREFERENCED_PARAMETER(Device);

    /* Reject a missing completion-count pointer. */
    if (BytesReturned == NULL) {
        /* The handler contract was invalid. */
        return STATUS_INVALID_PARAMETER;
    }

    /* Clear the completion count for every failure path. */
    *BytesReturned = 0U;
    /* Retrieve the fixed read request. */
    PVOID inputBuffer = NULL;
    /* Receive the actual WDF input length. */
    size_t actualInputLength = 0U;
    /* Require the complete fixed read request. */
    NTSTATUS status = WdfRequestRetrieveInputBuffer(
        Request,
        sizeof(KSWORD_ARK_RAW_DISK_READ_REQUEST),
        &inputBuffer,
        &actualInputLength);

    /* Reject missing or truncated input before parsing fields. */
    if (!NT_SUCCESS(status)
        || InputBufferLength < sizeof(KSWORD_ARK_RAW_DISK_READ_REQUEST)
        || actualInputLength < sizeof(KSWORD_ARK_RAW_DISK_READ_REQUEST)) {
        /* Preserve the WDF failure or normalize a dispatcher length mismatch. */
        return NT_SUCCESS(status) ? STATUS_INFO_LENGTH_MISMATCH : status;
    }

    /* Snapshot input before METHOD_BUFFERED response initialization can erase it. */
    KSWORD_ARK_RAW_DISK_READ_REQUEST requestSnapshot;
    /* Preserve every fixed read field in independent stack storage. */
    RtlCopyMemory(&requestSnapshot, inputBuffer, sizeof(requestSnapshot));

    /* Retrieve at least the fixed variable-response header. */
    PVOID outputBuffer = NULL;
    /* Receive the actual WDF output length. */
    size_t actualOutputLength = 0U;
    /* Require enough output bytes for stable error reporting. */
    status = WdfRequestRetrieveOutputBuffer(
        Request,
        KSWORD_ARK_RAW_DISK_READ_RESPONSE_HEADER_SIZE,
        &outputBuffer,
        &actualOutputLength);

    /* Reject a missing response header. */
    if (!NT_SUCCESS(status)
        || actualOutputLength < KSWORD_ARK_RAW_DISK_READ_RESPONSE_HEADER_SIZE
        || OutputBufferLength < KSWORD_ARK_RAW_DISK_READ_RESPONSE_HEADER_SIZE) {
        /* Preserve the WDF failure or normalize a dispatcher length mismatch. */
        return NT_SUCCESS(status) ? STATUS_BUFFER_TOO_SMALL : status;
    }

    /* Execute the selected bounded read backend. */
    return KswordARKStorageReadRawDisk(
        &requestSnapshot,
        outputBuffer,
        actualOutputLength,
        BytesReturned);
}

NTSTATUS
KswordARKStorageIoctlWriteRawDisk(
    _In_ WDFDEVICE Device,
    _In_ WDFREQUEST Request,
    _In_ size_t InputBufferLength,
    _In_ size_t OutputBufferLength,
    _Out_ size_t* BytesReturned
    )
/*++

Routine Description:

    Validates a variable raw-disk write packet, evaluates the central safety
    policy, and only then invokes the storage backend.

--*/
{
    /* The dispatcher-provided output length is revalidated by WDF retrieval. */
    UNREFERENCED_PARAMETER(OutputBufferLength);

    /* Reject a missing completion-count pointer. */
    if (BytesReturned == NULL) {
        /* The handler contract was invalid. */
        return STATUS_INVALID_PARAMETER;
    }

    /* Clear the completion count for every failure path. */
    *BytesReturned = 0U;
    /* Retrieve at least the variable write request header. */
    PVOID inputBuffer = NULL;
    /* Receive the actual WDF input length. */
    size_t actualInputLength = 0U;
    /* Require enough input bytes to validate the variable payload. */
    NTSTATUS status = WdfRequestRetrieveInputBuffer(
        Request,
        KSWORD_ARK_RAW_DISK_WRITE_REQUEST_HEADER_SIZE,
        &inputBuffer,
        &actualInputLength);

    /* Reject missing or truncated input before parsing fields. */
    if (!NT_SUCCESS(status)
        || InputBufferLength < KSWORD_ARK_RAW_DISK_WRITE_REQUEST_HEADER_SIZE
        || actualInputLength < KSWORD_ARK_RAW_DISK_WRITE_REQUEST_HEADER_SIZE) {
        /* Preserve the WDF failure or normalize a dispatcher length mismatch. */
        return NT_SUCCESS(status) ? STATUS_INFO_LENGTH_MISMATCH : status;
    }

    /* Initialize a fixed header snapshot without reading the variable payload. */
    KSWORD_ARK_RAW_DISK_WRITE_REQUEST writeHeaderSnapshot = { 0 };
    /* Preserve the complete fixed header before any aliased response write. */
    RtlCopyMemory(
        &writeHeaderSnapshot,
        inputBuffer,
        KSWORD_ARK_RAW_DISK_WRITE_REQUEST_HEADER_SIZE);
    /* Compute the exact header-plus-payload snapshot size after bounded validation. */
    size_t writeRequestBytes = KSWORD_ARK_RAW_DISK_WRITE_REQUEST_HEADER_SIZE;

    /* Reject an empty or protocol-oversized raw-disk write payload. */
    if (writeHeaderSnapshot.length == 0U
        || writeHeaderSnapshot.length > KSWORD_ARK_RAW_DISK_MAX_TRANSFER_BYTES) {
        /* The caller declared an invalid transfer size. */
        return STATUS_INVALID_PARAMETER;
    }

    /* Reject a payload that extends beyond either validated input extent. */
    if ((size_t)writeHeaderSnapshot.length
            > actualInputLength - KSWORD_ARK_RAW_DISK_WRITE_REQUEST_HEADER_SIZE
        || (size_t)writeHeaderSnapshot.length
            > InputBufferLength - KSWORD_ARK_RAW_DISK_WRITE_REQUEST_HEADER_SIZE) {
        /* The variable payload cannot be copied safely. */
        return STATUS_INFO_LENGTH_MISMATCH;
    }

    /* Add the already bounded payload length to the fixed header size. */
    writeRequestBytes += (size_t)writeHeaderSnapshot.length;

    /* Require the protocol size field to cover the complete payload. */
    if ((size_t)writeHeaderSnapshot.size < writeRequestBytes
        || (size_t)writeHeaderSnapshot.size > actualInputLength
        || (size_t)writeHeaderSnapshot.size > InputBufferLength) {
        /* The caller's advertised packet extent is inconsistent. */
        return STATUS_INFO_LENGTH_MISMATCH;
    }

    /* Retrieve the fixed write response. */
    PVOID outputBuffer = NULL;
    /* Receive the actual WDF output length. */
    size_t actualOutputLength = 0U;
    /* Require the complete write result. */
    status = WdfRequestRetrieveOutputBuffer(
        Request,
        sizeof(KSWORD_ARK_RAW_DISK_WRITE_RESPONSE),
        &outputBuffer,
        &actualOutputLength);

    /* Reject an undersized response buffer. */
    if (!NT_SUCCESS(status)
        || actualOutputLength < sizeof(KSWORD_ARK_RAW_DISK_WRITE_RESPONSE)) {
        /* Preserve the WDF retrieval status. */
        return NT_SUCCESS(status) ? STATUS_BUFFER_TOO_SMALL : status;
    }

    /* Allocate an independent snapshot because METHOD_BUFFERED aliases output and input. */
    PKSWORD_ARK_RAW_DISK_WRITE_REQUEST writeRequest =
        (PKSWORD_ARK_RAW_DISK_WRITE_REQUEST)KswordARKAllocateNonPagedPool(
            writeRequestBytes,
            KSW_STORAGE_FORENSICS_IOCTL_POOL_TAG);

    /* Stop before policy evaluation when the bounded snapshot cannot be allocated. */
    if (writeRequest == NULL) {
        /* Report the allocation failure without touching the aliased system buffer. */
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    /* Preserve the exact fixed header and payload before initializing any response. */
    RtlCopyMemory(writeRequest, inputBuffer, writeRequestBytes);
    /* Initialize the central safety context for a critical raw-disk mutation. */
    KSWORD_ARK_SAFETY_CONTEXT safetyContext = { 0 };
    /* Select the dedicated policy operation. */
    safetyContext.Operation = KSWORD_ARK_SAFETY_OPERATION_RAW_DISK_WRITE;
    /* Forward only the explicit UI confirmation bit. */
    safetyContext.ContextFlags =
        (writeRequest->flags & KSWORD_ARK_RAW_DISK_FLAG_UI_CONFIRMED_WRITE) != 0U
        ? KSWORD_ARK_SAFETY_CONTEXT_FLAG_UI_CONFIRMED
        : 0U;
    /* Use the physical-disk path shape as a bounded audit target. */
    WCHAR targetText[KSWORD_ARK_SAFETY_TEXT_MAX_CHARS] = { 0 };
    /* Format disk, backend, offset, and length for the policy audit stream. */
    (void)RtlStringCchPrintfW(
        targetText,
        RTL_NUMBER_OF(targetText),
        L"PhysicalDrive%lu backend=%lu offset=0x%I64X length=%lu",
        writeRequest->diskNumber,
        writeRequest->backend,
        writeRequest->offset,
        writeRequest->length);
    /* Attach the bounded audit text to the safety context. */
    safetyContext.TargetText = targetText;
    /* Measure the bounded audit target using the kernel string helper. */
    size_t targetTextChars = 0U;
    /* The formatted local buffer is guaranteed to be terminated. */
    (void)RtlStringCchLengthW(
        targetText,
        RTL_NUMBER_OF(targetText),
        &targetTextChars);
    /* Publish the bounded character count without the terminator. */
    safetyContext.TargetTextChars = (USHORT)targetTextChars;
    /* Ask the central policy to authorize this critical mutation. */
    status = KswordARKSafetyEvaluate(Device, &safetyContext);

    /* Stop before opening the disk when policy denies the operation. */
    if (!NT_SUCCESS(status)) {
        /* Initialize a complete denied response for the user-mode client. */
        PKSWORD_ARK_RAW_DISK_WRITE_RESPONSE response =
            (PKSWORD_ARK_RAW_DISK_WRITE_RESPONSE)outputBuffer;
        /* Clear all fixed response fields. */
        RtlZeroMemory(response, sizeof(*response));
        /* Publish the current protocol version. */
        response->version = KSWORD_ARK_STORAGE_FORENSICS_PROTOCOL_VERSION;
        /* Publish the fixed response size. */
        response->size = sizeof(*response);
        /* Report the stable access-denied protocol status. */
        response->status = KSWORD_ARK_RAW_DISK_STATUS_ACCESS_DENIED;
        /* Echo the selected backend. */
        response->backendUsed = writeRequest->backend;
        /* Preserve the central policy status. */
        response->lastStatus = status;
        /* Return the complete fixed denied response. */
        *BytesReturned = sizeof(*response);
        /* Release the independent request snapshot before returning. */
        ExFreePoolWithTag(writeRequest, KSW_STORAGE_FORENSICS_IOCTL_POOL_TAG);
        /* Propagate the central policy decision. */
        return status;
    }

    /* Execute the safety-authorized raw-disk write. */
    status = KswordARKStorageWriteRawDisk(
        writeRequest,
        writeRequestBytes,
        (KSWORD_ARK_RAW_DISK_WRITE_RESPONSE*)outputBuffer);
    /* The feature always initializes the complete fixed response. */
    *BytesReturned = sizeof(KSWORD_ARK_RAW_DISK_WRITE_RESPONSE);
    /* Release the independent request snapshot after the backend returns. */
    ExFreePoolWithTag(writeRequest, KSW_STORAGE_FORENSICS_IOCTL_POOL_TAG);
    /* Propagate the backend completion status. */
    return status;
}
