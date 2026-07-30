/*++

Module Name:

    kernel_unloaded_drivers_ioctl.c

Abstract:

    WDF adapter for the read-only unloaded-driver source query.

--*/

#include "kernel_unloaded_drivers.h"

NTSTATUS
KswordARKKernelIoctlQueryUnloadedDrivers(
    _In_ WDFDEVICE Device,
    _In_ WDFREQUEST Request,
    _In_ size_t InputBufferLength,
    _In_ size_t OutputBufferLength,
    _Out_ size_t* BytesReturned
    )
{
    KSWORD_ARK_QUERY_UNLOADED_DRIVERS_REQUEST requestCopy;
    PVOID inputBuffer = NULL;
    PVOID outputBuffer = NULL;
    size_t actualInputLength = 0U;
    size_t actualOutputLength = 0U;
    NTSTATUS status = STATUS_SUCCESS;

    // 本 IOCTL 没有设备级状态，也不请求写访问。
    UNREFERENCED_PARAMETER(Device);
    if (BytesReturned == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *BytesReturned = 0U;
    RtlZeroMemory(&requestCopy, sizeof(requestCopy));

    // 固定请求头必须完整存在。
    status = WdfRequestRetrieveInputBuffer(
        Request,
        sizeof(KSWORD_ARK_QUERY_UNLOADED_DRIVERS_REQUEST),
        &inputBuffer,
        &actualInputLength);
    if (!NT_SUCCESS(status) ||
        InputBufferLength <
            sizeof(KSWORD_ARK_QUERY_UNLOADED_DRIVERS_REQUEST) ||
        actualInputLength <
            sizeof(KSWORD_ARK_QUERY_UNLOADED_DRIVERS_REQUEST)) {
        return NT_SUCCESS(status) ? STATUS_INFO_LENGTH_MISMATCH : status;
    }

    // METHOD_BUFFERED 的输入/输出可能别名同一 system buffer；后端会先清空
    // 输出区，因此必须在取出/写入输出前保存完整请求，避免 size/source 被抹掉。
    RtlCopyMemory(
        &requestCopy,
        inputBuffer,
        sizeof(requestCopy));

    // 变长输出至少容纳响应头，后端按实际长度计算行容量。
    status = WdfRequestRetrieveOutputBuffer(
        Request,
        KSWORD_ARK_QUERY_UNLOADED_DRIVERS_RESPONSE_HEADER_SIZE,
        &outputBuffer,
        &actualOutputLength);
    if (!NT_SUCCESS(status) ||
        OutputBufferLength <
            KSWORD_ARK_QUERY_UNLOADED_DRIVERS_RESPONSE_HEADER_SIZE ||
        actualOutputLength <
            KSWORD_ARK_QUERY_UNLOADED_DRIVERS_RESPONSE_HEADER_SIZE) {
        return NT_SUCCESS(status) ? STATUS_BUFFER_TOO_SMALL : status;
    }

    return KswordARKQueryUnloadedDrivers(
        &requestCopy,
        (KSWORD_ARK_QUERY_UNLOADED_DRIVERS_RESPONSE*)outputBuffer,
        actualOutputLength,
        BytesReturned);
}
