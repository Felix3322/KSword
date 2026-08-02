/*++

Module Name:

    driver_image_editor_ioctl.c

Abstract:

    IOCTL boundary for unrestricted DriverObject image-field and loaded-module
    list transactions.

Environment:

    Kernel-mode Driver Framework, PASSIVE_LEVEL control path.

--*/

#include "ark/ark_driver.h"
#include "../../dispatch/ioctl_validation.h"

#include <ntstrsafe.h>

// 中文说明：每次查询/修改/恢复/放弃都写审计帧，日志只告警而不改变目标策略。
static VOID
KswordARKDriverImageLogResult(
    _In_ WDFDEVICE Device,
    _In_ const KSWORD_ARK_DRIVER_IMAGE_RESPONSE* Response
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
        "R0 driver-image: action=%lu status=0x%08X object=0x%I64X "
        "start=0x%I64X size=0x%I64X section=0x%I64X "
        "kldrBase=0x%I64X kldrSize=0x%I64X loader=0x%I64X "
        "link=0x%I64X generation=%lu managed=0x%02X owned=0x%02X "
        "conflict=0x%02X flags=0x%08X loaderStatus=0x%08X.",
        (unsigned long)Response->action,
        (unsigned int)Response->lastStatus,
        Response->driverObjectAddress,
        Response->currentValues.driverStart,
        Response->currentValues.driverSize,
        Response->currentValues.driverSection,
        Response->currentValues.kldrDllBase,
        Response->currentValues.kldrSizeOfImage,
        Response->loaderEntryAddress,
        Response->loaderLinkAddress,
        (unsigned long)Response->generation,
        (unsigned int)Response->managedFieldMask,
        (unsigned int)Response->ownedFieldMask,
        (unsigned int)Response->conflictFieldMask,
        (unsigned int)Response->responseFlags,
        (unsigned int)Response->loaderStatus);
    if (NT_SUCCESS(status)) {
        (VOID)KswordARKDriverEnqueueLogFrame(
            Device,
            NT_SUCCESS((NTSTATUS)Response->lastStatus) ? "Warn" : "Error",
            message);
    }
}

// 中文说明：METHOD_BUFFERED 边界先复制输入快照，再写固定尺寸响应，避免同缓冲区别名。
NTSTATUS
KswordARKKernelIoctlControlDriverImage(
    _In_ WDFDEVICE Device,
    _In_ WDFREQUEST Request,
    _In_ size_t InputBufferLength,
    _In_ size_t OutputBufferLength,
    _Out_ size_t* BytesReturned
    )
{
    KSWORD_ARK_DRIVER_IMAGE_REQUEST* inputBuffer = NULL;
    KSWORD_ARK_DRIVER_IMAGE_RESPONSE* outputBuffer = NULL;
    KSWORD_ARK_DRIVER_IMAGE_REQUEST requestSnapshot;
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

    // 中文说明：FILE_WRITE_ACCESS 仍在 WDF 请求边界复核，拒绝只读设备句柄发起修改协议。
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
    RtlCopyMemory(
        &requestSnapshot,
        inputBuffer,
        sizeof(requestSnapshot));

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

    // 中文说明：业务状态始终封装在响应中，IOCTL 传输成功便允许 R3 读取完整冲突诊断。
    status = KswordARKDriverControlImage(
        &requestSnapshot,
        outputBuffer);
    KswordARKDriverImageLogResult(Device, outputBuffer);
    UNREFERENCED_PARAMETER(status);
    return STATUS_SUCCESS;
}
