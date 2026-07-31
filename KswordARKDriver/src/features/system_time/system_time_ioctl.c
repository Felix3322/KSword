/*++

Module Name:

    system_time_ioctl.c

Abstract:

    系统全局变速的 WDF 查询与高风险控制适配器。

Environment:

    Kernel-mode Driver Framework.

--*/

#include "ark/ark_driver.h"
#include "ark/ark_system_time.h"
#include "../../dispatch/ioctl_validation.h"

/* 查询适配器只读取版本化固定请求，并返回当前虚拟计时状态。 */
NTSTATUS
KswordARKSystemTimeIoctlQuery(
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
    const KSWORD_ARK_QUERY_SYSTEM_TIME_REQUEST* queryRequest = NULL;
    NTSTATUS status = STATUS_SUCCESS;

    UNREFERENCED_PARAMETER(Device);
    if (BytesReturned == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *BytesReturned = 0U;

    /* 固定请求仍要求显式 version/size，防止新旧 R3 静默错读。 */
    status = WdfRequestRetrieveInputBuffer(
        Request,
        sizeof(KSWORD_ARK_QUERY_SYSTEM_TIME_REQUEST),
        &inputBuffer,
        &actualInputLength);
    if (!NT_SUCCESS(status) ||
        InputBufferLength <
            sizeof(KSWORD_ARK_QUERY_SYSTEM_TIME_REQUEST) ||
        actualInputLength <
            sizeof(KSWORD_ARK_QUERY_SYSTEM_TIME_REQUEST)) {
        return NT_SUCCESS(status)
            ? STATUS_INFO_LENGTH_MISMATCH
            : status;
    }
    queryRequest =
        (const KSWORD_ARK_QUERY_SYSTEM_TIME_REQUEST*)inputBuffer;
    if (queryRequest->version !=
            KSWORD_ARK_SYSTEM_TIME_PROTOCOL_VERSION ||
        queryRequest->size != sizeof(*queryRequest)) {
        return STATUS_REVISION_MISMATCH;
    }

    /* 输出缓冲区必须完整容纳全部状态与解析证据。 */
    status = WdfRequestRetrieveOutputBuffer(
        Request,
        sizeof(KSWORD_ARK_QUERY_SYSTEM_TIME_RESPONSE),
        &outputBuffer,
        &actualOutputLength);
    if (!NT_SUCCESS(status) ||
        OutputBufferLength <
            sizeof(KSWORD_ARK_QUERY_SYSTEM_TIME_RESPONSE) ||
        actualOutputLength <
            sizeof(KSWORD_ARK_QUERY_SYSTEM_TIME_RESPONSE)) {
        return NT_SUCCESS(status)
            ? STATUS_BUFFER_TOO_SMALL
            : status;
    }

    status = KswordARKSystemTimeQuery(
        (KSWORD_ARK_QUERY_SYSTEM_TIME_RESPONSE*)outputBuffer);
    if (NT_SUCCESS(status)) {
        *BytesReturned =
            sizeof(KSWORD_ARK_QUERY_SYSTEM_TIME_RESPONSE);
    }
    return status;
}

/*
 * 控制适配器先验证写权限与固定缓冲，再进入中央高危内核补丁策略。
 * RESET 是恢复动作，不要求风险策略再次授权。
 */
NTSTATUS
KswordARKSystemTimeIoctlControl(
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
    const KSWORD_ARK_CONTROL_SYSTEM_TIME_REQUEST* controlRequest = NULL;
    KSWORD_ARK_CONTROL_SYSTEM_TIME_REQUEST controlRequestSnapshot = { 0 };
    KSWORD_ARK_CONTROL_SYSTEM_TIME_RESPONSE* controlResponse = NULL;
    NTSTATUS status = STATUS_SUCCESS;

    if (BytesReturned == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *BytesReturned = 0U;

    /* 变速控制只能从具有 GENERIC_WRITE 的 KswordARK 设备句柄发出。 */
    status = KswordARKValidateDeviceIoControlWriteAccess(Request);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = WdfRequestRetrieveInputBuffer(
        Request,
        sizeof(KSWORD_ARK_CONTROL_SYSTEM_TIME_REQUEST),
        &inputBuffer,
        &actualInputLength);
    if (!NT_SUCCESS(status) ||
        InputBufferLength <
            sizeof(KSWORD_ARK_CONTROL_SYSTEM_TIME_REQUEST) ||
        actualInputLength <
            sizeof(KSWORD_ARK_CONTROL_SYSTEM_TIME_REQUEST)) {
        return NT_SUCCESS(status)
            ? STATUS_INFO_LENGTH_MISMATCH
            : status;
    }

    status = WdfRequestRetrieveOutputBuffer(
        Request,
        sizeof(KSWORD_ARK_CONTROL_SYSTEM_TIME_RESPONSE),
        &outputBuffer,
        &actualOutputLength);
    if (!NT_SUCCESS(status) ||
        OutputBufferLength <
            sizeof(KSWORD_ARK_CONTROL_SYSTEM_TIME_RESPONSE) ||
        actualOutputLength <
            sizeof(KSWORD_ARK_CONTROL_SYSTEM_TIME_RESPONSE)) {
        return NT_SUCCESS(status)
            ? STATUS_BUFFER_TOO_SMALL
            : status;
    }

    controlRequest =
        (const KSWORD_ARK_CONTROL_SYSTEM_TIME_REQUEST*)inputBuffer;
    controlResponse =
        (KSWORD_ARK_CONTROL_SYSTEM_TIME_RESPONSE*)outputBuffer;
    if (controlRequest->version !=
            KSWORD_ARK_SYSTEM_TIME_PROTOCOL_VERSION ||
        controlRequest->size != sizeof(*controlRequest)) {
        return STATUS_REVISION_MISMATCH;
    }

    /*
     * METHOD_BUFFERED 的输入和输出可能共用同一个 SystemBuffer。
     * 运行时会先清零响应，因此必须先复制请求，避免响应初始化覆盖请求。
     */
    RtlCopyMemory(
        &controlRequestSnapshot,
        controlRequest,
        sizeof(controlRequestSnapshot));
    controlRequest = &controlRequestSnapshot;

    /*
     * 加速和减速会接管全系统性能计数器，必须进入统一 KERNEL_PATCH
     * 审计；UI_CONFIRMED 同时由协议令牌和中央策略分别验证。
     */
    if (controlRequest->command !=
        KSWORD_ARK_SYSTEM_TIME_COMMAND_RESET) {
        KSWORD_ARK_SAFETY_CONTEXT safetyContext = { 0 };

        safetyContext.Operation =
            KSWORD_ARK_SAFETY_OPERATION_KERNEL_PATCH;
        safetyContext.ContextFlags =
            (controlRequest->flags &
                KSWORD_ARK_SYSTEM_TIME_CONTROL_FLAG_UI_CONFIRMED) != 0UL
            ? KSWORD_ARK_SAFETY_CONTEXT_FLAG_UI_CONFIRMED
            : 0UL;
        safetyContext.TargetText =
            L"System-wide performance-counter time remapping";
        safetyContext.TargetTextChars =
            (USHORT)(RTL_NUMBER_OF(
                L"System-wide performance-counter time remapping") -
                1U);
        status = KswordARKSafetyEvaluate(
            Device,
            &safetyContext);
        if (!NT_SUCCESS(status)) {
            RtlZeroMemory(
                controlResponse,
                sizeof(*controlResponse));
            controlResponse->version =
                KSWORD_ARK_SYSTEM_TIME_PROTOCOL_VERSION;
            controlResponse->size =
                sizeof(*controlResponse);
            controlResponse->status =
                KSWORD_ARK_SYSTEM_TIME_STATUS_CONFIRMATION_REQUIRED;
            controlResponse->lastStatus = status;
            *BytesReturned = sizeof(*controlResponse);
            return status;
        }
    }

    /* 运行时返回稳定业务状态；实际 IOCTL 传输保持固定响应大小。 */
    status = KswordARKSystemTimeControl(
        controlRequest,
        controlResponse);
    *BytesReturned = sizeof(*controlResponse);
    return status;
}
