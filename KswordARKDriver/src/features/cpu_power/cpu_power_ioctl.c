#include <ntddk.h>
#include <wdf.h>

#include "ark/ark_ioctl.h"
#include "ark/ark_safety.h"
#include "../../dispatch/ioctl_validation.h"
#include "cpu_power_runtime.h"

// ============================================================
// cpu_power_ioctl.c
// 作用：
// - 只负责 WDF 缓冲区、安全策略与固定响应长度；
// - 真实 CPUID/MSR 探测和修改位于 cpu_power_runtime.c；
// - 控制路径必须同时经过 FILE_WRITE_ACCESS、UI 确认与安全策略。
// ============================================================

// KswordARKCpuPowerIoctlQuery：返回当前 CPU 电源能力与白名单 MSR 快照。
NTSTATUS
KswordARKCpuPowerIoctlQuery(
    _In_ WDFDEVICE Device,
    _In_ WDFREQUEST Request,
    _In_ size_t InputBufferLength,
    _In_ size_t OutputBufferLength,
    _Out_ size_t* BytesReturned
    )
{
    // response 指向 METHOD_BUFFERED 固定输出包。
    KSWORD_ARK_CPU_POWER_RESPONSE* response = NULL;
    // actualOutputLength 接收 WDF 实际缓冲区长度。
    size_t actualOutputLength = 0U;
    // status 保存缓冲区校验与运行时查询结果。
    NTSTATUS status = STATUS_SUCCESS;

    // 本 handler 不需要设备扩展或输入缓冲区。
    UNREFERENCED_PARAMETER(Device);
    UNREFERENCED_PARAMETER(InputBufferLength);
    UNREFERENCED_PARAMETER(OutputBufferLength);

    // 字节计数输出必须有效且先清零。
    if (BytesReturned == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *BytesReturned = 0U;

    // 取得完整固定响应缓冲区。
    status = KswordARKRetrieveRequiredOutputBuffer(
        Request,
        sizeof(*response),
        (PVOID*)&response,
        &actualOutputLength);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    // 运行时以固定包返回 partial/unsupported 语义。
    status = KswordARKCpuPowerQuerySnapshot(response);
    // 只要响应包已经建立，就向 WDF 报告完整长度。
    *BytesReturned = sizeof(*response);
    return status;
}

// KswordARKCpuPowerIoctlControl：安全门控后执行结构化 CPU 电源控制。
NTSTATUS
KswordARKCpuPowerIoctlControl(
    _In_ WDFDEVICE Device,
    _In_ WDFREQUEST Request,
    _In_ size_t InputBufferLength,
    _In_ size_t OutputBufferLength,
    _Out_ size_t* BytesReturned
    )
{
    // controlRequest 指向完整固定输入包。
    KSWORD_ARK_CPU_POWER_CONTROL_REQUEST* controlRequest = NULL;
    // response 指向固定输出快照。
    KSWORD_ARK_CPU_POWER_RESPONSE* response = NULL;
    // safetyContext 把 UI 确认交给统一 R0 安全策略。
    KSWORD_ARK_SAFETY_CONTEXT safetyContext;
    // actualInputLength/actualOutputLength 接收 WDF 实际长度。
    size_t actualInputLength = 0U;
    size_t actualOutputLength = 0U;
    // status 保存每个门控和运行时结果。
    NTSTATUS status = STATUS_SUCCESS;
    // targetText 是安全审计使用的固定目标说明。
    static const WCHAR targetText[] =
        L"CPU RAPL HWP Turbo power-management MSRs";

    // 长度由统一 retrieval helper 重新验证。
    UNREFERENCED_PARAMETER(InputBufferLength);
    UNREFERENCED_PARAMETER(OutputBufferLength);

    // 字节计数输出必须有效且先清零。
    if (BytesReturned == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *BytesReturned = 0U;

    // 跨处理器 affinity 与 MSR 修改只在 PASSIVE_LEVEL 执行。
    if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
        return STATUS_INVALID_DEVICE_STATE;
    }

    // 取得完整控制请求。
    status = KswordARKRetrieveRequiredInputBuffer(
        Request,
        sizeof(*controlRequest),
        (PVOID*)&controlRequest,
        &actualInputLength);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    // 取得完整固定响应缓冲区。
    status = KswordARKRetrieveRequiredOutputBuffer(
        Request,
        sizeof(*response),
        (PVOID*)&response,
        &actualOutputLength);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    // 先建立最小失败响应，任何门控退出都有版本化语义。
    RtlZeroMemory(response, sizeof(*response));
    response->size = sizeof(*response);
    response->version = KSWORD_ARK_CPU_POWER_PROTOCOL_VERSION;

    // 协议头和 UI 确认在进入通用安全策略前先校验。
    if (controlRequest->size < sizeof(*controlRequest) ||
        controlRequest->version != KSWORD_ARK_CPU_POWER_PROTOCOL_VERSION ||
        (controlRequest->requestFlags &
            KSWORD_ARK_CPU_POWER_REQUEST_FLAG_UI_CONFIRMED) == 0UL) {
        response->failureReason =
            KSWORD_ARK_CPU_POWER_FAILURE_REQUEST_HEADER;
        response->lastStatus = STATUS_INVALID_PARAMETER;
        *BytesReturned = sizeof(*response);
        return STATUS_INVALID_PARAMETER;
    }

    // 构造统一的高风险内核修改安全上下文。
    RtlZeroMemory(&safetyContext, sizeof(safetyContext));
    safetyContext.Operation = KSWORD_ARK_SAFETY_OPERATION_KERNEL_PATCH;
    safetyContext.ContextFlags = KSWORD_ARK_SAFETY_CONTEXT_FLAG_UI_CONFIRMED;
    safetyContext.TargetText = targetText;
    safetyContext.TargetTextChars =
        (USHORT)(RTL_NUMBER_OF(targetText) - 1U);
    // 由设备安全策略统一检查当前调用者与危险功能开关。
    status = KswordARKSafetyEvaluate(Device, &safetyContext);
    if (!NT_SUCCESS(status)) {
        response->failureReason =
            KSWORD_ARK_CPU_POWER_FAILURE_SAFETY_POLICY;
        response->lastStatus = status;
        *BytesReturned = sizeof(*response);
        return status;
    }

    // 运行时执行能力、锁定位、expected snapshot、逐 CPU 写入与回读验证。
    status = KswordARKCpuPowerApply(controlRequest, response);
    // 无论语义成功或失败，固定响应都可供新客户端解释。
    *BytesReturned = sizeof(*response);
    return status;
}
