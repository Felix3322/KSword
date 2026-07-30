/*++

Module Name:

    driver_blind_ioctl.c

Abstract:

    IOCTL boundary for reversible DriverObject communication blocking.

Environment:

    Kernel-mode Driver Framework

--*/

#include "ark/ark_driver.h"
#include "../../dispatch/ioctl_validation.h"

#include <ntstrsafe.h>

/* 中文说明：记录一次通信控制结果，日志失败不改变 IOCTL 的真实状态。 */
static VOID
KswordARKDriverCommunicationLogResult(
    _In_ WDFDEVICE Device,
    _In_ const KSWORD_ARK_DRIVER_COMMUNICATION_RESPONSE* Response
    )
{
    CHAR logMessage[KSWORD_ARK_LOG_ENTRY_MAX_BYTES] = { 0 };
    NTSTATUS formatStatus = STATUS_SUCCESS;

    /* 中文说明：防御空响应，避免诊断路径影响控制路径。 */
    if (Response == NULL) {
        /* 中文说明：缺少响应时没有可安全记录的字段。 */
        return;
    }

    /* 中文说明：只记录地址、动作、状态和 mask，不记录用户提供的显示文本。 */
    formatStatus = RtlStringCbPrintfA(
        logMessage,
        sizeof(logMessage),
        "R0 driver-communication: action=%lu state=%lu status=0x%08X "
        "target=0x%I64X changed=0x%08X active=0x%08X owned=0x%08X "
        "conflict=0x%08X generation=%lu.",
        (unsigned long)Response->action,
        (unsigned long)Response->state,
        (unsigned int)Response->lastStatus,
        Response->driverStart,
        (unsigned int)Response->changedMask,
        (unsigned int)Response->activeMask,
        (unsigned int)Response->ownedMask,
        (unsigned int)Response->conflictMask,
        (unsigned long)Response->generation);
    /* 中文说明：格式化成功后把结果送入现有 R0 日志通道。 */
    if (NT_SUCCESS(formatStatus)) {
        /* 中文说明：失败结果使用 Warn，成功结果使用 Info。 */
        (VOID)KswordARKDriverEnqueueLogFrame(
            Device,
            NT_SUCCESS((NTSTATUS)Response->lastStatus) ? "Info" : "Warn",
            logMessage);
    }
}

/* 中文说明：固定显示名必须在数组边界内终止，防止 safety policy 越界读取。 */
static BOOLEAN
KswordARKDriverCommunicationHasTerminatedName(
    _In_reads_(KSWORD_ARK_DRIVER_OBJECT_NAME_CHARS) const WCHAR* DriverName
    )
{
    ULONG nameIndex = 0UL;

    /* 中文说明：固定请求布局保证指针有效，仍保留空指针防御。 */
    if (DriverName == NULL) {
        /* 中文说明：空指针不能作为安全策略目标文本。 */
        return FALSE;
    }

    /* 中文说明：在固定数组内查找首个 NUL，不调用无界字符串函数。 */
    for (nameIndex = 0UL;
        nameIndex < KSWORD_ARK_DRIVER_OBJECT_NAME_CHARS;
        ++nameIndex) {
        /* 中文说明：空显示名和正常终止名称都视为边界安全。 */
        if (DriverName[nameIndex] == L'\0') {
            /* 中文说明：找到终止符后允许后续语义检查。 */
            return TRUE;
        }
    }

    /* 中文说明：数组内无终止符时拒绝整个请求。 */
    return FALSE;
}

NTSTATUS
KswordARKKernelIoctlControlDriverCommunication(
    _In_ WDFDEVICE Device,
    _In_ WDFREQUEST Request,
    _In_ size_t InputBufferLength,
    _In_ size_t OutputBufferLength,
    _Out_ size_t* BytesReturned
    )
/*++

Routine Description:

    Validates the fixed v1 request, applies the BLIND safety gate, and invokes
    the transactional DriverObject backend. QUERY and RESTORE intentionally
    bypass the mutation safety gate so recovery remains available.

Arguments:

    Device - WDF device used by safety policy and logging.
    Request - Current METHOD_BUFFERED request.
    InputBufferLength - Dispatcher-reported input length.
    OutputBufferLength - Dispatcher-reported output length.
    BytesReturned - Receives the fixed response size after output retrieval.

Return Value:

    Validation, safety-policy, or backend NTSTATUS.

--*/
{
    KSWORD_ARK_DRIVER_COMMUNICATION_REQUEST* requestBuffer = NULL;
    KSWORD_ARK_DRIVER_COMMUNICATION_RESPONSE* responseBuffer = NULL;
    KSWORD_ARK_DRIVER_COMMUNICATION_REQUEST requestSnapshot;
    size_t actualInputLength = 0U;
    size_t actualOutputLength = 0U;
    NTSTATUS status = STATUS_SUCCESS;

    /* 中文说明：实际长度由统一 WDF helper 校验，这两个分发参数仅保持 handler ABI。 */
    UNREFERENCED_PARAMETER(InputBufferLength);
    /* 中文说明：输出长度同样由 WDF buffer helper 取得权威值。 */
    UNREFERENCED_PARAMETER(OutputBufferLength);

    /* 中文说明：无返回长度指针时不能安全完成请求。 */
    if (BytesReturned == NULL) {
        /* 中文说明：返回固定参数错误且不触碰任何状态。 */
        return STATUS_INVALID_PARAMETER;
    }
    /* 中文说明：取得输出缓冲前默认不返回数据。 */
    *BytesReturned = 0U;
    /* 中文说明：通信控制后端和 FAST_MUTEX 只允许 PASSIVE_LEVEL。 */
    if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
        /* 中文说明：错误 IRQL 不尝试 WDF buffer 或对象目录操作。 */
        return STATUS_INVALID_DEVICE_STATE;
    }
    /* 中文说明：即使 QUERY/RESTORE 也要求用写权限打开设备。 */
    status = KswordARKValidateDeviceIoControlWriteAccess(Request);
    /* 中文说明：访问校验失败时不泄露目标状态。 */
    if (!NT_SUCCESS(status)) {
        /* 中文说明：把访问拒绝直接交给框架完成。 */
        return status;
    }

    /* 中文说明：先取得 METHOD_BUFFERED 输入并复制，避免清零输出覆盖同一系统缓冲。 */
    status = KswordARKRetrieveRequiredInputBuffer(
        Request,
        sizeof(requestSnapshot),
        (PVOID*)&requestBuffer,
        &actualInputLength);
    /* 中文说明：固定请求不完整时拒绝执行。 */
    if (!NT_SUCCESS(status)) {
        /* 中文说明：保留统一 helper 的精确长度错误。 */
        return status;
    }
    /* 中文说明：把不可信共享缓冲复制到栈上形成稳定快照。 */
    RtlCopyMemory(
        &requestSnapshot,
        requestBuffer,
        sizeof(requestSnapshot));

    /* 中文说明：取得可容纳完整固定响应的 METHOD_BUFFERED 输出。 */
    status = KswordARKRetrieveRequiredOutputBuffer(
        Request,
        sizeof(*responseBuffer),
        (PVOID*)&responseBuffer,
        &actualOutputLength);
    /* 中文说明：输出不足时不能返回可解释状态。 */
    if (!NT_SUCCESS(status)) {
        /* 中文说明：不执行任何目标修改。 */
        return status;
    }
    /* 中文说明：输出缓冲取得后立即清零，防止泄露先前系统缓冲内容。 */
    RtlZeroMemory(responseBuffer, sizeof(*responseBuffer));
    /* 中文说明：所有后续失败都返回一个完整 v1 响应。 */
    responseBuffer->version =
        KSWORD_ARK_DRIVER_COMMUNICATION_PROTOCOL_VERSION;
    /* 中文说明：回显 action 便于 R3 关联操作。 */
    responseBuffer->action = requestSnapshot.action;
    /* 中文说明：固定实现始终只针对公开的五个通信入口。 */
    responseBuffer->targetedMask =
        KSWORD_ARK_DRIVER_COMMUNICATION_MAJOR_MASK_ALL;
    /* 中文说明：固定响应已经初始化，后续路径均可报告其大小。 */
    *BytesReturned = sizeof(*responseBuffer);

    /* 中文说明：名称必须终止；QUERY/RESTORE 可空，BLIND 后端再校验证据身份。 */
    if (!KswordARKDriverCommunicationHasTerminatedName(
        requestSnapshot.driverName)) {
        /* 中文说明：记录稳定参数错误供 R3 展示。 */
        responseBuffer->lastStatus = STATUS_INVALID_PARAMETER;
        /* 中文说明：不让 safety policy 读取未终止名称。 */
        return STATUS_INVALID_PARAMETER;
    }

    /* 中文说明：只有 BLIND 是高风险 mutation，需要中央 safety gate。 */
    if (requestSnapshot.action ==
        KSWORD_ARK_DRIVER_COMMUNICATION_ACTION_BLIND) {
        KSWORD_ARK_SAFETY_CONTEXT safetyContext;
        static const WCHAR fallbackTarget[] = L"DriverObject MajorFunction";

        /* 中文说明：高风险动作必须由 UI 明确二次确认。 */
        if ((requestSnapshot.flags &
            KSWORD_ARK_DRIVER_COMMUNICATION_FLAG_UI_CONFIRMED) == 0UL) {
            /* 中文说明：缺少确认时返回固定参数错误，不把它降级为 legacy 请求。 */
            responseBuffer->lastStatus = STATUS_INVALID_PARAMETER;
            /* 中文说明：按 lastStatus 记录缺少 UI 确认的业务拒绝。 */
            KswordARKDriverCommunicationLogResult(Device, responseBuffer);
            /* 中文说明：完整业务响应已形成，以 transport success 交给 R3 展示。 */
            return STATUS_SUCCESS;
        }

        /* 中文说明：清零 safety 上下文以固定未来扩展字段。 */
        RtlZeroMemory(&safetyContext, sizeof(safetyContext));
        /* 中文说明：MajorFunction 替换归类为 kernel patch。 */
        safetyContext.Operation = KSWORD_ARK_SAFETY_OPERATION_KERNEL_PATCH;
        /* 中文说明：把请求中的明确确认映射到统一 safety flag。 */
        safetyContext.ContextFlags =
            KSWORD_ARK_SAFETY_CONTEXT_FLAG_UI_CONFIRMED;
        /* 中文说明：把 BLIND 证据规范名同时用于安全策略审计文本。 */
        safetyContext.TargetText =
            requestSnapshot.driverName[0] != L'\0'
            ? requestSnapshot.driverName
            : fallbackTarget;
        /* 中文说明：固定上限避免 safety policy 进行无界读取。 */
        safetyContext.TargetTextChars =
            requestSnapshot.driverName[0] != L'\0'
            ? (USHORT)KSWORD_ARK_DRIVER_OBJECT_NAME_CHARS
            : (USHORT)(RTL_NUMBER_OF(fallbackTarget) - 1U);
        /* 中文说明：中央策略负责高级模式、操作开关和确认要求。 */
        status = KswordARKSafetyEvaluate(Device, &safetyContext);
        /* 中文说明：策略拒绝时保持目标 dispatch 表完全不变。 */
        if (!NT_SUCCESS(status)) {
            /* 中文说明：把策略状态写入固定响应。 */
            responseBuffer->lastStatus = status;
            /* 中文说明：记录一次被拒绝的控制结果。 */
            KswordARKDriverCommunicationLogResult(Device, responseBuffer);
            /* 中文说明：业务拒绝位于 lastStatus，transport 成功保证 R3 能读取响应。 */
            return STATUS_SUCCESS;
        }
    }

    /* 中文说明：后端再次校验协议字段并执行 QUERY/BLIND/RESTORE 状态机。 */
    status = KswordARKDriverControlCommunication(
        &requestSnapshot,
        responseBuffer);
    /* 中文说明：证据页会批量 QUERY；成功 inactive 不写日志，避免轮询淹没真实事件。 */
    if (requestSnapshot.action != KSWORD_ARK_DRIVER_COMMUNICATION_ACTION_QUERY ||
        responseBuffer->state != KSWORD_ARK_DRIVER_COMMUNICATION_STATE_INACTIVE ||
        !NT_SUCCESS((NTSTATUS)responseBuffer->lastStatus)) {
        /* 中文说明：失败、BLIND/RESTORE 以及 ACTIVE/CONFLICT 查询仍保留完整审计。 */
        KswordARKDriverCommunicationLogResult(Device, responseBuffer);
    }
    /* 中文说明：后端业务状态保存在 lastStatus，固定响应形成后统一 transport success。 */
    return STATUS_SUCCESS;
}
