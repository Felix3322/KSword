/*++

Module Name:

    network_ioctl.c

Abstract:

    IOCTL handlers for KswordARK network filter and port-hide rules.

Environment:

    Kernel-mode Driver Framework

--*/

#include "ark/ark_driver.h"
#include "../../dispatch/ioctl_validation.h"

#include <ntstrsafe.h>
#include <stdarg.h>

static VOID
KswordARKNetworkIoctlLog(
    _In_ WDFDEVICE Device,
    _In_z_ PCSTR LevelText,
    _In_z_ PCSTR FormatText,
    ...
    )
/*++

Routine Description:

    输出网络 IOCTL 日志。中文说明：规则变更属于安全敏感操作，记录状态与规则数
    便于 R3 日志面板审计。

Arguments:

    Device - WDF 设备对象。
    LevelText - 日志级别。
    FormatText - printf 风格格式串。
    ... - 格式化参数。

Return Value:

    None. 本函数没有返回值。

--*/
{
    CHAR logMessage[KSWORD_ARK_LOG_ENTRY_MAX_BYTES] = { 0 };
    va_list arguments;

    va_start(arguments, FormatText);
    if (NT_SUCCESS(RtlStringCbVPrintfA(logMessage, sizeof(logMessage), FormatText, arguments))) {
        (VOID)KswordARKDriverEnqueueLogFrame(Device, LevelText, logMessage);
    }
    va_end(arguments);
}

NTSTATUS
KswordARKNetworkIoctlSetRules(
    _In_ WDFDEVICE Device,
    _In_ WDFREQUEST Request,
    _In_ size_t InputBufferLength,
    _In_ size_t OutputBufferLength,
    _Out_ size_t* BytesReturned
    )
/*++

Routine Description:

    处理 IOCTL_KSWORD_ARK_NETWORK_SET_RULES。中文说明：该 IOCTL 需要写权限，规则
    后端负责完整校验与一次性快照替换。

Arguments:

    Device - WDF 设备对象。
    Request - 当前 WDF 请求。
    InputBufferLength - 输入长度。
    OutputBufferLength - 输出长度。
    BytesReturned - 返回写入字节数。

Return Value:

    NTSTATUS from validation or backend.

--*/
{
    KSWORD_ARK_NETWORK_SET_RULES_REQUEST* setRequest = NULL;
    PVOID outputBuffer = NULL;
    size_t actualOutputLength = 0U;
    NTSTATUS status = STATUS_SUCCESS;

    UNREFERENCED_PARAMETER(InputBufferLength);
    UNREFERENCED_PARAMETER(OutputBufferLength);

    if (BytesReturned == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *BytesReturned = 0U;

    status = KswordARKValidateDeviceIoControlWriteAccess(Request);
    if (!NT_SUCCESS(status)) {
        KswordARKNetworkIoctlLog(Device, "Warn", "R0 network set-rules denied, status=0x%08X.", (unsigned int)status);
        return status;
    }

    status = KswordARKRetrieveRequiredInputBuffer(
        Request,
        sizeof(KSWORD_ARK_NETWORK_SET_RULES_REQUEST),
        (PVOID*)&setRequest,
        NULL);
    if (!NT_SUCCESS(status)) {
        KswordARKNetworkIoctlLog(Device, "Error", "R0 network set-rules input invalid, status=0x%08X.", (unsigned int)status);
        return status;
    }

    status = KswordARKRetrieveRequiredOutputBuffer(
        Request,
        sizeof(KSWORD_ARK_NETWORK_SET_RULES_RESPONSE),
        &outputBuffer,
        &actualOutputLength);
    if (!NT_SUCCESS(status)) {
        KswordARKNetworkIoctlLog(Device, "Error", "R0 network set-rules output invalid, status=0x%08X.", (unsigned int)status);
        return status;
    }

    status = KswordARKNetworkSetRules(
        setRequest,
        outputBuffer,
        actualOutputLength,
        BytesReturned);
    if (NT_SUCCESS(status) && *BytesReturned >= sizeof(KSWORD_ARK_NETWORK_SET_RULES_RESPONSE)) {
        KSWORD_ARK_NETWORK_SET_RULES_RESPONSE* response =
            (KSWORD_ARK_NETWORK_SET_RULES_RESPONSE*)outputBuffer;
        KswordARKNetworkIoctlLog(
            Device,
            response->status == KSWORD_ARK_NETWORK_STATUS_APPLIED ? "Info" : "Warn",
            "R0 network set-rules status=%lu rules=%lu block=%lu hide=%lu last=0x%08X.",
            (unsigned long)response->status,
            (unsigned long)response->appliedCount,
            (unsigned long)response->blockedRuleCount,
            (unsigned long)response->hiddenPortRuleCount,
            (unsigned int)response->lastStatus);
    }

    return status;
}

NTSTATUS
KswordARKNetworkIoctlQueryStatus(
    _In_ WDFDEVICE Device,
    _In_ WDFREQUEST Request,
    _In_ size_t InputBufferLength,
    _In_ size_t OutputBufferLength,
    _Out_ size_t* BytesReturned
    )
/*++

Routine Description:

    处理 IOCTL_KSWORD_ARK_NETWORK_QUERY_STATUS。中文说明：输出固定状态响应，包含
    WFP 注册状态、规则快照和 classify 计数。

Arguments:

    Device - WDF 设备对象。
    Request - 当前 WDF 请求。
    InputBufferLength - 输入长度。
    OutputBufferLength - 输出长度。
    BytesReturned - 返回写入字节数。

Return Value:

    NTSTATUS from buffer retrieval or backend.

--*/
{
    PVOID outputBuffer = NULL;
    size_t actualOutputLength = 0U;
    NTSTATUS status = STATUS_SUCCESS;

    UNREFERENCED_PARAMETER(InputBufferLength);
    UNREFERENCED_PARAMETER(OutputBufferLength);

    if (BytesReturned == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *BytesReturned = 0U;

    status = KswordARKRetrieveRequiredOutputBuffer(
        Request,
        sizeof(KSWORD_ARK_NETWORK_STATUS_RESPONSE),
        &outputBuffer,
        &actualOutputLength);
    if (!NT_SUCCESS(status)) {
        KswordARKNetworkIoctlLog(Device, "Error", "R0 network status output invalid, status=0x%08X.", (unsigned int)status);
        return status;
    }

    status = KswordARKNetworkQueryStatus(
        outputBuffer,
        actualOutputLength,
        BytesReturned);
    if (NT_SUCCESS(status) && *BytesReturned >= sizeof(KSWORD_ARK_NETWORK_STATUS_RESPONSE)) {
        KSWORD_ARK_NETWORK_STATUS_RESPONSE* response =
            (KSWORD_ARK_NETWORK_STATUS_RESPONSE*)outputBuffer;
        KswordARKNetworkIoctlLog(
            Device,
            "Info",
            "R0 network status flags=0x%08X rules=%lu blockedHits=%I64u.",
            (unsigned int)response->runtimeFlags,
            (unsigned long)response->ruleCount,
            (unsigned long long)response->blockedCount);
    }

    return status;
}

static NTSTATUS
KswordARKNetworkIoctlRetrieveAuditBuffers(
    _In_ WDFREQUEST Request,
    _In_ size_t InputBufferLength,
    _In_ size_t RequiredOutputLength,
    _Outptr_result_maybenull_ KSWORD_ARK_NETWORK_AUDIT_QUERY_REQUEST** QueryRequestOut,
    _Outptr_result_bytebuffer_(*ActualOutputLengthOut) PVOID* OutputBufferOut,
    _Out_ size_t* ActualOutputLengthOut
    )
/*++

Routine Description:

    提取网络审计 IOCTL 的可选请求与必需输出缓冲。中文说明：四个只读审计 handler
    共用相同 buffer 规则，避免在每个 handler 中复制 WDF 检索分支。

Arguments:

    Request - 当前 WDF 请求。
    InputBufferLength - dispatch 提供的输入长度。
    RequiredOutputLength - 响应头最小长度。
    QueryRequestOut - 接收可选请求；未提供时返回 NULL。
    OutputBufferOut - 接收输出缓冲。
    ActualOutputLengthOut - 接收输出缓冲实际长度。

Return Value:

    NTSTATUS from shared validation helpers.

--*/
{
    PVOID inputBuffer = NULL;
    size_t actualInputLength = 0U;
    BOOLEAN inputPresent = FALSE;
    NTSTATUS status = STATUS_SUCCESS;

    if (QueryRequestOut == NULL || OutputBufferOut == NULL || ActualOutputLengthOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *QueryRequestOut = NULL;
    *OutputBufferOut = NULL;
    *ActualOutputLengthOut = 0U;

    status = KswordARKRetrieveOptionalInputBuffer(
        Request,
        InputBufferLength,
        sizeof(KSWORD_ARK_NETWORK_AUDIT_QUERY_REQUEST),
        &inputBuffer,
        &actualInputLength,
        &inputPresent);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    if (inputPresent) {
        UNREFERENCED_PARAMETER(actualInputLength);
        *QueryRequestOut = (KSWORD_ARK_NETWORK_AUDIT_QUERY_REQUEST*)inputBuffer;
    }

    return KswordARKRetrieveRequiredOutputBuffer(
        Request,
        RequiredOutputLength,
        OutputBufferOut,
        ActualOutputLengthOut);
}

NTSTATUS
KswordARKNetworkIoctlQueryTcpEndpoints(
    _In_ WDFDEVICE Device,
    _In_ WDFREQUEST Request,
    _In_ size_t InputBufferLength,
    _In_ size_t OutputBufferLength,
    _Out_ size_t* BytesReturned
    )
/*++

Routine Description:

    处理 IOCTL_KSWORD_ARK_NETWORK_QUERY_TCP_ENDPOINTS。中文说明：这是只读审计入口，
    handler 只负责 buffer 检索，TCP 表遍历由 network_audit.c 后端负责。

Arguments:

    Device - WDF 设备对象。
    Request - 当前 WDF 请求。
    InputBufferLength - 输入长度。
    OutputBufferLength - 输出长度。
    BytesReturned - 返回写入字节数。

Return Value:

    NTSTATUS from buffer retrieval or backend.

--*/
{
    KSWORD_ARK_NETWORK_AUDIT_QUERY_REQUEST* queryRequest = NULL;
    PVOID outputBuffer = NULL;
    size_t actualOutputLength = 0U;
    NTSTATUS status = STATUS_SUCCESS;

    UNREFERENCED_PARAMETER(OutputBufferLength);

    if (BytesReturned == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *BytesReturned = 0U;

    status = KswordARKNetworkIoctlRetrieveAuditBuffers(
        Request,
        InputBufferLength,
        sizeof(KSWORD_ARK_NETWORK_ENDPOINT_RESPONSE) - sizeof(KSWORD_ARK_NETWORK_ENDPOINT_ROW),
        &queryRequest,
        &outputBuffer,
        &actualOutputLength);
    if (!NT_SUCCESS(status)) {
        KswordARKNetworkIoctlLog(Device, "Error", "R0 network TCP audit buffer invalid, status=0x%08X.", (unsigned int)status);
        return status;
    }

    status = KswordARKNetworkQueryTcpEndpoints(
        queryRequest,
        outputBuffer,
        actualOutputLength,
        BytesReturned);
    if (NT_SUCCESS(status) && *BytesReturned >= sizeof(KSWORD_ARK_NETWORK_ENDPOINT_RESPONSE) - sizeof(KSWORD_ARK_NETWORK_ENDPOINT_ROW)) {
        KSWORD_ARK_NETWORK_ENDPOINT_RESPONSE* response =
            (KSWORD_ARK_NETWORK_ENDPOINT_RESPONSE*)outputBuffer;
        KswordARKNetworkIoctlLog(Device, "Info", "R0 network TCP audit status=%lu rows=%lu/%lu.", response->status, response->returnedRowCount, response->totalRowCount);
    }

    return status;
}

NTSTATUS
KswordARKNetworkIoctlQueryUdpEndpoints(
    _In_ WDFDEVICE Device,
    _In_ WDFREQUEST Request,
    _In_ size_t InputBufferLength,
    _In_ size_t OutputBufferLength,
    _Out_ size_t* BytesReturned
    )
/*++

Routine Description:

    处理 IOCTL_KSWORD_ARK_NETWORK_QUERY_UDP_ENDPOINTS。中文说明：该入口只读返回 UDP
    endpoint 审计响应，不删除连接也不改变端口隐藏策略。

Arguments:

    Device - WDF 设备对象。
    Request - 当前 WDF 请求。
    InputBufferLength - 输入长度。
    OutputBufferLength - 输出长度。
    BytesReturned - 返回写入字节数。

Return Value:

    NTSTATUS from buffer retrieval or backend.

--*/
{
    KSWORD_ARK_NETWORK_AUDIT_QUERY_REQUEST* queryRequest = NULL;
    PVOID outputBuffer = NULL;
    size_t actualOutputLength = 0U;
    NTSTATUS status = STATUS_SUCCESS;

    UNREFERENCED_PARAMETER(OutputBufferLength);

    if (BytesReturned == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *BytesReturned = 0U;

    status = KswordARKNetworkIoctlRetrieveAuditBuffers(
        Request,
        InputBufferLength,
        sizeof(KSWORD_ARK_NETWORK_ENDPOINT_RESPONSE) - sizeof(KSWORD_ARK_NETWORK_ENDPOINT_ROW),
        &queryRequest,
        &outputBuffer,
        &actualOutputLength);
    if (!NT_SUCCESS(status)) {
        KswordARKNetworkIoctlLog(Device, "Error", "R0 network UDP audit buffer invalid, status=0x%08X.", (unsigned int)status);
        return status;
    }

    status = KswordARKNetworkQueryUdpEndpoints(
        queryRequest,
        outputBuffer,
        actualOutputLength,
        BytesReturned);
    if (NT_SUCCESS(status) && *BytesReturned >= sizeof(KSWORD_ARK_NETWORK_ENDPOINT_RESPONSE) - sizeof(KSWORD_ARK_NETWORK_ENDPOINT_ROW)) {
        KSWORD_ARK_NETWORK_ENDPOINT_RESPONSE* response =
            (KSWORD_ARK_NETWORK_ENDPOINT_RESPONSE*)outputBuffer;
        KswordARKNetworkIoctlLog(Device, "Info", "R0 network UDP audit status=%lu rows=%lu/%lu.", response->status, response->returnedRowCount, response->totalRowCount);
    }

    return status;
}

NTSTATUS
KswordARKNetworkIoctlQueryWfpInventory(
    _In_ WDFDEVICE Device,
    _In_ WDFREQUEST Request,
    _In_ size_t InputBufferLength,
    _In_ size_t OutputBufferLength,
    _Out_ size_t* BytesReturned
    )
/*++

Routine Description:

    处理 IOCTL_KSWORD_ARK_NETWORK_QUERY_WFP_INVENTORY。中文说明：该入口只读返回
    WFP provider/sublayer/filter/callout inventory 骨架，不禁用或删除 WFP 对象。

Arguments:

    Device - WDF 设备对象。
    Request - 当前 WDF 请求。
    InputBufferLength - 输入长度。
    OutputBufferLength - 输出长度。
    BytesReturned - 返回写入字节数。

Return Value:

    NTSTATUS from buffer retrieval or backend.

--*/
{
    KSWORD_ARK_NETWORK_AUDIT_QUERY_REQUEST* queryRequest = NULL;
    PVOID outputBuffer = NULL;
    size_t actualOutputLength = 0U;
    NTSTATUS status = STATUS_SUCCESS;

    UNREFERENCED_PARAMETER(OutputBufferLength);

    if (BytesReturned == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *BytesReturned = 0U;

    status = KswordARKNetworkIoctlRetrieveAuditBuffers(
        Request,
        InputBufferLength,
        sizeof(KSWORD_ARK_NETWORK_WFP_INVENTORY_RESPONSE) - sizeof(KSWORD_ARK_NETWORK_WFP_INVENTORY_ROW),
        &queryRequest,
        &outputBuffer,
        &actualOutputLength);
    if (!NT_SUCCESS(status)) {
        KswordARKNetworkIoctlLog(Device, "Error", "R0 network WFP audit buffer invalid, status=0x%08X.", (unsigned int)status);
        return status;
    }

    status = KswordARKNetworkQueryWfpInventory(
        queryRequest,
        outputBuffer,
        actualOutputLength,
        BytesReturned);
    if (NT_SUCCESS(status) && *BytesReturned >= sizeof(KSWORD_ARK_NETWORK_WFP_INVENTORY_RESPONSE) - sizeof(KSWORD_ARK_NETWORK_WFP_INVENTORY_ROW)) {
        KSWORD_ARK_NETWORK_WFP_INVENTORY_RESPONSE* response =
            (KSWORD_ARK_NETWORK_WFP_INVENTORY_RESPONSE*)outputBuffer;
        KswordARKNetworkIoctlLog(Device, "Info", "R0 network WFP audit status=%lu rows=%lu/%lu.", response->status, response->returnedRowCount, response->totalRowCount);
    }

    return status;
}

NTSTATUS
KswordARKNetworkIoctlQueryWfpEvents(
    _In_ WDFDEVICE Device,
    _In_ WDFREQUEST Request,
    _In_ size_t InputBufferLength,
    _In_ size_t OutputBufferLength,
    _Out_ size_t* BytesReturned
    )
/*++

Routine Description:

    处理 IOCTL_KSWORD_ARK_NETWORK_QUERY_WFP_EVENTS。中文说明：METHOD_BUFFERED 的输入
    与输出可能指向同一 SystemBuffer，因此必须先复制 cursor/maxRows 再写响应。

Arguments:

    Device - WDF 设备对象。
    Request - 当前 WDF 请求。
    InputBufferLength - 输入长度。
    OutputBufferLength - 输出长度。
    BytesReturned - 返回写入字节数。

Return Value:

    NTSTATUS from buffer retrieval or versioned event backend.

--*/
{
    // 中文说明：指向 METHOD_BUFFERED 输入请求，复制后不再使用。
    KSWORD_ARK_NETWORK_WFP_EVENT_QUERY_REQUEST* inputRequest = NULL;
    // 中文说明：局部请求防止输出清零覆盖 afterSequence/maxRows。
    KSWORD_ARK_NETWORK_WFP_EVENT_QUERY_REQUEST localRequest = { 0 };
    // 中文说明：接收 METHOD_BUFFERED 输出 SystemBuffer。
    PVOID outputBuffer = NULL;
    // 中文说明：保存 WDF 返回的实际输入长度，helper 不接受空长度输出参数。
    size_t actualInputLength = 0U;
    // 中文说明：保存 WDF 实际输出缓冲长度。
    size_t actualOutputLength = 0U;
    // 中文说明：保存检索或后端状态。
    NTSTATUS status = STATUS_SUCCESS;
    // 中文说明：事件响应头不含 entries[1] 占位行。
    const size_t responseHeaderSize =
        sizeof(KSWORD_ARK_NETWORK_WFP_EVENT_RESPONSE) -
        sizeof(KSWORD_ARK_NETWORK_WFP_EVENT_ROW);

    // 中文说明：dispatch 的输出长度由 WDF 检索结果再次验证。
    UNREFERENCED_PARAMETER(OutputBufferLength);

    // 中文说明：调用方必须提供返回字节计数。
    if (BytesReturned == NULL) {
        // 中文说明：无法回报完成长度时拒绝请求。
        return STATUS_INVALID_PARAMETER;
    }
    // 中文说明：默认没有输出字节。
    *BytesReturned = 0U;

    // 中文说明：事件查询要求完整版本化输入，旧驱动会在 registry 层拒绝未知 IOCTL。
    status = KswordARKRetrieveRequiredInputBuffer(
        Request,
        sizeof(KSWORD_ARK_NETWORK_WFP_EVENT_QUERY_REQUEST),
        (PVOID*)&inputRequest,
        &actualInputLength);
    // 中文说明：输入检索失败时不访问 SystemBuffer。
    if (!NT_SUCCESS(status)) {
        // 中文说明：只记录失败，不在轮询成功路径制造高频日志。
        KswordARKNetworkIoctlLog(
            Device,
            "Error",
            "R0 WFP event query input invalid, status=0x%08X.",
            (unsigned int)status);
        // 中文说明：把 WDF 检索错误返回 dispatch。
        return status;
    }
    // 中文说明：dispatch 提供的输入长度也必须覆盖稳定请求 ABI。
    if (InputBufferLength < sizeof(localRequest) ||
        actualInputLength < sizeof(localRequest)) {
        // 中文说明：长度不一致时拒绝，避免复制截断请求。
        return STATUS_BUFFER_TOO_SMALL;
    }
    // 中文说明：在任何输出检索或清零前复制 alias 的 METHOD_BUFFERED 请求。
    RtlCopyMemory(&localRequest, inputRequest, sizeof(localRequest));

    // 中文说明：输出必须至少容纳无行响应头。
    status = KswordARKRetrieveRequiredOutputBuffer(
        Request,
        responseHeaderSize,
        &outputBuffer,
        &actualOutputLength);
    // 中文说明：输出检索失败时保留已复制请求但不调用后端。
    if (!NT_SUCCESS(status)) {
        // 中文说明：记录实际缓冲错误。
        KswordARKNetworkIoctlLog(
            Device,
            "Error",
            "R0 WFP event query output invalid, status=0x%08X.",
            (unsigned int)status);
        // 中文说明：把 WDF 检索错误返回 dispatch。
        return status;
    }

    // 中文说明：后端读取局部请求并写入可能 alias 原输入的输出缓冲。
    status = KswordARKNetworkQueryWfpEvents(
        &localRequest,
        outputBuffer,
        actualOutputLength,
        BytesReturned);
    // 中文说明：轮询成功不写驱动日志，避免持续网络活动污染日志 ring。
    if (!NT_SUCCESS(status)) {
        // 中文说明：仅后端失败时记录诊断。
        KswordARKNetworkIoctlLog(
            Device,
            "Error",
            "R0 WFP event query backend failed, status=0x%08X.",
            (unsigned int)status);
    }
    // 中文说明：返回后端传输状态。
    return status;
}

NTSTATUS
KswordARKNetworkIoctlQueryNdisChain(
    _In_ WDFDEVICE Device,
    _In_ WDFREQUEST Request,
    _In_ size_t InputBufferLength,
    _In_ size_t OutputBufferLength,
    _Out_ size_t* BytesReturned
    )
/*++

Routine Description:

    处理 IOCTL_KSWORD_ARK_NETWORK_QUERY_NDIS_CHAIN。中文说明：该入口只读返回
    NDIS chain 骨架，不 detach、不 pause、不重排任何 NDIS 组件。

Arguments:

    Device - WDF 设备对象。
    Request - 当前 WDF 请求。
    InputBufferLength - 输入长度。
    OutputBufferLength - 输出长度。
    BytesReturned - 返回写入字节数。

Return Value:

    NTSTATUS from buffer retrieval or backend.

--*/
{
    KSWORD_ARK_NETWORK_AUDIT_QUERY_REQUEST* queryRequest = NULL;
    PVOID outputBuffer = NULL;
    size_t actualOutputLength = 0U;
    NTSTATUS status = STATUS_SUCCESS;

    UNREFERENCED_PARAMETER(OutputBufferLength);

    if (BytesReturned == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *BytesReturned = 0U;

    status = KswordARKNetworkIoctlRetrieveAuditBuffers(
        Request,
        InputBufferLength,
        sizeof(KSWORD_ARK_NETWORK_NDIS_CHAIN_RESPONSE) - sizeof(KSWORD_ARK_NETWORK_NDIS_CHAIN_ROW),
        &queryRequest,
        &outputBuffer,
        &actualOutputLength);
    if (!NT_SUCCESS(status)) {
        KswordARKNetworkIoctlLog(Device, "Error", "R0 network NDIS audit buffer invalid, status=0x%08X.", (unsigned int)status);
        return status;
    }

    status = KswordARKNetworkQueryNdisChain(
        queryRequest,
        outputBuffer,
        actualOutputLength,
        BytesReturned);
    if (NT_SUCCESS(status) && *BytesReturned >= sizeof(KSWORD_ARK_NETWORK_NDIS_CHAIN_RESPONSE) - sizeof(KSWORD_ARK_NETWORK_NDIS_CHAIN_ROW)) {
        KSWORD_ARK_NETWORK_NDIS_CHAIN_RESPONSE* response =
            (KSWORD_ARK_NETWORK_NDIS_CHAIN_RESPONSE*)outputBuffer;
        KswordARKNetworkIoctlLog(Device, "Info", "R0 network NDIS audit status=%lu rows=%lu/%lu.", response->status, response->returnedRowCount, response->totalRowCount);
    }

    return status;
}
