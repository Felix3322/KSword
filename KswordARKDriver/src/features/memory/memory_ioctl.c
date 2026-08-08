/*++

Module Name:

    memory_ioctl.c

Abstract:

    IOCTL handlers for physical memory and page-table inspection operations.

Environment:

    Kernel-mode Driver Framework

--*/

#include "ark/ark_driver.h"
#include "ark/ark_memory_evidence.h"
#include "../../dispatch/ioctl_validation.h"
#include "../../platform/pool_compat.h"

#include <ntstrsafe.h>
#include <stdarg.h>

// 物理写入请求带尾随 data[]，栈快照放不下，改用池副本；tag 与其它 IOCTL 副本一致。
#define KSWORD_ARK_MEMORY_TOOL_IOCTL_POOL_TAG 'pMsK'

#ifndef STATUS_REQUEST_NOT_ACCEPTED
#define STATUS_REQUEST_NOT_ACCEPTED ((NTSTATUS)0xC00000D0L)
#endif

// 物理读取响应头不包含尾随 data[1]，handler 只要求 R3 至少提供头部空间。
#define KSWORD_ARK_PHYSICAL_READ_RESPONSE_HEADER_SIZE \
    (sizeof(KSWORD_ARK_READ_PHYSICAL_MEMORY_RESPONSE) - sizeof(((KSWORD_ARK_READ_PHYSICAL_MEMORY_RESPONSE*)0)->data))

// 物理写入请求头不包含尾随 data[1]，handler 用它计算完整输入长度。
#define KSWORD_ARK_PHYSICAL_WRITE_REQUEST_HEADER_SIZE \
    (sizeof(KSWORD_ARK_WRITE_PHYSICAL_MEMORY_REQUEST) - sizeof(((KSWORD_ARK_WRITE_PHYSICAL_MEMORY_REQUEST*)0)->data))

// 内核 executable page 扫描响应头不包含尾随 entries[1]。
#define KSWORD_ARK_KERNEL_EXEC_SCAN_RESPONSE_HEADER_SIZE \
    (sizeof(KSWORD_ARK_SCAN_KERNEL_EXECUTABLE_MEMORY_RESPONSE) - sizeof(KSWORD_ARK_KERNEL_EXECUTABLE_MEMORY_ENTRY))

// 内核 executable scan v1 请求前缀，允许旧 R3 只传 flags/maxEntries/start/end。
#define KSWORD_ARK_KERNEL_EXEC_SCAN_REQUEST_V1_SIZE \
    FIELD_OFFSET(KSWORD_ARK_SCAN_KERNEL_EXECUTABLE_MEMORY_REQUEST, maxBytes)

// 内核 memory evidence 扫描响应头不包含尾随 rows[1]。
#define KSWORD_ARK_MEMORY_EVIDENCE_RESPONSE_HEADER_SIZE \
    (sizeof(KSWORD_ARK_SCAN_KERNEL_MEMORY_EVIDENCE_RESPONSE) - sizeof(KSWORD_ARK_KERNEL_MEMORY_EVIDENCE_ROW))

static VOID
KswordARKMemoryToolIoctlLog(
    _In_ WDFDEVICE Device,
    _In_z_ PCSTR LevelText,
    _In_z_ PCSTR FormatText,
    ...
    )
/*++

Routine Description:

    写入物理内存/PTE 工具 IOCTL 诊断日志。中文说明：日志只记录地址、长度、
    状态和 PID，不记录物理内存内容，避免把敏感字节写入环形日志。

Arguments:

    Device - WDF 设备对象，用于投递日志。
    LevelText - 日志等级文本。
    FormatText - printf 风格 ANSI 格式串。
    ... - 格式参数。

Return Value:

    None. 日志失败不影响 IOCTL 请求完成。

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
KswordARKMemoryIoctlReadPhysicalMemory(
    _In_ WDFDEVICE Device,
    _In_ WDFREQUEST Request,
    _In_ size_t InputBufferLength,
    _In_ size_t OutputBufferLength,
    _Out_ size_t* BytesReturned
    )
/*++

Routine Description:

    处理 IOCTL_KSWORD_ARK_READ_PHYSICAL_MEMORY。中文说明：handler 负责 WDF
    缓冲获取、flags/长度初筛和读访问校验，实际 MmCopyMemory 读取在 backend。

Arguments:

    Device - WDF 设备对象，用于日志。
    Request - 当前 IOCTL 请求。
    InputBufferLength - 输入长度；METHOD_BUFFERED 下由 WDF 再校验。
    OutputBufferLength - 输出长度；METHOD_BUFFERED 下由 WDF 再校验。
    BytesReturned - 接收写入字节数。

Return Value:

    NTSTATUS from validation or KswordARKDriverReadPhysicalMemory.

--*/
{
    KSWORD_ARK_READ_PHYSICAL_MEMORY_REQUEST* readRequest = NULL;
    // requestSnapshot 在后端清零共用 SystemBuffer 前保存完整请求。
    KSWORD_ARK_READ_PHYSICAL_MEMORY_REQUEST requestSnapshot;
    PVOID outputBuffer = NULL;
    size_t actualInputLength = 0U;
    size_t actualOutputLength = 0U;
    NTSTATUS status = STATUS_SUCCESS;

    UNREFERENCED_PARAMETER(InputBufferLength);
    UNREFERENCED_PARAMETER(OutputBufferLength);

    if (BytesReturned == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *BytesReturned = 0U;

    status = KswordARKRetrieveRequiredInputBuffer(
        Request,
        sizeof(KSWORD_ARK_READ_PHYSICAL_MEMORY_REQUEST),
        (PVOID*)&readRequest,
        &actualInputLength);
    if (!NT_SUCCESS(status)) {
        KswordARKMemoryToolIoctlLog(Device, "Error", "R0 read-physical ioctl: input invalid, status=0x%08X.", (unsigned int)status);
        return status;
    }

    /*
     * METHOD_BUFFERED 的输入和输出是同一个 SystemBuffer；后端会先
     * RtlZeroMemory 输出再读 physicalAddress/bytesToRead，不做快照就会
     * 拿响应头字节当物理地址和长度去 MmCopyMemory。
     */
    RtlCopyMemory(&requestSnapshot, readRequest, sizeof(requestSnapshot));
    readRequest = &requestSnapshot;

    if (readRequest->flags != 0UL ||
        readRequest->reserved != 0UL ||
        readRequest->reserved2 != 0UL) {
        KswordARKMemoryToolIoctlLog(Device, "Warn", "R0 read-physical ioctl: flags/reserved rejected, flags=0x%08X.", (unsigned int)readRequest->flags);
        return STATUS_INVALID_PARAMETER;
    }
    if (readRequest->bytesToRead > KSWORD_ARK_MEMORY_PHYSICAL_READ_MAX_BYTES) {
        KswordARKMemoryToolIoctlLog(Device, "Warn", "R0 read-physical ioctl: size rejected, pa=0x%I64X, bytes=%lu.", readRequest->physicalAddress, (unsigned long)readRequest->bytesToRead);
        return STATUS_INVALID_PARAMETER;
    }

    status = KswordARKRetrieveRequiredOutputBuffer(
        Request,
        KSWORD_ARK_PHYSICAL_READ_RESPONSE_HEADER_SIZE,
        &outputBuffer,
        &actualOutputLength);
    if (!NT_SUCCESS(status)) {
        KswordARKMemoryToolIoctlLog(Device, "Error", "R0 read-physical ioctl: output invalid, status=0x%08X.", (unsigned int)status);
        return status;
    }

    status = KswordARKDriverReadPhysicalMemory(
        outputBuffer,
        actualOutputLength,
        readRequest,
        BytesReturned);
    if (!NT_SUCCESS(status)) {
        KswordARKMemoryToolIoctlLog(Device, "Error", "R0 read-physical failed: pa=0x%I64X, bytes=%lu, status=0x%08X.", readRequest->physicalAddress, (unsigned long)readRequest->bytesToRead, (unsigned int)status);
        return status;
    }

    if (*BytesReturned >= KSWORD_ARK_PHYSICAL_READ_RESPONSE_HEADER_SIZE) {
        KSWORD_ARK_READ_PHYSICAL_MEMORY_RESPONSE* response =
            (KSWORD_ARK_READ_PHYSICAL_MEMORY_RESPONSE*)outputBuffer;
        KswordARKMemoryToolIoctlLog(
            Device,
            "Info",
            "R0 read-physical response: pa=0x%I64X, status=%lu, requested=%lu, read=%lu.",
            response->requestedPhysicalAddress,
            (unsigned long)response->readStatus,
            (unsigned long)response->requestedBytes,
            (unsigned long)response->bytesRead);
    }

    return STATUS_SUCCESS;
}

NTSTATUS
KswordARKMemoryIoctlScanKernelExecutableMemory(
    _In_ WDFDEVICE Device,
    _In_ WDFREQUEST Request,
    _In_ size_t InputBufferLength,
    _In_ size_t OutputBufferLength,
    _Out_ size_t* BytesReturned
    )
/*++

Routine Description:

    处理 IOCTL_KSWORD_ARK_SCAN_KERNEL_EXECUTABLE_MEMORY。中文说明：handler 只做
    METHOD_BUFFERED 缓冲获取、flags/range 初筛和日志；实际扫描为只读后端，
    不写 PTE，不改 CR0，也不承诺全内核地址空间覆盖。

Arguments:

    Device - WDF 设备对象，用于日志。
    Request - 当前 IOCTL 请求。
    InputBufferLength - 输入长度；缺省时使用默认全模块保守扫描。
    OutputBufferLength - 输出长度；WDF 再确认。
    BytesReturned - 接收响应字节数。

Return Value:

    NTSTATUS from buffer validation or KswordARKDriverScanKernelExecutableMemory.

--*/
{
    KSWORD_ARK_SCAN_KERNEL_EXECUTABLE_MEMORY_REQUEST* scanRequest = NULL;
    KSWORD_ARK_SCAN_KERNEL_EXECUTABLE_MEMORY_REQUEST defaultRequest;
    KSWORD_ARK_SCAN_KERNEL_EXECUTABLE_MEMORY_REQUEST scanRequestCopy;
    PVOID inputBuffer = NULL;
    PVOID outputBuffer = NULL;
    size_t actualInputLength = 0U;
    size_t actualOutputLength = 0U;
    BOOLEAN hasInput = FALSE;
    NTSTATUS status = STATUS_SUCCESS;

    UNREFERENCED_PARAMETER(OutputBufferLength);

    if (BytesReturned == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *BytesReturned = 0U;

    RtlZeroMemory(&defaultRequest, sizeof(defaultRequest));
    RtlZeroMemory(&scanRequestCopy, sizeof(scanRequestCopy));
    defaultRequest.flags = KSWORD_ARK_KERNEL_EXEC_SCAN_FLAG_INCLUDE_ALL;

    status = KswordARKRetrieveOptionalInputBuffer(
        Request,
        InputBufferLength,
        KSWORD_ARK_KERNEL_EXEC_SCAN_REQUEST_V1_SIZE,
        &inputBuffer,
        &actualInputLength,
        &hasInput);
    if (!NT_SUCCESS(status)) {
        KswordARKMemoryToolIoctlLog(Device, "Error", "R0 scan-kernel-exec ioctl: input invalid, status=0x%08X.", (unsigned int)status);
        return status;
    }
    if (hasInput &&
        actualInputLength > KSWORD_ARK_KERNEL_EXEC_SCAN_REQUEST_V1_SIZE &&
        actualInputLength < sizeof(KSWORD_ARK_SCAN_KERNEL_EXECUTABLE_MEMORY_REQUEST)) {
        KswordARKMemoryToolIoctlLog(
            Device,
            "Warn",
            "R0 scan-kernel-exec ioctl: partial v2 input rejected, actual=%Iu.",
            actualInputLength);
        return STATUS_INVALID_PARAMETER;
    }

    if (hasInput) {
        size_t bytesToCopy = actualInputLength;
        if (bytesToCopy > sizeof(scanRequestCopy)) {
            bytesToCopy = sizeof(scanRequestCopy);
        }
        RtlCopyMemory(&scanRequestCopy, inputBuffer, bytesToCopy);
    }
    scanRequest = hasInput ? &scanRequestCopy : &defaultRequest;
    if ((scanRequest->flags & ~KSWORD_ARK_KERNEL_EXEC_SCAN_FLAG_INCLUDE_ALL) != 0UL ||
        scanRequest->reserved0 != 0UL ||
        (scanRequest->startAddress != 0ULL &&
            scanRequest->endAddress != 0ULL &&
            scanRequest->endAddress <= scanRequest->startAddress) ||
        scanRequest->maxBytes > KSWORD_ARK_KERNEL_EXEC_SCAN_HARD_MAX_BYTES ||
        scanRequest->hashBytes > KSWORD_ARK_KERNEL_EXEC_FIRST_BYTES_HARD_MAX) {
        KswordARKMemoryToolIoctlLog(
            Device,
            "Warn",
            "R0 scan-kernel-exec ioctl: flags/range/budget rejected, flags=0x%08X, start=0x%I64X, end=0x%I64X.",
            (unsigned int)scanRequest->flags,
            scanRequest->startAddress,
            scanRequest->endAddress);
        return STATUS_INVALID_PARAMETER;
    }
    /*
     * 中文说明：该 IOCTL 使用 METHOD_BUFFERED，输入和输出可能是同一个
     * SystemBuffer；backend 会清零响应缓冲，所以在获取输出缓冲前固定复制请求。
     */
    if (!hasInput) {
        RtlCopyMemory(&scanRequestCopy, scanRequest, sizeof(scanRequestCopy));
    }

    status = KswordARKRetrieveRequiredOutputBuffer(
        Request,
        KSWORD_ARK_KERNEL_EXEC_SCAN_RESPONSE_HEADER_SIZE,
        &outputBuffer,
        &actualOutputLength);
    if (!NT_SUCCESS(status)) {
        KswordARKMemoryToolIoctlLog(Device, "Error", "R0 scan-kernel-exec ioctl: output invalid, status=0x%08X.", (unsigned int)status);
        return status;
    }

    status = KswordARKDriverScanKernelExecutableMemory(
        outputBuffer,
        actualOutputLength,
        &scanRequestCopy,
        BytesReturned);
    if (!NT_SUCCESS(status)) {
        KswordARKMemoryToolIoctlLog(Device, "Error", "R0 scan-kernel-exec failed: status=0x%08X, outBytes=%Iu.", (unsigned int)status, *BytesReturned);
        return status;
    }

    if (*BytesReturned >= KSWORD_ARK_KERNEL_EXEC_SCAN_RESPONSE_HEADER_SIZE) {
        KSWORD_ARK_SCAN_KERNEL_EXECUTABLE_MEMORY_RESPONSE* response =
            (KSWORD_ARK_SCAN_KERNEL_EXECUTABLE_MEMORY_RESPONSE*)outputBuffer;
        KswordARKMemoryToolIoctlLog(
            Device,
            "Info",
            "R0 scan-kernel-exec response: status=%lu, total=%lu, returned=%lu, modules=%lu, last=0x%08X.",
            (unsigned long)response->status,
            (unsigned long)response->totalCount,
            (unsigned long)response->returnedCount,
            (unsigned long)response->moduleCount,
            (unsigned int)response->lastStatus);
    }

    return STATUS_SUCCESS;
}

NTSTATUS
KswordARKMemoryIoctlWritePhysicalMemory(
    _In_ WDFDEVICE Device,
    _In_ WDFREQUEST Request,
    _In_ size_t InputBufferLength,
    _In_ size_t OutputBufferLength,
    _Out_ size_t* BytesReturned
    )
/*++

Routine Description:

    处理 IOCTL_KSWORD_ARK_WRITE_PHYSICAL_MEMORY。中文说明：写入物理内存要求
    FILE_WRITE_ACCESS、FORCE 确认和 safety policy 允许，backend 再执行映射写入。

Arguments:

    Device - WDF 设备对象，用于日志和 safety policy。
    Request - 当前 IOCTL 请求。
    InputBufferLength - 输入长度；METHOD_BUFFERED 下由 WDF 再校验。
    OutputBufferLength - 输出长度；METHOD_BUFFERED 下由 WDF 再校验。
    BytesReturned - 接收写入字节数。

Return Value:

    NTSTATUS from validation, safety policy or KswordARKDriverWritePhysicalMemory.

--*/
{
    KSWORD_ARK_WRITE_PHYSICAL_MEMORY_REQUEST* writeRequest = NULL;
    // writeRequestCopy 是请求头加尾随 data[] 的完整池副本，长度不定所以不能放栈上。
    KSWORD_ARK_WRITE_PHYSICAL_MEMORY_REQUEST* writeRequestCopy = NULL;
    PVOID outputBuffer = NULL;
    size_t actualInputLength = 0U;
    size_t actualOutputLength = 0U;
    size_t requiredInputLength = 0U;
    const ULONG allowedFlags =
        KSWORD_ARK_PHYSICAL_WRITE_FLAG_UI_CONFIRMED |
        KSWORD_ARK_PHYSICAL_WRITE_FLAG_FORCE;
    NTSTATUS status = STATUS_SUCCESS;

    UNREFERENCED_PARAMETER(InputBufferLength);
    UNREFERENCED_PARAMETER(OutputBufferLength);

    if (BytesReturned == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *BytesReturned = 0U;

    status = KswordARKValidateDeviceIoControlWriteAccess(Request);
    if (!NT_SUCCESS(status)) {
        KswordARKMemoryToolIoctlLog(Device, "Warn", "R0 write-physical denied: write access required, status=0x%08X.", (unsigned int)status);
        return status;
    }

    status = KswordARKRetrieveRequiredInputBuffer(
        Request,
        KSWORD_ARK_PHYSICAL_WRITE_REQUEST_HEADER_SIZE,
        (PVOID*)&writeRequest,
        &actualInputLength);
    if (!NT_SUCCESS(status)) {
        KswordARKMemoryToolIoctlLog(Device, "Error", "R0 write-physical ioctl: input invalid, status=0x%08X.", (unsigned int)status);
        return status;
    }

    if ((writeRequest->flags & ~allowedFlags) != 0UL ||
        writeRequest->reserved != 0UL ||
        writeRequest->reserved2 != 0UL) {
        KswordARKMemoryToolIoctlLog(Device, "Warn", "R0 write-physical ioctl: flags/reserved rejected, flags=0x%08X.", (unsigned int)writeRequest->flags);
        return STATUS_INVALID_PARAMETER;
    }
    if (writeRequest->bytesToWrite == 0UL ||
        writeRequest->bytesToWrite > KSWORD_ARK_MEMORY_PHYSICAL_WRITE_MAX_BYTES) {
        KswordARKMemoryToolIoctlLog(Device, "Warn", "R0 write-physical ioctl: size rejected, pa=0x%I64X, bytes=%lu.", writeRequest->physicalAddress, (unsigned long)writeRequest->bytesToWrite);
        return STATUS_INVALID_PARAMETER;
    }
    if ((SIZE_T)writeRequest->bytesToWrite >
        (MAXSIZE_T - KSWORD_ARK_PHYSICAL_WRITE_REQUEST_HEADER_SIZE)) {
        KswordARKMemoryToolIoctlLog(Device, "Warn", "R0 write-physical ioctl: size overflow rejected, bytes=%lu.", (unsigned long)writeRequest->bytesToWrite);
        return STATUS_INVALID_PARAMETER;
    }

    requiredInputLength =
        KSWORD_ARK_PHYSICAL_WRITE_REQUEST_HEADER_SIZE +
        (SIZE_T)writeRequest->bytesToWrite;
    if (actualInputLength < requiredInputLength) {
        KswordARKMemoryToolIoctlLog(Device, "Warn", "R0 write-physical ioctl: input truncated, actual=%Iu, required=%Iu.", actualInputLength, requiredInputLength);
        return STATUS_INVALID_PARAMETER;
    }

    /*
     * METHOD_BUFFERED 的输入和输出共用同一个 SystemBuffer。后端会先
     * RtlZeroMemory 输出缓冲，再读 physicalAddress/bytesToWrite 并把
     * Request->data 拷进映射页；不先复制就等于拿响应头字节当物理地址，
     * 把响应内容写进一段错误的物理内存。
     */
    writeRequestCopy = (KSWORD_ARK_WRITE_PHYSICAL_MEMORY_REQUEST*)KswordARKAllocateNonPagedPool(
        requiredInputLength,
        KSWORD_ARK_MEMORY_TOOL_IOCTL_POOL_TAG);
    if (writeRequestCopy == NULL) {
        KswordARKMemoryToolIoctlLog(Device, "Error", "R0 write-physical ioctl: input copy allocation failed, bytes=%Iu.", requiredInputLength);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlCopyMemory(writeRequestCopy, writeRequest, requiredInputLength);
    writeRequest = writeRequestCopy;

    status = KswordARKRetrieveRequiredOutputBuffer(
        Request,
        sizeof(KSWORD_ARK_WRITE_PHYSICAL_MEMORY_RESPONSE),
        &outputBuffer,
        &actualOutputLength);
    if (!NT_SUCCESS(status)) {
        KswordARKMemoryToolIoctlLog(Device, "Error", "R0 write-physical ioctl: output invalid, status=0x%08X.", (unsigned int)status);
        ExFreePoolWithTag(writeRequestCopy, KSWORD_ARK_MEMORY_TOOL_IOCTL_POOL_TAG);
        return status;
    }

    if ((writeRequest->flags & KSWORD_ARK_PHYSICAL_WRITE_FLAG_FORCE) == 0UL) {
        KSWORD_ARK_WRITE_PHYSICAL_MEMORY_RESPONSE* response =
            (KSWORD_ARK_WRITE_PHYSICAL_MEMORY_RESPONSE*)outputBuffer;
        RtlZeroMemory(outputBuffer, actualOutputLength);
        response->version = KSWORD_ARK_MEMORY_PROTOCOL_VERSION;
        response->size = sizeof(*response);
        response->fieldFlags =
            KSWORD_ARK_MEMORY_FIELD_WRITE_DATA_PRESENT |
            KSWORD_ARK_MEMORY_FIELD_FORCE_WRITE_REQUIRED;
        response->writeStatus = KSWORD_ARK_MEMORY_PHYSICAL_WRITE_STATUS_FORCE_REQUIRED;
        response->mapStatus = STATUS_REQUEST_NOT_ACCEPTED;
        response->copyStatus = STATUS_REQUEST_NOT_ACCEPTED;
        response->source = KSWORD_ARK_MEMORY_SOURCE_R0_MM_MAP_PHYSICAL_MEMORY;
        response->requestedBytes = writeRequest->bytesToWrite;
        response->maxBytesPerRequest = KSWORD_ARK_MEMORY_PHYSICAL_WRITE_MAX_BYTES;
        response->requestedPhysicalAddress = writeRequest->physicalAddress;
        *BytesReturned = sizeof(*response);
        KswordARKMemoryToolIoctlLog(Device, "Warn", "R0 write-physical requires force confirmation: pa=0x%I64X, bytes=%lu.", writeRequest->physicalAddress, (unsigned long)writeRequest->bytesToWrite);
        ExFreePoolWithTag(writeRequestCopy, KSWORD_ARK_MEMORY_TOOL_IOCTL_POOL_TAG);
        return STATUS_SUCCESS;
    }

    {
        KSWORD_ARK_SAFETY_CONTEXT safetyContext;
        RtlZeroMemory(&safetyContext, sizeof(safetyContext));
        safetyContext.Operation = KSWORD_ARK_SAFETY_OPERATION_MEMORY_WRITE;
        safetyContext.ContextFlags = KSWORD_ARK_SAFETY_CONTEXT_FLAG_UI_CONFIRMED;
        safetyContext.TargetProcessId = 0UL;
        status = KswordARKSafetyEvaluate(Device, &safetyContext);
        if (!NT_SUCCESS(status)) {
            KswordARKMemoryToolIoctlLog(Device, "Warn", "R0 write-physical denied by safety policy: pa=0x%I64X, bytes=%lu, status=0x%08X.", writeRequest->physicalAddress, (unsigned long)writeRequest->bytesToWrite, (unsigned int)status);
            ExFreePoolWithTag(writeRequestCopy, KSWORD_ARK_MEMORY_TOOL_IOCTL_POOL_TAG);
            return status;
        }
    }

    // 后端只看得到池副本，长度也必须换成副本长度，不能再用 SystemBuffer 长度。
    status = KswordARKDriverWritePhysicalMemory(
        outputBuffer,
        actualOutputLength,
        writeRequest,
        requiredInputLength,
        BytesReturned);
    if (!NT_SUCCESS(status)) {
        KswordARKMemoryToolIoctlLog(Device, "Error", "R0 write-physical failed: pa=0x%I64X, bytes=%lu, status=0x%08X.", writeRequest->physicalAddress, (unsigned long)writeRequest->bytesToWrite, (unsigned int)status);
        ExFreePoolWithTag(writeRequestCopy, KSWORD_ARK_MEMORY_TOOL_IOCTL_POOL_TAG);
        return status;
    }

    if (*BytesReturned >= sizeof(KSWORD_ARK_WRITE_PHYSICAL_MEMORY_RESPONSE)) {
        KSWORD_ARK_WRITE_PHYSICAL_MEMORY_RESPONSE* response =
            (KSWORD_ARK_WRITE_PHYSICAL_MEMORY_RESPONSE*)outputBuffer;
        KswordARKMemoryToolIoctlLog(
            Device,
            "Info",
            "R0 write-physical response: pa=0x%I64X, status=%lu, requested=%lu, written=%lu.",
            response->requestedPhysicalAddress,
            (unsigned long)response->writeStatus,
            (unsigned long)response->requestedBytes,
            (unsigned long)response->bytesWritten);
    }

    ExFreePoolWithTag(writeRequestCopy, KSWORD_ARK_MEMORY_TOOL_IOCTL_POOL_TAG);
    return STATUS_SUCCESS;
}

NTSTATUS
KswordARKMemoryIoctlScanKernelMemoryEvidence(
    _In_ WDFDEVICE Device,
    _In_ WDFREQUEST Request,
    _In_ size_t InputBufferLength,
    _In_ size_t OutputBufferLength,
    _Out_ size_t* BytesReturned
    )
/*++

Routine Description:

    处理未注册的 IOCTL_KSWORD_ARK_SCAN_KERNEL_MEMORY_EVIDENCE。中文说明：第 6
    会话统一在 ioctl_registry.c 接入；当前 handler 只做 METHOD_BUFFERED 输入
    复制、flags/range/cost 上限初筛、PASSIVE_LEVEL 约束和日志。后端只读采集
    PTE、BigPool、模块 section 样本，不写 PTE、不改 CR0、不写内核内存。

Arguments:

    Device - WDF 设备对象，用于日志。
    Request - 当前 IOCTL 请求。
    InputBufferLength - 输入长度；缺省时使用默认只读全源扫描请求。
    OutputBufferLength - 输出长度；WDF 再确认。
    BytesReturned - 接收响应字节数。

Return Value:

    NTSTATUS from buffer validation or KswordARKDriverScanKernelMemoryEvidence.

--*/
{
    KSWORD_ARK_SCAN_KERNEL_MEMORY_EVIDENCE_REQUEST* evidenceRequest = NULL;
    KSWORD_ARK_SCAN_KERNEL_MEMORY_EVIDENCE_REQUEST defaultRequest;
    KSWORD_ARK_SCAN_KERNEL_MEMORY_EVIDENCE_REQUEST requestCopy;
    PVOID inputBuffer = NULL;
    PVOID outputBuffer = NULL;
    size_t actualInputLength = 0U;
    size_t actualOutputLength = 0U;
    BOOLEAN hasInput = FALSE;
    const ULONG allowedFlags = KSWORD_ARK_MEMORY_EVIDENCE_FLAG_INCLUDE_ALL;
    NTSTATUS status = STATUS_SUCCESS;

    UNREFERENCED_PARAMETER(OutputBufferLength);

    if (BytesReturned == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *BytesReturned = 0U;

    if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
        KswordARKMemoryToolIoctlLog(Device, "Warn", "R0 memory-evidence ioctl rejected: non-passive IRQL.");
        return STATUS_INVALID_DEVICE_STATE;
    }

    RtlZeroMemory(&defaultRequest, sizeof(defaultRequest));
    RtlZeroMemory(&requestCopy, sizeof(requestCopy));
    defaultRequest.flags =
        KSWORD_ARK_MEMORY_EVIDENCE_FLAG_INCLUDE_LOADED_MODULE_EXECUTABLE |
        KSWORD_ARK_MEMORY_EVIDENCE_FLAG_INCLUDE_BIGPOOL |
        KSWORD_ARK_MEMORY_EVIDENCE_FLAG_INCLUDE_TEXT_SECTION_SAMPLES |
        KSWORD_ARK_MEMORY_EVIDENCE_FLAG_INCLUDE_SUSPECTED_BIGPOOL;
    defaultRequest.maxRows = KSWORD_ARK_MEMORY_EVIDENCE_DEFAULT_MAX_ROWS;
    defaultRequest.maxBytes = KSWORD_ARK_MEMORY_EVIDENCE_DEFAULT_MAX_BYTES;
    defaultRequest.maxBigPoolRows = KSWORD_ARK_MEMORY_EVIDENCE_DEFAULT_BIGPOOL_ROWS;
    defaultRequest.sampleBytes = KSWORD_ARK_MEMORY_EVIDENCE_DEFAULT_SAMPLE_BYTES;

    status = KswordARKRetrieveOptionalInputBuffer(
        Request,
        InputBufferLength,
        sizeof(KSWORD_ARK_SCAN_KERNEL_MEMORY_EVIDENCE_REQUEST),
        &inputBuffer,
        &actualInputLength,
        &hasInput);
    if (!NT_SUCCESS(status)) {
        KswordARKMemoryToolIoctlLog(Device, "Error", "R0 memory-evidence ioctl: input invalid, status=0x%08X.", (unsigned int)status);
        return status;
    }

    evidenceRequest = hasInput ?
        (KSWORD_ARK_SCAN_KERNEL_MEMORY_EVIDENCE_REQUEST*)inputBuffer :
        &defaultRequest;
    if ((evidenceRequest->flags & ~allowedFlags) != 0UL ||
        evidenceRequest->reserved0 != 0UL ||
        evidenceRequest->reserved1 != 0UL ||
        (evidenceRequest->startAddress != 0ULL &&
            evidenceRequest->endAddress != 0ULL &&
            evidenceRequest->endAddress <= evidenceRequest->startAddress) ||
        (evidenceRequest->maxRows > KSWORD_ARK_MEMORY_EVIDENCE_HARD_MAX_ROWS) ||
        (evidenceRequest->maxBytes > KSWORD_ARK_MEMORY_EVIDENCE_HARD_MAX_BYTES) ||
        (evidenceRequest->maxBigPoolRows > KSWORD_ARK_MEMORY_EVIDENCE_HARD_MAX_BIGPOOL_ROWS) ||
        (evidenceRequest->sampleBytes > KSWORD_ARK_MEMORY_EVIDENCE_HARD_MAX_SAMPLE_BYTES) ||
        ((evidenceRequest->flags & KSWORD_ARK_MEMORY_EVIDENCE_FLAG_INCLUDE_NONMODULE_EXECUTABLE_RANGES) != 0UL &&
            (evidenceRequest->startAddress == 0ULL ||
                evidenceRequest->endAddress == 0ULL ||
                evidenceRequest->endAddress <= evidenceRequest->startAddress))) {
        KswordARKMemoryToolIoctlLog(
            Device,
            "Warn",
            "R0 memory-evidence ioctl rejected: flags=0x%08X, start=0x%I64X, end=0x%I64X.",
            (unsigned int)evidenceRequest->flags,
            evidenceRequest->startAddress,
            evidenceRequest->endAddress);
        return STATUS_INVALID_PARAMETER;
    }

    RtlCopyMemory(&requestCopy, evidenceRequest, sizeof(requestCopy));

    status = KswordARKRetrieveRequiredOutputBuffer(
        Request,
        KSWORD_ARK_MEMORY_EVIDENCE_RESPONSE_HEADER_SIZE,
        &outputBuffer,
        &actualOutputLength);
    if (!NT_SUCCESS(status)) {
        KswordARKMemoryToolIoctlLog(Device, "Error", "R0 memory-evidence ioctl: output invalid, status=0x%08X.", (unsigned int)status);
        return status;
    }

    status = KswordARKDriverScanKernelMemoryEvidence(
        outputBuffer,
        actualOutputLength,
        &requestCopy,
        BytesReturned);
    if (!NT_SUCCESS(status)) {
        KswordARKMemoryToolIoctlLog(Device, "Error", "R0 memory-evidence failed: status=0x%08X, outBytes=%Iu.", (unsigned int)status, *BytesReturned);
        return status;
    }

    if (*BytesReturned >= KSWORD_ARK_MEMORY_EVIDENCE_RESPONSE_HEADER_SIZE) {
        KSWORD_ARK_SCAN_KERNEL_MEMORY_EVIDENCE_RESPONSE* response =
            (KSWORD_ARK_SCAN_KERNEL_MEMORY_EVIDENCE_RESPONSE*)outputBuffer;
        KswordARKMemoryToolIoctlLog(
            Device,
            "Info",
            "R0 memory-evidence response: status=%lu, total=%lu, returned=%lu, modules=%lu, bigpool=%lu, last=0x%08X.",
            (unsigned long)response->status,
            (unsigned long)response->totalRows,
            (unsigned long)response->returnedRows,
            (unsigned long)response->moduleCount,
            (unsigned long)response->bigPoolRowsSeen,
            (unsigned int)response->lastStatus);
    }

    return STATUS_SUCCESS;
}

NTSTATUS
KswordARKMemoryIoctlTranslateVirtualAddress(
    _In_ WDFDEVICE Device,
    _In_ WDFREQUEST Request,
    _In_ size_t InputBufferLength,
    _In_ size_t OutputBufferLength,
    _Out_ size_t* BytesReturned
    )
/*++

Routine Description:

    处理 IOCTL_KSWORD_ARK_TRANSLATE_VIRTUAL_ADDRESS。中文说明：handler 仅做
    缓冲和 flags 校验，实际 CR3/页表只读遍历由 backend 完成。

Arguments:

    Device - WDF 设备对象，用于日志。
    Request - 当前 IOCTL 请求。
    InputBufferLength - 输入长度；METHOD_BUFFERED 下由 WDF 再校验。
    OutputBufferLength - 输出长度；METHOD_BUFFERED 下由 WDF 再校验。
    BytesReturned - 接收写入字节数。

Return Value:

    NTSTATUS from validation or KswordARKDriverTranslateVirtualAddress.

--*/
{
    KSWORD_ARK_TRANSLATE_VIRTUAL_ADDRESS_REQUEST* translateRequest = NULL;
    // requestSnapshot 在后端清零共用 SystemBuffer 前保存完整请求。
    KSWORD_ARK_TRANSLATE_VIRTUAL_ADDRESS_REQUEST requestSnapshot;
    PVOID outputBuffer = NULL;
    size_t actualInputLength = 0U;
    size_t actualOutputLength = 0U;
    NTSTATUS status = STATUS_SUCCESS;

    UNREFERENCED_PARAMETER(InputBufferLength);
    UNREFERENCED_PARAMETER(OutputBufferLength);

    if (BytesReturned == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *BytesReturned = 0U;

    status = KswordARKRetrieveRequiredInputBuffer(
        Request,
        sizeof(KSWORD_ARK_TRANSLATE_VIRTUAL_ADDRESS_REQUEST),
        (PVOID*)&translateRequest,
        &actualInputLength);
    if (!NT_SUCCESS(status)) {
        KswordARKMemoryToolIoctlLog(Device, "Error", "R0 translate-va ioctl: input invalid, status=0x%08X.", (unsigned int)status);
        return status;
    }

    /*
     * METHOD_BUFFERED 的输入和输出共用同一个 SystemBuffer；后端清零输出后
     * 才读 processId/virtualAddress，不做快照就会翻译一个错误的地址。
     */
    RtlCopyMemory(&requestSnapshot, translateRequest, sizeof(requestSnapshot));
    translateRequest = &requestSnapshot;

    if (translateRequest->flags != 0UL || translateRequest->reserved != 0UL) {
        KswordARKMemoryToolIoctlLog(Device, "Warn", "R0 translate-va ioctl: flags/reserved rejected, flags=0x%08X.", (unsigned int)translateRequest->flags);
        return STATUS_INVALID_PARAMETER;
    }

    status = KswordARKRetrieveRequiredOutputBuffer(
        Request,
        sizeof(KSWORD_ARK_TRANSLATE_VIRTUAL_ADDRESS_RESPONSE),
        &outputBuffer,
        &actualOutputLength);
    if (!NT_SUCCESS(status)) {
        KswordARKMemoryToolIoctlLog(Device, "Error", "R0 translate-va ioctl: output invalid, status=0x%08X.", (unsigned int)status);
        return status;
    }

    status = KswordARKDriverTranslateVirtualAddress(
        outputBuffer,
        actualOutputLength,
        translateRequest,
        BytesReturned);
    if (!NT_SUCCESS(status)) {
        KswordARKMemoryToolIoctlLog(Device, "Error", "R0 translate-va failed: pid=%lu, va=0x%I64X, status=0x%08X.", (unsigned long)translateRequest->processId, translateRequest->virtualAddress, (unsigned int)status);
        return status;
    }

    if (*BytesReturned >= sizeof(KSWORD_ARK_TRANSLATE_VIRTUAL_ADDRESS_RESPONSE)) {
        KSWORD_ARK_TRANSLATE_VIRTUAL_ADDRESS_RESPONSE* response =
            (KSWORD_ARK_TRANSLATE_VIRTUAL_ADDRESS_RESPONSE*)outputBuffer;
        KswordARKMemoryToolIoctlLog(
            Device,
            "Info",
            "R0 translate-va response: pid=%lu, va=0x%I64X, resolved=%lu, status=%lu, pa=0x%I64X.",
            (unsigned long)response->info.processId,
            response->info.virtualAddress,
            (unsigned long)response->info.resolved,
            (unsigned long)response->info.queryStatus,
            response->info.physicalAddress);
    }

    return STATUS_SUCCESS;
}

NTSTATUS
KswordARKMemoryIoctlQueryPageTableEntry(
    _In_ WDFDEVICE Device,
    _In_ WDFREQUEST Request,
    _In_ size_t InputBufferLength,
    _In_ size_t OutputBufferLength,
    _Out_ size_t* BytesReturned
    )
/*++

Routine Description:

    处理 IOCTL_KSWORD_ARK_QUERY_PAGE_TABLE_ENTRY。中文说明：返回 PML4E/PDPTE/
    PDE/PTE 原始值、flags、索引、page size 和大页类型，默认不提供写页表能力。

Arguments:

    Device - WDF 设备对象，用于日志。
    Request - 当前 IOCTL 请求。
    InputBufferLength - 输入长度；METHOD_BUFFERED 下由 WDF 再校验。
    OutputBufferLength - 输出长度；METHOD_BUFFERED 下由 WDF 再校验。
    BytesReturned - 接收写入字节数。

Return Value:

    NTSTATUS from validation or KswordARKDriverQueryPageTableEntry.

--*/
{
    KSWORD_ARK_QUERY_PAGE_TABLE_ENTRY_REQUEST* queryRequest = NULL;
    // requestSnapshot 在后端清零共用 SystemBuffer 前保存完整请求。
    KSWORD_ARK_QUERY_PAGE_TABLE_ENTRY_REQUEST requestSnapshot;
    PVOID outputBuffer = NULL;
    size_t actualInputLength = 0U;
    size_t actualOutputLength = 0U;
    NTSTATUS status = STATUS_SUCCESS;

    UNREFERENCED_PARAMETER(InputBufferLength);
    UNREFERENCED_PARAMETER(OutputBufferLength);

    if (BytesReturned == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *BytesReturned = 0U;

    status = KswordARKRetrieveRequiredInputBuffer(
        Request,
        sizeof(KSWORD_ARK_QUERY_PAGE_TABLE_ENTRY_REQUEST),
        (PVOID*)&queryRequest,
        &actualInputLength);
    if (!NT_SUCCESS(status)) {
        KswordARKMemoryToolIoctlLog(Device, "Error", "R0 query-pte ioctl: input invalid, status=0x%08X.", (unsigned int)status);
        return status;
    }

    /*
     * METHOD_BUFFERED 的输入和输出共用同一个 SystemBuffer；后端清零输出后
     * 才读 processId/virtualAddress，不做快照就会查错页表项。
     */
    RtlCopyMemory(&requestSnapshot, queryRequest, sizeof(requestSnapshot));
    queryRequest = &requestSnapshot;

    if (queryRequest->flags != 0UL || queryRequest->reserved != 0UL) {
        KswordARKMemoryToolIoctlLog(Device, "Warn", "R0 query-pte ioctl: flags/reserved rejected, flags=0x%08X.", (unsigned int)queryRequest->flags);
        return STATUS_INVALID_PARAMETER;
    }

    status = KswordARKRetrieveRequiredOutputBuffer(
        Request,
        sizeof(KSWORD_ARK_QUERY_PAGE_TABLE_ENTRY_RESPONSE),
        &outputBuffer,
        &actualOutputLength);
    if (!NT_SUCCESS(status)) {
        KswordARKMemoryToolIoctlLog(Device, "Error", "R0 query-pte ioctl: output invalid, status=0x%08X.", (unsigned int)status);
        return status;
    }

    status = KswordARKDriverQueryPageTableEntry(
        outputBuffer,
        actualOutputLength,
        queryRequest,
        BytesReturned);
    if (!NT_SUCCESS(status)) {
        KswordARKMemoryToolIoctlLog(Device, "Error", "R0 query-pte failed: pid=%lu, va=0x%I64X, status=0x%08X.", (unsigned long)queryRequest->processId, queryRequest->virtualAddress, (unsigned int)status);
        return status;
    }

    if (*BytesReturned >= sizeof(KSWORD_ARK_QUERY_PAGE_TABLE_ENTRY_RESPONSE)) {
        KSWORD_ARK_QUERY_PAGE_TABLE_ENTRY_RESPONSE* response =
            (KSWORD_ARK_QUERY_PAGE_TABLE_ENTRY_RESPONSE*)outputBuffer;
        KswordARKMemoryToolIoctlLog(
            Device,
            "Info",
            "R0 query-pte response: pid=%lu, va=0x%I64X, resolved=%lu, status=%lu, pageSize=%lu.",
            (unsigned long)response->info.processId,
            response->info.virtualAddress,
            (unsigned long)response->info.resolved,
            (unsigned long)response->info.queryStatus,
            (unsigned long)response->info.pageSize);
    }

    return STATUS_SUCCESS;
}
