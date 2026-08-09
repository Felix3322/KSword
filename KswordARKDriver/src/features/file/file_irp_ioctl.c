/*++

Module Name:

    file_irp_ioctl.c

Abstract:

    IOCTL handlers for the self-built file IRP path. 本层只做三件事：把
    METHOD_BUFFERED 请求完整快照出来、执行协议与安全边界校验、调用
    file_irp_request.c 的 IRP 引擎，保持分发层薄而可审计。

Environment:

    Kernel-mode Driver Framework

--*/

#include "ark/ark_driver.h"
#include "ark/ark_file_irp.h"
#include "../../dispatch/ioctl_validation.h"

#include <ntstrsafe.h>
#include <stdarg.h>

#define KSWORD_ARK_FILE_IRP_IOCTL_POOL_TAG 'oIsK'

static VOID
KswordARKFileIrpIoctlLog(
    _In_ WDFDEVICE Device,
    _In_z_ PCSTR LevelText,
    _In_z_ PCSTR FormatText,
    ...
    )
/*++

Routine Description:

    Format and enqueue one file-IRP handler log message.

Arguments:

    Device - WDF device that owns the log channel.
    LevelText - Log level string.
    FormatText - printf-style ANSI message template.
    ... - Template arguments.

Return Value:

    None. Formatting or enqueue failures are ignored.

--*/
{
    CHAR logMessage[KSWORD_ARK_LOG_ENTRY_MAX_BYTES] = { 0 };
    va_list arguments;

    va_start(arguments, FormatText);
    if (NT_SUCCESS(RtlStringCbVPrintfA(logMessage, sizeof(logMessage), FormatText, arguments))) {
        (void)KswordARKDriverEnqueueLogFrame(Device, LevelText, logMessage);
    }
    va_end(arguments);
}

static BOOLEAN
KswordARKFileIrpIoctlPathIsValid(
    _In_reads_(MaxChars) PCWSTR Path,
    _In_ USHORT PathLengthChars,
    _In_ USHORT MaxChars
    )
/*++

Routine Description:

    校验固定宽字符路径字段：长度非零、在容量内、且以 NUL 收尾。

Arguments:

    Path - 固定路径缓冲。
    PathLengthChars - 声明的字符数。
    MaxChars - 缓冲容量。

Return Value:

    TRUE 表示可安全用于构造 UNICODE_STRING。

--*/
{
    if (PathLengthChars == 0U || PathLengthChars >= MaxChars) {
        return FALSE;
    }
    return Path[PathLengthChars] == L'\0';
}

NTSTATUS
KswordARKFileIrpIoctlEnumDirectory(
    _In_ WDFDEVICE Device,
    _In_ WDFREQUEST Request,
    _In_ size_t InputBufferLength,
    _In_ size_t OutputBufferLength,
    _Out_ size_t* BytesReturned
    )
/*++

Routine Description:

    处理 IOCTL_KSWORD_ARK_FILE_IRP_ENUM_DIRECTORY。只读枚举，不需要确认令牌；
    与 IOCTL_KSWORD_ARK_ENUM_DIRECTORY 的唯一区别是请求被投递到哪一层。

Arguments:

    Device - WDF 设备对象，仅用于日志。
    Request - 当前 IOCTL 请求。
    InputBufferLength/OutputBufferLength - 分发层提供的声明长度。
    BytesReturned - 接收协议头与有效目录行总长度。

Return Value:

    NTSTATUS 表示 WDF 缓冲或协议处理结果；目录语义保存在响应字段。

--*/
{
    KSWORD_ARK_FILE_IRP_ENUM_DIRECTORY_REQUEST* directoryRequest = NULL;
    KSWORD_ARK_FILE_IRP_ENUM_DIRECTORY_REQUEST requestSnapshot;
    KSWORD_ARK_FILE_IRP_ENUM_DIRECTORY_RESPONSE* directoryResponse = NULL;
    PVOID inputBuffer = NULL;
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
        sizeof(KSWORD_ARK_FILE_IRP_ENUM_DIRECTORY_REQUEST),
        &inputBuffer,
        &actualInputLength);
    if (!NT_SUCCESS(status)) {
        KswordARKFileIrpIoctlLog(
            Device,
            "Error",
            "R0 irp-directory ioctl: input invalid, status=0x%08X.",
            (unsigned int)status);
        return status;
    }

    /*
     * METHOD_BUFFERED 的输入输出共用同一系统缓冲；响应头一旦清零就会抹掉
     * path/startIndex/targetLayer，所以必须先整体快照再校验。
     */
    directoryRequest = (KSWORD_ARK_FILE_IRP_ENUM_DIRECTORY_REQUEST*)inputBuffer;
    RtlCopyMemory(&requestSnapshot, directoryRequest, sizeof(requestSnapshot));

    if (requestSnapshot.version != KSWORD_ARK_FILE_IRP_PROTOCOL_VERSION ||
        requestSnapshot.size != (ULONG)sizeof(requestSnapshot) ||
        requestSnapshot.flags != 0UL ||
        requestSnapshot.targetLayer > KSWORD_ARK_FILE_IRP_LAYER_MAX ||
        requestSnapshot.maxEntries == 0UL ||
        requestSnapshot.maxEntries > KSWORD_ARK_DIRECTORY_ENUM_MAX_PAGE_ENTRIES ||
        requestSnapshot.startIndex >= KSWORD_ARK_DIRECTORY_ENUM_MAX_TOTAL_ENTRIES ||
        requestSnapshot.maxEntries >
            KSWORD_ARK_DIRECTORY_ENUM_MAX_TOTAL_ENTRIES - requestSnapshot.startIndex ||
        requestSnapshot.reserved != 0U ||
        !KswordARKFileIrpIoctlPathIsValid(
            requestSnapshot.path,
            requestSnapshot.pathLengthChars,
            (USHORT)KSWORD_ARK_DIRECTORY_ENUM_PATH_MAX_CHARS)) {
        KswordARKFileIrpIoctlLog(
            Device,
            "Warn",
            "R0 irp-directory ioctl: request rejected, version=%lu, layer=%lu, start=%lu, max=%lu, chars=%u.",
            (unsigned long)requestSnapshot.version,
            (unsigned long)requestSnapshot.targetLayer,
            (unsigned long)requestSnapshot.startIndex,
            (unsigned long)requestSnapshot.maxEntries,
            (unsigned int)requestSnapshot.pathLengthChars);
        return STATUS_INVALID_PARAMETER;
    }

    status = KswordARKRetrieveRequiredOutputBuffer(
        Request,
        KSWORD_ARK_FILE_IRP_ENUM_DIRECTORY_RESPONSE_HEADER_SIZE +
            sizeof(KSWORD_ARK_DIRECTORY_ENTRY),
        &outputBuffer,
        &actualOutputLength);
    if (!NT_SUCCESS(status)) {
        KswordARKFileIrpIoctlLog(
            Device,
            "Error",
            "R0 irp-directory ioctl: output invalid, status=0x%08X.",
            (unsigned int)status);
        return status;
    }

    status = KswordARKDriverEnumerateDirectoryByIrp(
        outputBuffer,
        actualOutputLength,
        &requestSnapshot,
        BytesReturned);
    if (!NT_SUCCESS(status)) {
        KswordARKFileIrpIoctlLog(
            Device,
            "Error",
            "R0 irp-directory ioctl: feature failed, chars=%u, status=0x%08X.",
            (unsigned int)requestSnapshot.pathLengthChars,
            (unsigned int)status);
        return status;
    }

    if (*BytesReturned >= KSWORD_ARK_FILE_IRP_ENUM_DIRECTORY_RESPONSE_HEADER_SIZE) {
        directoryResponse =
            (KSWORD_ARK_FILE_IRP_ENUM_DIRECTORY_RESPONSE*)outputBuffer;
        if (directoryResponse->queryStatus !=
                KSWORD_ARK_DIRECTORY_ENUM_STATUS_OK &&
            directoryResponse->queryStatus !=
                KSWORD_ARK_DIRECTORY_ENUM_STATUS_PARTIAL) {
            KswordARKFileIrpIoctlLog(
                Device,
                "Warn",
                "R0 irp-directory semantic failure: layer=%lu, query=%lu, status=0x%08X.",
                (unsigned long)directoryResponse->targetLayer,
                (unsigned long)directoryResponse->queryStatus,
                (unsigned int)directoryResponse->lastStatus);
        }
    }

    return STATUS_SUCCESS;
}

NTSTATUS
KswordARKFileIrpIoctlSubmit(
    _In_ WDFDEVICE Device,
    _In_ WDFREQUEST Request,
    _In_ size_t InputBufferLength,
    _In_ size_t OutputBufferLength,
    _Out_ size_t* BytesReturned
    )
/*++

Routine Description:

    处理 IOCTL_KSWORD_ARK_FILE_IRP_SUBMIT。请求是变长的（固定头 + 内联输入
    数据），而 METHOD_BUFFERED 让输入与输出共用同一系统缓冲：响应的 outputData
    从偏移 1152 开始写，会盖住请求尾部的 inputData。因此本 handler 必须把
    整个请求（含内联数据）复制到独立的池缓冲后再交给 IRP 引擎。

Arguments:

    Device - WDF 设备对象，用于日志与安全策略。
    Request - 当前 IOCTL 请求。
    InputBufferLength/OutputBufferLength - 分发层提供的声明长度。
    BytesReturned - 接收响应头与输出数据总长度。

Return Value:

    STATUS_SUCCESS 表示响应包已构造完成；IRP 的真实语义在响应字段里。

--*/
{
    KSWORD_ARK_FILE_IRP_SUBMIT_REQUEST* submitRequest = NULL;
    KSWORD_ARK_FILE_IRP_SUBMIT_REQUEST* requestCopy = NULL;
    KSWORD_ARK_FILE_IRP_SUBMIT_RESPONSE* submitResponse = NULL;
    PVOID inputBuffer = NULL;
    PVOID outputBuffer = NULL;
    size_t actualInputLength = 0U;
    size_t actualOutputLength = 0U;
    size_t requiredInputLength = 0U;
    size_t copyLength = 0U;
    ULONG inputBytes = 0UL;
    ULONG safetyOperation = 0UL;
    NTSTATUS status = STATUS_SUCCESS;

    UNREFERENCED_PARAMETER(InputBufferLength);
    UNREFERENCED_PARAMETER(OutputBufferLength);

    if (BytesReturned == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *BytesReturned = 0U;

    status = KswordARKValidateDeviceIoControlWriteAccess(Request);
    if (!NT_SUCCESS(status)) {
        KswordARKFileIrpIoctlLog(
            Device,
            "Warn",
            "R0 irp-submit denied: write access required, status=0x%08X.",
            (unsigned int)status);
        return status;
    }

    status = KswordARKRetrieveRequiredInputBuffer(
        Request,
        KSWORD_ARK_FILE_IRP_SUBMIT_REQUEST_HEADER_SIZE,
        &inputBuffer,
        &actualInputLength);
    if (!NT_SUCCESS(status)) {
        KswordARKFileIrpIoctlLog(
            Device,
            "Error",
            "R0 irp-submit ioctl: input invalid, status=0x%08X.",
            (unsigned int)status);
        return status;
    }

    submitRequest = (KSWORD_ARK_FILE_IRP_SUBMIT_REQUEST*)inputBuffer;
    inputBytes = submitRequest->inputBytes;
    if (inputBytes > KSWORD_ARK_FILE_IRP_MAX_INPUT_BYTES) {
        KswordARKFileIrpIoctlLog(
            Device,
            "Warn",
            "R0 irp-submit ioctl: inline input too large, bytes=%lu.",
            (unsigned long)inputBytes);
        return STATUS_INVALID_PARAMETER;
    }

    requiredInputLength =
        (size_t)KSWORD_ARK_FILE_IRP_SUBMIT_REQUEST_HEADER_SIZE + inputBytes;
    if (actualInputLength < requiredInputLength) {
        KswordARKFileIrpIoctlLog(
            Device,
            "Warn",
            "R0 irp-submit ioctl: declared input exceeds buffer, need=%Iu, have=%Iu.",
            requiredInputLength,
            actualInputLength);
        return STATUS_INVALID_PARAMETER;
    }

    copyLength = requiredInputLength;
#pragma warning(push)
#pragma warning(disable:4996)
    requestCopy = (KSWORD_ARK_FILE_IRP_SUBMIT_REQUEST*)ExAllocatePoolWithTag(
        NonPagedPoolNx,
        copyLength,
        KSWORD_ARK_FILE_IRP_IOCTL_POOL_TAG);
#pragma warning(pop)
    if (requestCopy == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlCopyMemory(requestCopy, inputBuffer, copyLength);

    if (requestCopy->version != KSWORD_ARK_FILE_IRP_PROTOCOL_VERSION ||
        requestCopy->size != KSWORD_ARK_FILE_IRP_SUBMIT_REQUEST_HEADER_SIZE ||
        (requestCopy->flags & ~KSWORD_ARK_FILE_IRP_FLAG_ALL) != 0UL ||
        requestCopy->majorFunction >= KSWORD_ARK_FILE_IRP_MAJOR_COUNT ||
        requestCopy->minorFunction > 0xFFUL ||
        requestCopy->targetLayer > KSWORD_ARK_FILE_IRP_LAYER_MAX ||
        requestCopy->outputBytes > KSWORD_ARK_FILE_IRP_MAX_OUTPUT_BYTES ||
        requestCopy->timeoutMs > KSWORD_ARK_FILE_IRP_MAX_TIMEOUT_MS ||
        requestCopy->reserved0 != 0UL ||
        requestCopy->reserved1 != 0UL ||
        requestCopy->patternLengthChars >= KSWORD_ARK_FILE_IRP_NAME_MAX_CHARS ||
        !KswordARKFileIrpIoctlPathIsValid(
            requestCopy->path,
            requestCopy->pathLengthChars,
            (USHORT)KSWORD_ARK_FILE_IRP_PATH_MAX_CHARS)) {
        KswordARKFileIrpIoctlLog(
            Device,
            "Warn",
            "R0 irp-submit ioctl: request rejected, version=%lu, major=%lu, layer=%lu, flags=0x%08X, chars=%u.",
            (unsigned long)requestCopy->version,
            (unsigned long)requestCopy->majorFunction,
            (unsigned long)requestCopy->targetLayer,
            (unsigned int)requestCopy->flags,
            (unsigned int)requestCopy->pathLengthChars);
        ExFreePoolWithTag(requestCopy, KSWORD_ARK_FILE_IRP_IOCTL_POOL_TAG);
        return STATUS_INVALID_PARAMETER;
    }
    if (requestCopy->patternLengthChars != 0U &&
        requestCopy->pattern[requestCopy->patternLengthChars] != L'\0') {
        ExFreePoolWithTag(requestCopy, KSWORD_ARK_FILE_IRP_IOCTL_POOL_TAG);
        return STATUS_INVALID_PARAMETER;
    }

    /*
     * 安全策略：写语义走文件写入闸门；PnP/电源等非文件语义按内核改动处理。
     * 令牌本身在 IRP 引擎里再校验一次，两处都不能省。
     */
    safetyOperation = KSWORD_ARK_SAFETY_OPERATION_NONE;
    switch (requestCopy->majorFunction) {
    case IRP_MJ_WRITE:
    case IRP_MJ_SET_INFORMATION:
    case IRP_MJ_SET_EA:
    case IRP_MJ_SET_VOLUME_INFORMATION:
    case IRP_MJ_SET_SECURITY:
    case IRP_MJ_SET_QUOTA:
    case IRP_MJ_FILE_SYSTEM_CONTROL:
        safetyOperation = KSWORD_ARK_SAFETY_OPERATION_FILE_DELETE;
        break;
    case IRP_MJ_POWER:
    case IRP_MJ_PNP:
    case IRP_MJ_SYSTEM_CONTROL:
    case IRP_MJ_SHUTDOWN:
    case IRP_MJ_DEVICE_CHANGE:
        safetyOperation = KSWORD_ARK_SAFETY_OPERATION_KERNEL_PATCH;
        break;
    default:
        break;
    }

    if (safetyOperation != KSWORD_ARK_SAFETY_OPERATION_NONE) {
        KSWORD_ARK_SAFETY_CONTEXT safetyContext;
        RtlZeroMemory(&safetyContext, sizeof(safetyContext));
        safetyContext.Operation = safetyOperation;
        safetyContext.TargetProcessId = 0UL;
        safetyContext.ContextFlags =
            ((requestCopy->flags & KSWORD_ARK_FILE_IRP_FLAG_UI_CONFIRMED) != 0UL)
                ? KSWORD_ARK_SAFETY_CONTEXT_FLAG_UI_CONFIRMED
                : 0UL;
        safetyContext.TargetText = requestCopy->path;
        safetyContext.TargetTextChars = requestCopy->pathLengthChars;
        status = KswordARKSafetyEvaluate(Device, &safetyContext);
        if (!NT_SUCCESS(status)) {
            KswordARKFileIrpIoctlLog(
                Device,
                "Warn",
                "R0 irp-submit denied by safety policy: major=%lu, chars=%u, status=0x%08X.",
                (unsigned long)requestCopy->majorFunction,
                (unsigned int)requestCopy->pathLengthChars,
                (unsigned int)status);
            ExFreePoolWithTag(requestCopy, KSWORD_ARK_FILE_IRP_IOCTL_POOL_TAG);
            return status;
        }
    }

    status = KswordARKRetrieveRequiredOutputBuffer(
        Request,
        KSWORD_ARK_FILE_IRP_SUBMIT_RESPONSE_HEADER_SIZE,
        &outputBuffer,
        &actualOutputLength);
    if (!NT_SUCCESS(status)) {
        KswordARKFileIrpIoctlLog(
            Device,
            "Error",
            "R0 irp-submit ioctl: output invalid, status=0x%08X.",
            (unsigned int)status);
        ExFreePoolWithTag(requestCopy, KSWORD_ARK_FILE_IRP_IOCTL_POOL_TAG);
        return status;
    }

    status = KswordARKDriverSubmitFileIrp(
        outputBuffer,
        actualOutputLength,
        requestCopy,
        (inputBytes != 0UL) ? requestCopy->inputData : NULL,
        inputBytes,
        BytesReturned);

    if (NT_SUCCESS(status) &&
        *BytesReturned >= KSWORD_ARK_FILE_IRP_SUBMIT_RESPONSE_HEADER_SIZE) {
        submitResponse = (KSWORD_ARK_FILE_IRP_SUBMIT_RESPONSE*)outputBuffer;
        KswordARKFileIrpIoctlLog(
            Device,
            (submitResponse->status == KSWORD_ARK_FILE_IRP_STATUS_OK)
                ? "Info"
                : "Warn",
            "R0 irp-submit: major=%lu, minor=%lu, layer=%lu, protocol=%lu, create=0x%08X, op=0x%08X, out=%lu.",
            (unsigned long)submitResponse->majorFunction,
            (unsigned long)submitResponse->minorFunction,
            (unsigned long)submitResponse->targetLayer,
            (unsigned long)submitResponse->status,
            (unsigned int)submitResponse->createStatus,
            (unsigned int)submitResponse->operationStatus,
            (unsigned long)submitResponse->outputBytes);
    }
    else if (!NT_SUCCESS(status)) {
        KswordARKFileIrpIoctlLog(
            Device,
            "Error",
            "R0 irp-submit ioctl: engine failed, major=%lu, status=0x%08X.",
            (unsigned long)requestCopy->majorFunction,
            (unsigned int)status);
    }

    ExFreePoolWithTag(requestCopy, KSWORD_ARK_FILE_IRP_IOCTL_POOL_TAG);
    return status;
}
