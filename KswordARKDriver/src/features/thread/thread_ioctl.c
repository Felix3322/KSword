/*++

Module Name:

    thread_ioctl.c

Abstract:

    IOCTL handlers for KswordARK thread inspection operations.

Environment:

    Kernel-mode Driver Framework

--*/

#include "ark/ark_driver.h"
#include "..\kernel\hook_scan_support.h"
#include "../../dispatch/ioctl_validation.h"
#include "../../platform/pool_compat.h"

#include <ntstrsafe.h>
#include <stdarg.h>

#define KSWORD_ARK_THREAD_ENUM_RESPONSE_HEADER_SIZE \
    (sizeof(KSWORD_ARK_ENUM_THREAD_RESPONSE) - sizeof(KSWORD_ARK_THREAD_ENTRY))

#ifndef THREAD_SUSPEND_RESUME
#define THREAD_SUSPEND_RESUME (0x0002)
#endif

typedef NTSTATUS(NTAPI* KSWORD_ZW_OR_NT_THREAD_SUSPEND_FN)(
    _In_ HANDLE ThreadHandle,
    _Out_opt_ PULONG PreviousSuspendCount
    );

NTSYSAPI
NTSTATUS
NTAPI
PsLookupThreadByThreadId(
    _In_ HANDLE ThreadId,
    _Outptr_ PETHREAD* Thread
    );

NTKERNELAPI
NTSTATUS
ObOpenObjectByPointer(
    _In_ PVOID Object,
    _In_ ULONG HandleAttributes,
    _In_opt_ PACCESS_STATE PassedAccessState,
    _In_opt_ ACCESS_MASK DesiredAccess,
    _In_opt_ POBJECT_TYPE ObjectType,
    _In_ KPROCESSOR_MODE AccessMode,
    _Out_ PHANDLE Handle
    );

static VOID
KswordARKThreadIoctlLog(
    _In_ WDFDEVICE Device,
    _In_z_ PCSTR LevelText,
    _In_z_ PCSTR FormatText,
    ...
    )
/*++

Routine Description:

    Format and enqueue one thread-handler diagnostic message. 这里集中处理
    日志格式化，避免枚举 handler 内部夹杂重复的 RtlStringCbVPrintfA 调用。

Arguments:

    Device - WDF device that owns the log channel.
    LevelText - Log level string.
    FormatText - printf-style ANSI message template.
    ... - Template arguments.

Return Value:

    None. 日志失败不影响 IOCTL 主路径。

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
KswordARKThreadIoctlEnumThread(
    _In_ WDFDEVICE Device,
    _In_ WDFREQUEST Request,
    _In_ size_t InputBufferLength,
    _In_ size_t OutputBufferLength,
    _Out_ size_t* BytesReturned
    )
/*++

Routine Description:

    Handle IOCTL_KSWORD_ARK_ENUM_THREAD. 输入包是可选的；缺省时枚举全部线程
    并请求全部 Phase-3 扩展字段。输出包允许部分填充，R3 通过 totalCount 判断
    是否需要更大缓冲区。

Arguments:

    Device - WDF device used for logging.
    Request - Current IOCTL request.
    InputBufferLength - Supplied input bytes; shorter input selects defaults.
    OutputBufferLength - Supplied output bytes; checked by WDF output retrieval.
    BytesReturned - Receives the feature-written response byte count.

Return Value:

    NTSTATUS from buffer retrieval or KswordARKDriverEnumerateThreads.

--*/
{
    KSWORD_ARK_ENUM_THREAD_REQUEST* enumRequest = NULL;
    KSWORD_ARK_ENUM_THREAD_REQUEST defaultRequest = { 0 };
    PVOID inputBuffer = NULL;
    PVOID outputBuffer = NULL;
    size_t actualInputLength = 0;
    size_t actualOutputLength = 0;
    BOOLEAN hasInput = FALSE;
    NTSTATUS status = STATUS_SUCCESS;

    UNREFERENCED_PARAMETER(OutputBufferLength);

    if (BytesReturned == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *BytesReturned = 0;

    status = KswordARKRetrieveOptionalInputBuffer(
        Request,
        InputBufferLength,
        sizeof(KSWORD_ARK_ENUM_THREAD_REQUEST),
        &inputBuffer,
        &actualInputLength,
        &hasInput);
    if (!NT_SUCCESS(status)) {
        KswordARKThreadIoctlLog(Device, "Error", "R0 enum-thread ioctl: input buffer invalid, status=0x%08X.", (unsigned int)status);
        return status;
    }

    if (hasInput) {
        enumRequest = (KSWORD_ARK_ENUM_THREAD_REQUEST*)inputBuffer;
    }
    else {
        enumRequest = &defaultRequest;
        enumRequest->flags = KSWORD_ARK_ENUM_THREAD_FLAG_INCLUDE_ALL;
        enumRequest->processId = 0UL;
        enumRequest->reserved0 = 0UL;
        enumRequest->reserved1 = 0UL;
    }

    status = KswordARKRetrieveRequiredOutputBuffer(
        Request,
        KSWORD_ARK_THREAD_ENUM_RESPONSE_HEADER_SIZE,
        &outputBuffer,
        &actualOutputLength);
    if (!NT_SUCCESS(status)) {
        KswordARKThreadIoctlLog(Device, "Error", "R0 enum-thread ioctl: output buffer invalid, status=0x%08X.", (unsigned int)status);
        return status;
    }

    status = KswordARKDriverEnumerateThreads(outputBuffer, actualOutputLength, enumRequest, BytesReturned);
    if (!NT_SUCCESS(status)) {
        KswordARKThreadIoctlLog(Device, "Error", "R0 enum-thread failed: status=0x%08X, outBytes=%Iu.", (unsigned int)status, *BytesReturned);
        return status;
    }

    if (*BytesReturned >= KSWORD_ARK_THREAD_ENUM_RESPONSE_HEADER_SIZE) {
        KSWORD_ARK_ENUM_THREAD_RESPONSE* responseHeader = (KSWORD_ARK_ENUM_THREAD_RESPONSE*)outputBuffer;
        KswordARKThreadIoctlLog(
            Device,
            "Info",
            "R0 enum-thread success: total=%lu, returned=%lu, outBytes=%Iu.",
            (unsigned long)responseHeader->totalCount,
            (unsigned long)responseHeader->returnedCount,
            *BytesReturned);
    }
    else {
        KswordARKThreadIoctlLog(Device, "Warn", "R0 enum-thread success: outBytes=%Iu (header partial).", *BytesReturned);
    }

    return status;
}

NTSTATUS
KswordARKThreadIoctlTerminate(
    _In_ WDFDEVICE Device,
    _In_ WDFREQUEST Request,
    _In_ size_t InputBufferLength,
    _In_ size_t OutputBufferLength,
    _Out_ size_t* BytesReturned
    )
/*++

Routine Description:

    Handle IOCTL_KSWORD_ARK_TERMINATE_THREAD. The handler validates the fixed
    PID/TID request, applies the existing destructive-process safety policy, and
    terminates only the referenced target thread.

Arguments:

    Device - WDF device used for logging and safety-policy evaluation.
    Request - Current IOCTL request.
    InputBufferLength - Caller-supplied input length; used by WDF retrieval.
    OutputBufferLength - Caller-supplied output length; unused for this IOCTL.
    BytesReturned - Receives sizeof(request) on success and zero on failure.

Return Value:

    NTSTATUS from validation, safety policy, or the specified-thread backend.

--*/
{
    KSWORD_ARK_TERMINATE_THREAD_REQUEST* terminateRequest = NULL;
    PVOID inputBuffer = NULL;
    size_t actualInputLength = 0;
    NTSTATUS status = STATUS_SUCCESS;

    // 该 IOCTL 只读取固定输入包，不需要输出缓冲区。
    UNREFERENCED_PARAMETER(InputBufferLength);
    UNREFERENCED_PARAMETER(OutputBufferLength);

    // 调用方必须提供返回字节计数的存储位置。
    if (BytesReturned == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *BytesReturned = 0;

    // 从 METHOD_BUFFERED 请求中获取完整的共享线程终止请求。
    status = KswordARKRetrieveRequiredInputBuffer(
        Request,
        sizeof(KSWORD_ARK_TERMINATE_THREAD_REQUEST),
        &inputBuffer,
        &actualInputLength);
    if (!NT_SUCCESS(status)) {
        KswordARKThreadIoctlLog(Device, "Error", "R0 terminate-thread ioctl: input buffer invalid, status=0x%08X.", (unsigned int)status);
        return status;
    }

    // 已验证长度的输入包可以安全转换为请求结构。
    terminateRequest = (KSWORD_ARK_TERMINATE_THREAD_REQUEST*)inputBuffer;
    status = KswordARKValidateUserPid((ULONG)terminateRequest->processId);
    if (!NT_SUCCESS(status) || terminateRequest->threadId == 0UL) {
        KswordARKThreadIoctlLog(
            Device,
            "Warn",
            "R0 terminate-thread ioctl: pid=%lu, tid=%lu rejected, status=0x%08X.",
            (unsigned long)terminateRequest->processId,
            (unsigned long)terminateRequest->threadId,
            (unsigned int)(NT_SUCCESS(status) ? STATUS_INVALID_PARAMETER : status));
        return NT_SUCCESS(status) ? STATUS_INVALID_PARAMETER : status;
    }

    // 指定线程终止属于破坏性进程操作，复用已有的进程安全策略。
    {
        KSWORD_ARK_SAFETY_CONTEXT safetyContext;
        RtlZeroMemory(&safetyContext, sizeof(safetyContext));
        safetyContext.Operation = KSWORD_ARK_SAFETY_OPERATION_PROCESS_TERMINATE;
        safetyContext.TargetProcessId = (ULONG)terminateRequest->processId;
        safetyContext.ContextFlags = KSWORD_ARK_SAFETY_CONTEXT_FLAG_UI_CONFIRMED;
        status = KswordARKSafetyEvaluate(Device, &safetyContext);
        if (!NT_SUCCESS(status)) {
            KswordARKThreadIoctlLog(
                Device,
                "Warn",
                "R0 terminate-thread denied by safety policy: pid=%lu, tid=%lu, status=0x%08X.",
                (unsigned long)terminateRequest->processId,
                (unsigned long)terminateRequest->threadId,
                (unsigned int)status);
            return status;
        }
    }

    // 后端会重新引用并验证 ETHREAD 所属进程，不信任 R3 传入的任何对象地址。
    status = KswordARKDriverTerminateThreadById(
        Device,
        (ULONG)terminateRequest->processId,
        (ULONG)terminateRequest->threadId,
        (NTSTATUS)terminateRequest->exitStatus);
    if (NT_SUCCESS(status)) {
        KswordARKThreadIoctlLog(
            Device,
            "Info",
            "R0 terminate-thread success: pid=%lu, tid=%lu.",
            (unsigned long)terminateRequest->processId,
            (unsigned long)terminateRequest->threadId);
        *BytesReturned = sizeof(KSWORD_ARK_TERMINATE_THREAD_REQUEST);
    }
    else {
        KswordARKThreadIoctlLog(
            Device,
            "Error",
            "R0 terminate-thread failed: pid=%lu, tid=%lu, status=0x%08X.",
            (unsigned long)terminateRequest->processId,
            (unsigned long)terminateRequest->threadId,
            (unsigned int)status);
    }

    return status;
}

static KSWORD_ZW_OR_NT_THREAD_SUSPEND_FN
KswordARKResolveThreadSuspendRoutine(
    _In_ BOOLEAN Suspend
    )
{
    UNICODE_STRING routineName;
    KSWORD_ZW_OR_NT_THREAD_SUSPEND_FN routine = NULL;

    RtlInitUnicodeString(&routineName, Suspend ? L"ZwSuspendThread" : L"ZwResumeThread");
    routine = (KSWORD_ZW_OR_NT_THREAD_SUSPEND_FN)MmGetSystemRoutineAddress(&routineName);
    if (routine != NULL) {
        return routine;
    }

    RtlInitUnicodeString(&routineName, Suspend ? L"NtSuspendThread" : L"NtResumeThread");
    return (KSWORD_ZW_OR_NT_THREAD_SUSPEND_FN)MmGetSystemRoutineAddress(&routineName);
}

static NTSTATUS
KswordARKDriverSetThreadSuspendedById(
    _In_ WDFDEVICE Device,
    _In_ ULONG ProcessId,
    _In_ ULONG ThreadId,
    _In_ BOOLEAN Suspend
    )
/*++

Routine Description:

    Reference one ETHREAD by TID, verify that it still belongs to the requested
    user process, then suspend or resume it through a kernel thread handle.

Arguments:

    Device - WDF device used for diagnostics.
    ProcessId - Expected owner PID.
    ThreadId - Target TID.
    Suspend - TRUE to increment the suspend count, FALSE to decrement it.

Return Value:

    NTSTATUS from validation, ownership checking, handle creation, or the
    resolved Zw/Nt thread control routine.

--*/
{
    KSWORD_ZW_OR_NT_THREAD_SUSPEND_FN controlRoutine = NULL;
    PETHREAD threadObject = NULL;
    HANDLE threadHandle = NULL;
    ULONG actualProcessId = 0UL;
    ULONG previousSuspendCount = 0UL;
    NTSTATUS status = STATUS_SUCCESS;

    if (ProcessId <= 4UL || ThreadId == 0UL) {
        return STATUS_INVALID_PARAMETER;
    }

    status = PsLookupThreadByThreadId(ULongToHandle(ThreadId), &threadObject);
    if (!NT_SUCCESS(status)) {
        KswordARKThreadIoctlLog(
            Device,
            "Warn",
            "R0 thread-control lookup failed: pid=%lu, tid=%lu, status=0x%08X.",
            (unsigned long)ProcessId,
            (unsigned long)ThreadId,
            (unsigned int)status);
        return status;
    }

    actualProcessId = HandleToULong(PsGetThreadProcessId(threadObject));
    if (actualProcessId != ProcessId) {
        status = STATUS_NOT_FOUND;
        KswordARKThreadIoctlLog(
            Device,
            "Warn",
            "R0 thread-control ownership mismatch: requestPid=%lu, actualPid=%lu, tid=%lu.",
            (unsigned long)ProcessId,
            (unsigned long)actualProcessId,
            (unsigned long)ThreadId);
        goto Exit;
    }

    // 挂起当前正在处理本 IOCTL 的线程会让请求永远无法完成，因此明确拒绝。
    if (Suspend && threadObject == PsGetCurrentThread()) {
        status = STATUS_INVALID_DEVICE_STATE;
        KswordARKThreadIoctlLog(
            Device,
            "Warn",
            "R0 suspend-thread rejected current request thread: pid=%lu, tid=%lu.",
            (unsigned long)ProcessId,
            (unsigned long)ThreadId);
        goto Exit;
    }

    controlRoutine = KswordARKResolveThreadSuspendRoutine(Suspend);
    if (controlRoutine == NULL) {
        status = STATUS_PROCEDURE_NOT_FOUND;
        goto Exit;
    }

    status = ObOpenObjectByPointer(
        threadObject,
        OBJ_KERNEL_HANDLE,
        NULL,
        THREAD_SUSPEND_RESUME,
        *PsThreadType,
        KernelMode,
        &threadHandle);
    if (!NT_SUCCESS(status)) {
        goto Exit;
    }

    status = controlRoutine(threadHandle, &previousSuspendCount);
    KswordARKThreadIoctlLog(
        Device,
        NT_SUCCESS(status) ? "Info" : "Warn",
        "R0 %s-thread result: pid=%lu, tid=%lu, previousSuspendCount=%lu, status=0x%08X.",
        Suspend ? "suspend" : "resume",
        (unsigned long)ProcessId,
        (unsigned long)ThreadId,
        (unsigned long)previousSuspendCount,
        (unsigned int)status);

Exit:
    if (threadHandle != NULL) {
        ZwClose(threadHandle);
        threadHandle = NULL;
    }
    if (threadObject != NULL) {
        ObDereferenceObject(threadObject);
        threadObject = NULL;
    }
    return status;
}

NTSTATUS
KswordARKThreadIoctlSetSuspended(
    _In_ WDFDEVICE Device,
    _In_ WDFREQUEST Request,
    _In_ size_t InputBufferLength,
    _In_ size_t OutputBufferLength,
    _Out_ size_t* BytesReturned
    )
/*++

Routine Description:

    Handle IOCTL_KSWORD_ARK_SET_THREAD_SUSPENDED. Suspend requests reuse the
    destructive suspend safety policy; resume remains available as recovery.

Arguments:

    Device - WDF device used for logging and safety-policy evaluation.
    Request - Current IOCTL request.
    InputBufferLength - Caller input length; validated through WDF retrieval.
    OutputBufferLength - Caller output length; unused.
    BytesReturned - Receives request size on success and zero on failure.

Return Value:

    NTSTATUS from validation, safety policy, or the thread-control backend.

--*/
{
    KSWORD_ARK_SET_THREAD_SUSPENDED_REQUEST* controlRequest = NULL;
    PVOID inputBuffer = NULL;
    size_t actualInputLength = 0;
    BOOLEAN suspend = FALSE;
    NTSTATUS status = STATUS_SUCCESS;

    UNREFERENCED_PARAMETER(InputBufferLength);
    UNREFERENCED_PARAMETER(OutputBufferLength);

    if (BytesReturned == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *BytesReturned = 0;

    status = KswordARKRetrieveRequiredInputBuffer(
        Request,
        sizeof(KSWORD_ARK_SET_THREAD_SUSPENDED_REQUEST),
        &inputBuffer,
        &actualInputLength);
    if (!NT_SUCCESS(status)) {
        KswordARKThreadIoctlLog(
            Device,
            "Error",
            "R0 thread-control ioctl: input buffer invalid, status=0x%08X.",
            (unsigned int)status);
        return status;
    }

    controlRequest = (KSWORD_ARK_SET_THREAD_SUSPENDED_REQUEST*)inputBuffer;
    status = KswordARKValidateUserPid((ULONG)controlRequest->processId);
    if (!NT_SUCCESS(status) || controlRequest->threadId == 0UL) {
        return NT_SUCCESS(status) ? STATUS_INVALID_PARAMETER : status;
    }
    if (controlRequest->action == KSWORD_ARK_THREAD_SUSPEND_ACTION_SUSPEND) {
        suspend = TRUE;
    }
    else if (controlRequest->action != KSWORD_ARK_THREAD_SUSPEND_ACTION_RESUME) {
        return STATUS_INVALID_PARAMETER;
    }

    if (suspend) {
        KSWORD_ARK_SAFETY_CONTEXT safetyContext;
        RtlZeroMemory(&safetyContext, sizeof(safetyContext));
        safetyContext.Operation = KSWORD_ARK_SAFETY_OPERATION_PROCESS_SUSPEND;
        safetyContext.TargetProcessId = (ULONG)controlRequest->processId;
        safetyContext.ContextFlags = KSWORD_ARK_SAFETY_CONTEXT_FLAG_UI_CONFIRMED;
        status = KswordARKSafetyEvaluate(Device, &safetyContext);
        if (!NT_SUCCESS(status)) {
            KswordARKThreadIoctlLog(
                Device,
                "Warn",
                "R0 suspend-thread denied by safety policy: pid=%lu, tid=%lu, status=0x%08X.",
                (unsigned long)controlRequest->processId,
                (unsigned long)controlRequest->threadId,
                (unsigned int)status);
            return status;
        }
    }

    status = KswordARKDriverSetThreadSuspendedById(
        Device,
        (ULONG)controlRequest->processId,
        (ULONG)controlRequest->threadId,
        suspend);
    if (NT_SUCCESS(status)) {
        *BytesReturned = sizeof(KSWORD_ARK_SET_THREAD_SUSPENDED_REQUEST);
    }
    return status;
}

static BOOLEAN
KswordARKDriverThreadIsProtectedDriverEntity(
    _In_ WDFDEVICE Device,
    _In_ ULONG64 StartAddress
    )
{
    WDFDRIVER wdfDriver = NULL;
    PDRIVER_OBJECT driverObject = NULL;
    ULONG_PTR driverStart = 0U;
    ULONG_PTR driverEnd = 0U;
    ULONG driverSize = 0UL;

    // 自保护绑定当前 WDFDEVICE 所属 DriverObject 实体，而不是可重命名文件名。
    // 任何取值失败或范围回绕都按受保护处理。
    if (Device == NULL || StartAddress == 0ULL) {
        return TRUE;
    }
    wdfDriver = WdfDeviceGetDriver(Device);
    if (wdfDriver == NULL) {
        return TRUE;
    }
    driverObject = WdfDriverWdmGetDriverObject(wdfDriver);
    if (driverObject == NULL) {
        return TRUE;
    }

    __try {
        driverStart = (ULONG_PTR)driverObject->DriverStart;
        driverSize = driverObject->DriverSize;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return TRUE;
    }
    if (driverStart == 0U || driverSize == 0UL ||
        (ULONG_PTR)driverSize > ((ULONG_PTR)(~(ULONG_PTR)0) - driverStart)) {
        return TRUE;
    }
    driverEnd = driverStart + (ULONG_PTR)driverSize;
    return (ULONG_PTR)StartAddress >= driverStart &&
        (ULONG_PTR)StartAddress < driverEnd;
}

static NTSTATUS
KswordARKDriverThreadVerifyLiveIdentity(
    _In_ PETHREAD ThreadObject,
    _In_ const KSWORD_ARK_CONTROL_DRIVER_THREAD_REQUEST* ControlRequest,
    _Out_opt_ ULONG64* ActualStartAddressOut
    )
{
    KSWORD_ARK_THREAD_DETAIL_REQUEST detailRequest;
    KSWORD_ARK_THREAD_DETAIL_RESPONSE detailResponse;
    ULONG64 actualStartAddress = 0ULL;
    size_t detailBytes = 0U;
    NTSTATUS status = STATUS_SUCCESS;

    if (ActualStartAddressOut != NULL) {
        *ActualStartAddressOut = 0ULL;
    }
    if (ThreadObject == NULL || ControlRequest == NULL ||
        ControlRequest->threadId == 0UL ||
        ControlRequest->expectedStartAddress == 0ULL ||
        ControlRequest->expectedCreateTime100ns == 0ULL) {
        return STATUS_INVALID_PARAMETER;
    }

    // 已引用对象仍需验证 Ps 公共身份，防止调用链误传其它 ETHREAD。
    if (HandleToULong(PsGetThreadId(ThreadObject)) != ControlRequest->threadId ||
        HandleToULong(PsGetThreadProcessId(ThreadObject)) != 4UL) {
        return STATUS_OBJECT_NAME_NOT_FOUND;
    }

#if (NTDDI_VERSION >= NTDDI_WINTHRESHOLD)
    {
        const LONGLONG createTime = PsGetThreadCreateTime(ThreadObject);
        if (createTime <= 0 ||
            (ULONG64)createTime != ControlRequest->expectedCreateTime100ns) {
            return STATUS_OBJECT_NAME_NOT_FOUND;
        }
    }
#else
    // 目标 WDK 无可靠创建时间 API 时，整个驱动线程控制协议关闭。
    return STATUS_NOT_SUPPORTED;
#endif

    RtlZeroMemory(&detailRequest, sizeof(detailRequest));
    RtlZeroMemory(&detailResponse, sizeof(detailResponse));
    detailRequest.version = KSWORD_ARK_THREAD_PROTOCOL_VERSION;
    detailRequest.flags = KSWORD_ARK_THREAD_DETAIL_FLAG_INCLUDE_START;
    detailRequest.threadId = ControlRequest->threadId;
    detailRequest.processId = 4UL;
    status = KswordARKDriverQueryThreadDetail(
        &detailResponse,
        sizeof(detailResponse),
        &detailRequest,
        &detailBytes);
    if (!NT_SUCCESS(status) ||
        detailResponse.processId != 4UL) {
        return NT_SUCCESS(status) ? STATUS_OBJECT_NAME_NOT_FOUND : status;
    }

    if ((detailResponse.fieldFlags & KSWORD_ARK_THREAD_DETAIL_FIELD_WIN32_START_ADDRESS) != 0UL) {
        actualStartAddress = detailResponse.win32StartAddress;
    }
    else if ((detailResponse.fieldFlags & KSWORD_ARK_THREAD_DETAIL_FIELD_START_ADDRESS) != 0UL) {
        actualStartAddress = detailResponse.startAddress;
    }
    if (actualStartAddress == 0ULL ||
        !(((detailResponse.fieldFlags & KSWORD_ARK_THREAD_DETAIL_FIELD_START_ADDRESS) != 0UL &&
           ControlRequest->expectedStartAddress == detailResponse.startAddress) ||
          ((detailResponse.fieldFlags & KSWORD_ARK_THREAD_DETAIL_FIELD_WIN32_START_ADDRESS) != 0UL &&
           ControlRequest->expectedStartAddress == detailResponse.win32StartAddress))) {
        return STATUS_OBJECT_NAME_NOT_FOUND;
    }
    if (ActualStartAddressOut != NULL) {
        *ActualStartAddressOut = ControlRequest->expectedStartAddress;
    }
    return STATUS_SUCCESS;
}

static NTSTATUS
KswordARKDriverControlDriverThread(
    _In_ WDFDEVICE Device,
    _In_ const KSWORD_ARK_CONTROL_DRIVER_THREAD_REQUEST* ControlRequest
    )
/*++

Routine Description:

    Validate one PID 4 system thread against its live R0 start address and the
    loaded-driver module snapshot, then suspend, resume, or terminate it.

Arguments:

    Device - WDF device used for diagnostics and safety evaluation.
    ControlRequest - Fixed request containing TID, action, confirmation, and
    the R3-observed start address used as an anti-stale consistency check.

Return Value:

    NTSTATUS from identity/module validation, safety policy, or thread control.

--*/
{
    KSW_HOOK_SYSTEM_MODULE_INFORMATION* moduleInfo = NULL;
    const KSW_HOOK_SYSTEM_MODULE_ENTRY* ownerModule = NULL;
    const UCHAR* moduleFileName = NULL;
    ULONG moduleFileNameBytes = 0UL;
    ULONG moduleInfoBytes = 0UL;
    WCHAR moduleNameWide[128] = { 0 };
    USHORT moduleNameChars = 0U;
    PETHREAD threadObject = NULL;
    PETHREAD actionThreadObject = NULL;
    HANDLE threadHandle = NULL;
    ULONG previousSuspendCount = 0UL;
    ULONG64 actualStartAddress = 0ULL;
    KSWORD_ZW_OR_NT_THREAD_SUSPEND_FN suspendRoutine = NULL;
    NTSTATUS status = STATUS_SUCCESS;

    if (ControlRequest == NULL ||
        ControlRequest->size != sizeof(*ControlRequest) ||
        ControlRequest->version != KSWORD_ARK_DRIVER_THREAD_CONTROL_PROTOCOL_VERSION ||
        ControlRequest->threadId == 0UL ||
        ControlRequest->expectedStartAddress == 0ULL ||
        ControlRequest->expectedCreateTime100ns == 0ULL ||
        (ControlRequest->flags & ~KSWORD_ARK_DRIVER_THREAD_CONTROL_FLAG_VALID_MASK) != 0UL ||
        ControlRequest->reserved0 != 0UL ||
        ControlRequest->reserved1 != 0UL ||
        (ControlRequest->action != KSWORD_ARK_DRIVER_THREAD_ACTION_SUSPEND &&
         ControlRequest->action != KSWORD_ARK_DRIVER_THREAD_ACTION_RESUME &&
         ControlRequest->action != KSWORD_ARK_DRIVER_THREAD_ACTION_TERMINATE)) {
        return STATUS_INVALID_PARAMETER;
    }
    if ((ControlRequest->action == KSWORD_ARK_DRIVER_THREAD_ACTION_SUSPEND ||
         ControlRequest->action == KSWORD_ARK_DRIVER_THREAD_ACTION_TERMINATE) &&
        (ControlRequest->flags & KSWORD_ARK_DRIVER_THREAD_CONTROL_FLAG_UI_CONFIRMED) == 0UL) {
        return STATUS_ACCESS_DENIED;
    }
    if (ControlRequest->action == KSWORD_ARK_DRIVER_THREAD_ACTION_RESUME &&
        ControlRequest->flags != 0UL) {
        return STATUS_INVALID_PARAMETER;
    }
    if (ControlRequest->action == KSWORD_ARK_DRIVER_THREAD_ACTION_TERMINATE) {
        if (ControlRequest->terminateMethod <
                KSWORD_ARK_DRIVER_THREAD_TERMINATE_METHOD_PSP_BY_POINTER ||
            ControlRequest->terminateMethod >
                KSWORD_ARK_DRIVER_THREAD_TERMINATE_METHOD_SPECIAL_TO_NORMAL_APC) {
            return STATUS_INVALID_PARAMETER;
        }
    }
    else if (ControlRequest->terminateMethod !=
             KSWORD_ARK_DRIVER_THREAD_TERMINATE_METHOD_NONE) {
        return STATUS_INVALID_PARAMETER;
    }

    // 先持有目标 ETHREAD，直到地址/模块校验和动作全部完成，阻止 TID 回收竞态。
    status = PsLookupThreadByThreadId(
        ULongToHandle(ControlRequest->threadId),
        &threadObject);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    if (threadObject == PsGetCurrentThread() &&
        ControlRequest->action != KSWORD_ARK_DRIVER_THREAD_ACTION_RESUME) {
        status = STATUS_INVALID_DEVICE_STATE;
        goto Exit;
    }

    status = KswordARKDriverThreadVerifyLiveIdentity(
        threadObject,
        ControlRequest,
        &actualStartAddress);
    if (!NT_SUCCESS(status)) {
        KswordARKThreadIoctlLog(
            Device,
            "Warn",
            "Driver-thread control identity rejected: tid=%lu, expectedStart=0x%I64X, expectedCreateTime100ns=%I64u, status=0x%08X.",
            (unsigned long)ControlRequest->threadId,
            ControlRequest->expectedStartAddress,
            ControlRequest->expectedCreateTime100ns,
            (unsigned int)status);
        goto Exit;
    }

    status = KswordARKHookBuildModuleSnapshot(&moduleInfo, &moduleInfoBytes);
    if (!NT_SUCCESS(status)) {
        goto Exit;
    }
    ownerModule = KswordARKHookFindModuleForAddress(
        moduleInfo,
        (ULONG_PTR)actualStartAddress);
    if (ownerModule == NULL || ownerModule == &moduleInfo->Modules[0]) {
        status = STATUS_ACCESS_DENIED;
        goto Exit;
    }
    KswordARKHookGetModuleFileName(ownerModule, &moduleFileName, &moduleFileNameBytes);
    if (KswordARKDriverThreadIsProtectedDriverEntity(Device, actualStartAddress)) {
        status = STATUS_ACCESS_DENIED;
        goto Exit;
    }
    KswordARKHookCopyBoundedAnsiToWide(
        moduleFileName,
        moduleFileNameBytes,
        moduleNameWide,
        RTL_NUMBER_OF(moduleNameWide));
    while (moduleNameChars + 1U < RTL_NUMBER_OF(moduleNameWide) &&
           moduleNameWide[moduleNameChars] != L'\0') {
        ++moduleNameChars;
    }

    if (ControlRequest->action != KSWORD_ARK_DRIVER_THREAD_ACTION_RESUME) {
        KSWORD_ARK_SAFETY_CONTEXT safetyContext;
        RtlZeroMemory(&safetyContext, sizeof(safetyContext));
        safetyContext.Operation = KSWORD_ARK_SAFETY_OPERATION_DRIVER_THREAD_CONTROL;
        safetyContext.ContextFlags =
            (ControlRequest->flags & KSWORD_ARK_DRIVER_THREAD_CONTROL_FLAG_UI_CONFIRMED) != 0UL
            ? KSWORD_ARK_SAFETY_CONTEXT_FLAG_UI_CONFIRMED
            : 0UL;
        safetyContext.TargetText = moduleNameWide;
        safetyContext.TargetTextChars = moduleNameChars;
        status = KswordARKSafetyEvaluate(Device, &safetyContext);
        if (!NT_SUCCESS(status)) {
            goto Exit;
        }
    }

    // 动作入口前按 TID 重新引用一次 ETHREAD，并要求它仍是最初持有的同一对象。
    // 随后从新引用精确核对 TID + StartAddress + CreateTime；失败时不进入任何后端。
    status = PsLookupThreadByThreadId(
        ULongToHandle(ControlRequest->threadId),
        &actionThreadObject);
    if (!NT_SUCCESS(status) || actionThreadObject != threadObject) {
        if (NT_SUCCESS(status)) {
            status = STATUS_OBJECT_NAME_NOT_FOUND;
        }
        goto Exit;
    }
    status = KswordARKDriverThreadVerifyLiveIdentity(
        actionThreadObject,
        ControlRequest,
        &actualStartAddress);
    if (!NT_SUCCESS(status)) {
        KswordARKThreadIoctlLog(
            Device,
            "Warn",
            "Driver-thread control final identity check failed: tid=%lu, expectedStart=0x%I64X, expectedCreateTime100ns=%I64u, status=0x%08X.",
            (unsigned long)ControlRequest->threadId,
            ControlRequest->expectedStartAddress,
            ControlRequest->expectedCreateTime100ns,
            (unsigned int)status);
        goto Exit;
    }

    if (ControlRequest->action == KSWORD_ARK_DRIVER_THREAD_ACTION_TERMINATE) {
        switch (ControlRequest->terminateMethod) {
        case KSWORD_ARK_DRIVER_THREAD_TERMINATE_METHOD_PSP_BY_POINTER:
            status = KswordARKDriverTerminateReferencedThreadPsp(
                actionThreadObject,
                STATUS_CANCELLED);
            break;
        case KSWORD_ARK_DRIVER_THREAD_TERMINATE_METHOD_ZW_OR_NT:
            status = KswordARKDriverTerminateReferencedThreadZwOrNt(
                actionThreadObject,
                STATUS_CANCELLED);
            break;
        case KSWORD_ARK_DRIVER_THREAD_TERMINATE_METHOD_NORMAL_APC:
            status = KswordARKDriverQueueTerminateSystemThreadApc(
                actionThreadObject,
                FALSE);
            break;
        case KSWORD_ARK_DRIVER_THREAD_TERMINATE_METHOD_SPECIAL_TO_NORMAL_APC:
            status = KswordARKDriverQueueTerminateSystemThreadApc(
                actionThreadObject,
                TRUE);
            break;
        default:
            status = STATUS_INVALID_PARAMETER;
            break;
        }
    }
    else {
        status = ObOpenObjectByPointer(
            actionThreadObject,
            OBJ_KERNEL_HANDLE,
            NULL,
            THREAD_SUSPEND_RESUME,
            *PsThreadType,
            KernelMode,
            &threadHandle);
        if (!NT_SUCCESS(status)) {
            goto Exit;
        }
        suspendRoutine = KswordARKResolveThreadSuspendRoutine(
            ControlRequest->action == KSWORD_ARK_DRIVER_THREAD_ACTION_SUSPEND);
        status = suspendRoutine != NULL
            ? suspendRoutine(threadHandle, &previousSuspendCount)
            : STATUS_PROCEDURE_NOT_FOUND;
    }

    KswordARKThreadIoctlLog(
        Device,
        NT_SUCCESS(status) ? "Info" : "Warn",
        "Driver-thread control result: tid=%lu, createTime100ns=%I64u, action=%lu, terminateMethod=%lu, module=%ws, start=0x%I64X, previousSuspendCount=%lu, status=0x%08X.",
        (unsigned long)ControlRequest->threadId,
        ControlRequest->expectedCreateTime100ns,
        (unsigned long)ControlRequest->action,
        (unsigned long)ControlRequest->terminateMethod,
        moduleNameWide,
        actualStartAddress,
        (unsigned long)previousSuspendCount,
        (unsigned int)status);

Exit:
    if (threadHandle != NULL) {
        ZwClose(threadHandle);
        threadHandle = NULL;
    }
    if (actionThreadObject != NULL) {
        ObDereferenceObject(actionThreadObject);
        actionThreadObject = NULL;
    }
    if (threadObject != NULL) {
        ObDereferenceObject(threadObject);
        threadObject = NULL;
    }
    if (moduleInfo != NULL) {
        ExFreePoolWithTag(moduleInfo, KSW_HOOK_SCAN_TAG);
        moduleInfo = NULL;
    }
    return status;
}

NTSTATUS
KswordARKThreadIoctlControlDriverThread(
    _In_ WDFDEVICE Device,
    _In_ WDFREQUEST Request,
    _In_ size_t InputBufferLength,
    _In_ size_t OutputBufferLength,
    _Out_ size_t* BytesReturned
    )
{
    KSWORD_ARK_CONTROL_DRIVER_THREAD_REQUEST* controlRequest = NULL;
    PVOID inputBuffer = NULL;
    size_t actualInputLength = 0;
    NTSTATUS status = STATUS_SUCCESS;

    UNREFERENCED_PARAMETER(OutputBufferLength);

    if (BytesReturned == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *BytesReturned = 0;

    status = KswordARKRetrieveRequiredInputBuffer(
        Request,
        sizeof(KSWORD_ARK_CONTROL_DRIVER_THREAD_REQUEST),
        &inputBuffer,
        &actualInputLength);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    controlRequest = (KSWORD_ARK_CONTROL_DRIVER_THREAD_REQUEST*)inputBuffer;
    if (InputBufferLength != sizeof(*controlRequest) ||
        actualInputLength != sizeof(*controlRequest)) {
        return STATUS_INFO_LENGTH_MISMATCH;
    }
    status = KswordARKDriverControlDriverThread(Device, controlRequest);
    if (NT_SUCCESS(status)) {
        *BytesReturned = sizeof(KSWORD_ARK_CONTROL_DRIVER_THREAD_REQUEST);
    }
    return status;
}
