/*++

Module Name:

    object_callback.c

Abstract:

    Object manager callback registration (Process/Thread handle operations only).

Environment:

    Kernel-mode Driver Framework

--*/

#include "callback_internal.h"
#include "ark/ark_process_protect.h"

static const WCHAR g_KswordArkObAltitude[] = L"385201.5142";

NTSYSAPI
PEPROCESS
NTAPI
PsGetThreadProcess(
    _In_ PETHREAD Thread
    );

#ifndef PROCESS_TERMINATE
#define PROCESS_TERMINATE 0x0001
#endif
#ifndef PROCESS_CREATE_THREAD
#define PROCESS_CREATE_THREAD 0x0002
#endif
#ifndef PROCESS_SET_QUOTA
#define PROCESS_SET_QUOTA 0x0100
#endif
#ifndef PROCESS_SET_INFORMATION
#define PROCESS_SET_INFORMATION 0x0200
#endif
#ifndef PROCESS_VM_OPERATION
#define PROCESS_VM_OPERATION 0x0008
#endif
#ifndef PROCESS_VM_WRITE
#define PROCESS_VM_WRITE 0x0020
#endif
#ifndef PROCESS_SUSPEND_RESUME
#define PROCESS_SUSPEND_RESUME 0x0800
#endif
#ifndef THREAD_TERMINATE
#define THREAD_TERMINATE 0x0001
#endif
#ifndef THREAD_SUSPEND_RESUME
#define THREAD_SUSPEND_RESUME 0x0002
#endif
#ifndef THREAD_SET_CONTEXT
#define THREAD_SET_CONTEXT 0x0010
#endif
#ifndef THREAD_SET_INFORMATION
#define THREAD_SET_INFORMATION 0x0020
#endif
#ifndef THREAD_SET_LIMITED_INFORMATION
#define THREAD_SET_LIMITED_INFORMATION 0x0400
#endif
#ifndef THREAD_DIRECT_IMPERSONATION
#define THREAD_DIRECT_IMPERSONATION 0x0200
#endif

static ACCESS_MASK
KswordArkObjectBuildStripMask(
    _In_ POBJECT_TYPE objectType
    )
{
    if (objectType == *PsProcessType) {
        return (ACCESS_MASK)(
            PROCESS_TERMINATE |
            PROCESS_CREATE_THREAD |
            PROCESS_VM_OPERATION |
            PROCESS_VM_WRITE |
            PROCESS_DUP_HANDLE |
            PROCESS_SET_INFORMATION |
            PROCESS_SET_QUOTA |
            PROCESS_SUSPEND_RESUME |
            WRITE_DAC |
            WRITE_OWNER);
    }

    if (objectType == *PsThreadType) {
        return (ACCESS_MASK)(
            THREAD_TERMINATE |
            THREAD_SUSPEND_RESUME |
            THREAD_SET_CONTEXT |
            THREAD_SET_INFORMATION |
            THREAD_SET_LIMITED_INFORMATION |
            THREAD_DIRECT_IMPERSONATION |
            WRITE_DAC |
            WRITE_OWNER);
    }

    return 0U;
}

OB_PREOP_CALLBACK_STATUS
KswordArkObjectPreOperation(
    _In_ PVOID RegistrationContext,
    _Inout_ POB_PRE_OPERATION_INFORMATION OperationInformation
    )
{
    KSWORD_ARK_CALLBACK_RUNTIME* runtime = (KSWORD_ARK_CALLBACK_RUNTIME*)RegistrationContext;
    KSWORD_ARK_CALLBACK_MATCH_RESULT matchResult;
    ULONG operationType = 0U;
    ULONG callbackOperationMask = 0U;
    UNICODE_STRING initiatorPath = { 0 };
    UNICODE_STRING targetPath = { 0 };
    WCHAR initiatorPathBuffer[KSWORD_ARK_CALLBACK_EVENT_MAX_INITIATOR_CHARS] = { 0 };
    WCHAR targetPathBuffer[KSWORD_ARK_CALLBACK_EVENT_MAX_TARGET_CHARS] = { 0 };
    ACCESS_MASK* desiredAccessPointer = NULL;
    ACCESS_MASK originalDesiredAccess = 0U;
    ACCESS_MASK stripMask = 0U;
    ACCESS_MASK strippedAccess = 0U;
    PEPROCESS targetProcess = NULL;
    BOOLEAN targetIsThreadObject = FALSE;
    NTSTATUS matchStatus = STATUS_SUCCESS;

    UNREFERENCED_PARAMETER(runtime);

    if (OperationInformation == NULL ||
        OperationInformation->KernelHandle ||
        OperationInformation->ObjectType == NULL) {
        return OB_PREOP_SUCCESS;
    }

    if (OperationInformation->ObjectType != *PsProcessType &&
        OperationInformation->ObjectType != *PsThreadType) {
        return OB_PREOP_SUCCESS;
    }

    if (OperationInformation->Operation == OB_OPERATION_HANDLE_CREATE) {
        operationType = KSWORD_ARK_OBJECT_OP_HANDLE_CREATE;
        desiredAccessPointer = &OperationInformation->Parameters->CreateHandleInformation.DesiredAccess;
    }
    else if (OperationInformation->Operation == OB_OPERATION_HANDLE_DUPLICATE) {
        operationType = KSWORD_ARK_OBJECT_OP_HANDLE_DUPLICATE;
        desiredAccessPointer = &OperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess;
    }
    else {
        return OB_PREOP_SUCCESS;
    }

    if (OperationInformation->ObjectType == *PsProcessType) {
        callbackOperationMask = operationType | KSWORD_ARK_OBJECT_OP_TYPE_PROCESS;
        targetProcess = (PEPROCESS)OperationInformation->Object;
    }
    else {
        callbackOperationMask = operationType | KSWORD_ARK_OBJECT_OP_TYPE_THREAD;
        targetIsThreadObject = TRUE;
        targetProcess = PsGetThreadProcess((PETHREAD)OperationInformation->Object);
    }

    if (targetProcess != NULL) {
        (VOID)KswordArkResolveProcessImagePath(
            targetProcess,
            targetPathBuffer,
            RTL_NUMBER_OF(targetPathBuffer),
            NULL);
    }

    (VOID)KswordArkResolveProcessImagePath(
        PsGetCurrentProcess(),
        initiatorPathBuffer,
        RTL_NUMBER_OF(initiatorPathBuffer),
        NULL);
    RtlInitUnicodeString(&initiatorPath, initiatorPathBuffer);

    // 进程保护先于通用回调规则执行：它有自己的规则表和信任白名单，两者削掉的
    // 权限位取并集。这里复用已经解析好的映像路径，避免在句柄热路径上重复调用
    // SeLocateProcessImageName；占位串在保护判定之后才写入，保证保护规则看到的
    // 是真实路径或空串，而不是诊断文本。
    (VOID)KswordArkProcessProtectFilterHandleOperation(
        targetIsThreadObject,
        targetProcess,
        targetPathBuffer,
        initiatorPathBuffer,
        desiredAccessPointer);

    if (targetPathBuffer[0] == L'\0') {
        (VOID)RtlStringCbPrintfW(
            targetPathBuffer,
            sizeof(targetPathBuffer),
            L"ObjectType=%s,Operation=0x%08lX",
            (OperationInformation->ObjectType == *PsProcessType) ? L"Process" : L"Thread",
            (unsigned long)operationType);
    }
    RtlInitUnicodeString(&targetPath, targetPathBuffer);

    matchStatus = KswordArkCallbackMatchRule(
        KSWORD_ARK_CALLBACK_TYPE_OBJECT,
        callbackOperationMask,
        &initiatorPath,
        &targetPath,
        &matchResult);
    if (!NT_SUCCESS(matchStatus) || !matchResult.Matched) {
        return OB_PREOP_SUCCESS;
    }

    if (matchResult.Action == KSWORD_ARK_RULE_ACTION_LOG_ONLY) {
        KswordArkCallbackLogFormat(
            "Info",
            "Object callback log rule hit, objectType=%lu, operation=0x%08lX, groupId=%lu, ruleId=%lu.",
            (unsigned long)((OperationInformation->ObjectType == *PsProcessType) ? 1UL : 2UL),
            (unsigned long)callbackOperationMask,
            (unsigned long)matchResult.GroupId,
            (unsigned long)matchResult.RuleId);
        return OB_PREOP_SUCCESS;
    }

    if (matchResult.Action != KSWORD_ARK_RULE_ACTION_STRIP_ACCESS ||
        desiredAccessPointer == NULL) {
        return OB_PREOP_SUCCESS;
    }

    stripMask = KswordArkObjectBuildStripMask(OperationInformation->ObjectType);
    originalDesiredAccess = *desiredAccessPointer;
    strippedAccess = originalDesiredAccess & (~stripMask);
    *desiredAccessPointer = strippedAccess;

    KswordArkCallbackLogFormat(
        "Warn",
        "Object access stripped, objectType=%lu, op=0x%08lX, desired=0x%08lX->0x%08lX, groupId=%lu, ruleId=%lu.",
        (unsigned long)((OperationInformation->ObjectType == *PsProcessType) ? 1UL : 2UL),
        (unsigned long)callbackOperationMask,
        (unsigned long)originalDesiredAccess,
        (unsigned long)strippedAccess,
        (unsigned long)matchResult.GroupId,
        (unsigned long)matchResult.RuleId);
    return OB_PREOP_SUCCESS;
}

NTSTATUS
KswordArkObjectCallbackRegister(
    _In_ KSWORD_ARK_CALLBACK_RUNTIME* runtime
    )
{
    OB_CALLBACK_REGISTRATION callbackRegistration;
    OB_OPERATION_REGISTRATION operationRegistration[2];
    UNICODE_STRING altitudeText;
    NTSTATUS status = STATUS_SUCCESS;

    if (runtime == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    RtlZeroMemory(&callbackRegistration, sizeof(callbackRegistration));
    RtlZeroMemory(operationRegistration, sizeof(operationRegistration));
    RtlInitUnicodeString(&altitudeText, g_KswordArkObAltitude);

    operationRegistration[0].ObjectType = PsProcessType;
    operationRegistration[0].Operations =
        OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
    operationRegistration[0].PreOperation = KswordArkObjectPreOperation;
    operationRegistration[0].PostOperation = NULL;

    operationRegistration[1].ObjectType = PsThreadType;
    operationRegistration[1].Operations =
        OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
    operationRegistration[1].PreOperation = KswordArkObjectPreOperation;
    operationRegistration[1].PostOperation = NULL;

    callbackRegistration.Version = OB_FLT_REGISTRATION_VERSION;
    callbackRegistration.OperationRegistrationCount = RTL_NUMBER_OF(operationRegistration);
    callbackRegistration.RegistrationContext = runtime;
    callbackRegistration.Altitude = altitudeText;
    callbackRegistration.OperationRegistration = operationRegistration;

    status = ObRegisterCallbacks(&callbackRegistration, &runtime->ObRegistrationHandle);
    // 进程保护完全挂在这一个句柄回调上：注册结果必须回填，否则 R3 无法区分
    // "没配保护规则"和"这台机器上句柄回调根本挂不上"。
    KswordArkProcessProtectNoteObjectCallbackState(NT_SUCCESS(status) ? TRUE : FALSE, status);
    if (NT_SUCCESS(status)) {
        // 注册期全局 runtime 尚未发布，必须用显式 runtime 版本写日志。
        KswordArkCallbackLogFrameForRuntime(
            runtime,
            "Info",
            "Object callbacks registered for Process/Thread.");
    }
    return status;
}

VOID
KswordArkObjectCallbackUnregister(
    _In_ KSWORD_ARK_CALLBACK_RUNTIME* runtime
    )
{
    if (runtime == NULL) {
        return;
    }

    if (runtime->ObRegistrationHandle != NULL) {
        ObUnRegisterCallbacks(runtime->ObRegistrationHandle);
        runtime->ObRegistrationHandle = NULL;
        KswordArkProcessProtectNoteObjectCallbackState(FALSE, STATUS_NOT_SUPPORTED);
        KswordArkCallbackLogFrame("Info", "Object callbacks unregistered.");
    }
}
