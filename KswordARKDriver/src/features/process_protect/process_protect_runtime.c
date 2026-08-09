/*++

Module Name:

    process_protect_runtime.c

Abstract:

    Handle-callback based process protection runtime. The object manager
    pre-operation callback funnels every process/thread handle create and
    duplicate through this module; matching targets get the dangerous access
    bits stripped from DesiredAccess before the handle is granted.

Environment:

    Kernel-mode Driver Framework

--*/

#include "process_protect_internal.h"

#ifndef PROCESS_TERMINATE
#define PROCESS_TERMINATE 0x0001
#endif
#ifndef PROCESS_CREATE_THREAD
#define PROCESS_CREATE_THREAD 0x0002
#endif
#ifndef PROCESS_VM_OPERATION
#define PROCESS_VM_OPERATION 0x0008
#endif
#ifndef PROCESS_VM_READ
#define PROCESS_VM_READ 0x0010
#endif
#ifndef PROCESS_VM_WRITE
#define PROCESS_VM_WRITE 0x0020
#endif
#ifndef PROCESS_DUP_HANDLE
#define PROCESS_DUP_HANDLE 0x0040
#endif
#ifndef PROCESS_SET_QUOTA
#define PROCESS_SET_QUOTA 0x0100
#endif
#ifndef PROCESS_SET_INFORMATION
#define PROCESS_SET_INFORMATION 0x0200
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
#ifndef THREAD_GET_CONTEXT
#define THREAD_GET_CONTEXT 0x0008
#endif
#ifndef THREAD_SET_CONTEXT
#define THREAD_SET_CONTEXT 0x0010
#endif
#ifndef THREAD_SET_INFORMATION
#define THREAD_SET_INFORMATION 0x0020
#endif
#ifndef THREAD_DIRECT_IMPERSONATION
#define THREAD_DIRECT_IMPERSONATION 0x0200
#endif
#ifndef THREAD_SET_LIMITED_INFORMATION
#define THREAD_SET_LIMITED_INFORMATION 0x0400
#endif

static EX_PUSH_LOCK g_KswordArkProcessProtectPublishLock;
static KSWORD_ARK_PROCESS_PROTECT_STATE* g_KswordArkProcessProtectState = NULL;

KSWORD_ARK_PROCESS_PROTECT_STATE*
KswordArkProcessProtectGetState(
    VOID
    )
{
    return g_KswordArkProcessProtectState;
}

static VOID
KswordArkProcessProtectLog(
    _In_ KSWORD_ARK_PROCESS_PROTECT_STATE* State,
    _In_z_ PCSTR LevelText,
    _In_z_ _Printf_format_string_ PCSTR FormatText,
    ...
    )
{
    CHAR logBuffer[KSWORD_ARK_LOG_ENTRY_MAX_BYTES] = { 0 };
    va_list argumentList;

    if (State == NULL || State->Device == WDF_NO_HANDLE) {
        return;
    }

    va_start(argumentList, FormatText);
    if (NT_SUCCESS(RtlStringCbVPrintfA(logBuffer, sizeof(logBuffer), FormatText, argumentList))) {
        (VOID)KswordARKDriverEnqueueLogFrame(State->Device, LevelText, logBuffer);
    }
    va_end(argumentList);
}

static VOID
KswordArkProcessProtectCopyFixedWide(
    _Out_writes_(DestinationChars) PWCHAR Destination,
    _In_ ULONG DestinationChars,
    _In_opt_z_ PCWSTR Source
    )
{
    size_t sourceChars = 0;

    if (Destination == NULL || DestinationChars == 0UL) {
        return;
    }

    Destination[0] = L'\0';
    if (Source == NULL) {
        return;
    }

    if (!NT_SUCCESS(RtlStringCchLengthW(Source, DestinationChars, &sourceChars))) {
        sourceChars = (size_t)DestinationChars - 1U;
    }
    if (sourceChars >= (size_t)DestinationChars) {
        sourceChars = (size_t)DestinationChars - 1U;
    }
    if (sourceChars != 0U) {
        RtlCopyMemory(Destination, Source, sourceChars * sizeof(WCHAR));
    }
    Destination[sourceChars] = L'\0';
}

static SIZE_T
KswordArkProcessProtectTextLength(
    _In_opt_z_ PCWSTR Text,
    _In_ SIZE_T MaxChars
    )
{
    size_t textChars = 0;

    if (Text == NULL || MaxChars == 0U) {
        return 0U;
    }
    if (!NT_SUCCESS(RtlStringCchLengthW(Text, MaxChars, &textChars))) {
        return MaxChars;
    }
    return (SIZE_T)textChars;
}

static BOOLEAN
KswordArkProcessProtectCharEquals(
    _In_ WCHAR LeftChar,
    _In_ WCHAR RightChar
    )
{
    return (RtlUpcaseUnicodeChar(LeftChar) == RtlUpcaseUnicodeChar(RightChar)) ? TRUE : FALSE;
}

static PCWSTR
KswordArkProcessProtectFindFileName(
    _In_opt_z_ PCWSTR PathText,
    _In_ SIZE_T PathChars
    )
/*++

Routine Description:

    Return the trailing file-name component of a path. Both NT paths
    (\Device\HarddiskVolume3\Windows\notepad.exe) and Win32 paths
    (C:\Windows\notepad.exe) use backslash, so one scan covers both.

--*/
{
    SIZE_T scanIndex = 0;
    PCWSTR fileNameText = PathText;

    if (PathText == NULL) {
        return NULL;
    }

    for (scanIndex = 0; scanIndex < PathChars; ++scanIndex) {
        if (PathText[scanIndex] == L'\\' || PathText[scanIndex] == L'/') {
            fileNameText = &PathText[scanIndex + 1U];
        }
    }
    return fileNameText;
}

static BOOLEAN
KswordArkProcessProtectImageNameMatch(
    _In_opt_z_ PCWSTR PatternText,
    _In_opt_z_ PCWSTR ImagePathText
    )
{
    SIZE_T patternChars = KswordArkProcessProtectTextLength(PatternText, KSWORD_ARK_PROCESS_PROTECT_IMAGE_CHARS);
    SIZE_T imageChars = KswordArkProcessProtectTextLength(ImagePathText, KSWORD_ARK_PROCESS_PROTECT_IMAGE_CHARS);
    PCWSTR imageFileName = NULL;
    SIZE_T fileNameChars = 0;
    SIZE_T compareIndex = 0;

    if (patternChars == 0U || imageChars == 0U) {
        return FALSE;
    }

    // 规则里也允许写完整路径；统一只比较末段文件名。
    PatternText = KswordArkProcessProtectFindFileName(PatternText, patternChars);
    patternChars = KswordArkProcessProtectTextLength(PatternText, KSWORD_ARK_PROCESS_PROTECT_IMAGE_CHARS);

    imageFileName = KswordArkProcessProtectFindFileName(ImagePathText, imageChars);
    fileNameChars = KswordArkProcessProtectTextLength(imageFileName, KSWORD_ARK_PROCESS_PROTECT_IMAGE_CHARS);

    if (patternChars == 0U || patternChars != fileNameChars) {
        return FALSE;
    }

    for (compareIndex = 0; compareIndex < patternChars; ++compareIndex) {
        if (!KswordArkProcessProtectCharEquals(PatternText[compareIndex], imageFileName[compareIndex])) {
            return FALSE;
        }
    }
    return TRUE;
}

static BOOLEAN
KswordArkProcessProtectImagePathMatch(
    _In_opt_z_ PCWSTR PatternText,
    _In_opt_z_ PCWSTR ImagePathText
    )
/*++

Routine Description:

    Case-insensitive suffix match between a configured path and the resolved
    image path. R0 sees NT paths while R3 usually stores Win32 paths, so a
    leading drive specifier is dropped from the pattern first; the remainder
    (\Windows\notepad.exe) is then matched against the tail of the NT path.

--*/
{
    SIZE_T patternChars = KswordArkProcessProtectTextLength(PatternText, KSWORD_ARK_PROCESS_PROTECT_IMAGE_CHARS);
    SIZE_T imageChars = KswordArkProcessProtectTextLength(ImagePathText, KSWORD_ARK_PROCESS_PROTECT_IMAGE_CHARS);
    SIZE_T suffixStart = 0;
    SIZE_T compareIndex = 0;

    if (patternChars == 0U || imageChars == 0U) {
        return FALSE;
    }

    // 去掉 "C:" 形式的盘符前缀，让 Win32 路径也能匹配到 NT 路径尾部。
    if (patternChars > 2U && PatternText[1] == L':') {
        PatternText += 2;
        patternChars -= 2U;
    }

    if (patternChars == 0U || patternChars > imageChars) {
        return FALSE;
    }

    suffixStart = imageChars - patternChars;
    for (compareIndex = 0; compareIndex < patternChars; ++compareIndex) {
        if (!KswordArkProcessProtectCharEquals(
                PatternText[compareIndex],
                ImagePathText[suffixStart + compareIndex])) {
            return FALSE;
        }
    }
    return TRUE;
}

static BOOLEAN
KswordArkProcessProtectIdentityMatch(
    _In_ ULONG TargetKind,
    _In_ ULONG ConfiguredProcessId,
    _In_opt_z_ PCWSTR ConfiguredImage,
    _In_ ULONG CandidateProcessId,
    _In_opt_z_ PCWSTR CandidateImagePath
    )
{
    switch (TargetKind) {
    case KSWORD_ARK_PROCESS_PROTECT_TARGET_KIND_PID:
        return (ConfiguredProcessId != 0UL && ConfiguredProcessId == CandidateProcessId) ? TRUE : FALSE;

    case KSWORD_ARK_PROCESS_PROTECT_TARGET_KIND_IMAGE_NAME:
        return KswordArkProcessProtectImageNameMatch(ConfiguredImage, CandidateImagePath);

    case KSWORD_ARK_PROCESS_PROTECT_TARGET_KIND_IMAGE_PATH:
        return KswordArkProcessProtectImagePathMatch(ConfiguredImage, CandidateImagePath);

    default:
        return FALSE;
    }
}

static ACCESS_MASK
KswordArkProcessProtectBuildProcessStripMask(
    _In_ ULONG ProtectAccessMask
    )
{
    ACCESS_MASK stripMask = 0U;

    if ((ProtectAccessMask & KSWORD_ARK_PROCESS_PROTECT_ACCESS_TERMINATE) != 0UL) {
        stripMask |= PROCESS_TERMINATE;
    }
    if ((ProtectAccessMask & KSWORD_ARK_PROCESS_PROTECT_ACCESS_VM_READ) != 0UL) {
        stripMask |= PROCESS_VM_READ;
    }
    if ((ProtectAccessMask & KSWORD_ARK_PROCESS_PROTECT_ACCESS_VM_WRITE) != 0UL) {
        stripMask |= (PROCESS_VM_OPERATION | PROCESS_VM_WRITE);
    }
    if ((ProtectAccessMask & KSWORD_ARK_PROCESS_PROTECT_ACCESS_CREATE_THREAD) != 0UL) {
        stripMask |= PROCESS_CREATE_THREAD;
    }
    if ((ProtectAccessMask & KSWORD_ARK_PROCESS_PROTECT_ACCESS_SUSPEND_RESUME) != 0UL) {
        stripMask |= PROCESS_SUSPEND_RESUME;
    }
    if ((ProtectAccessMask & KSWORD_ARK_PROCESS_PROTECT_ACCESS_SET_INFORMATION) != 0UL) {
        stripMask |= (PROCESS_SET_INFORMATION | PROCESS_SET_QUOTA | WRITE_DAC | WRITE_OWNER);
    }
    if ((ProtectAccessMask & KSWORD_ARK_PROCESS_PROTECT_ACCESS_DUP_HANDLE) != 0UL) {
        stripMask |= PROCESS_DUP_HANDLE;
    }
    return stripMask;
}

static ACCESS_MASK
KswordArkProcessProtectBuildThreadStripMask(
    _In_ ULONG ProtectAccessMask
    )
/*++

Routine Description:

    Project the same protection switches onto thread handles. CREATE_THREAD and
    DUP_HANDLE have no thread-object counterpart and are intentionally dropped;
    direct impersonation is grouped with VM_WRITE because both let the caller
    take over thread execution.

--*/
{
    ACCESS_MASK stripMask = 0U;

    if ((ProtectAccessMask & KSWORD_ARK_PROCESS_PROTECT_ACCESS_TERMINATE) != 0UL) {
        stripMask |= THREAD_TERMINATE;
    }
    if ((ProtectAccessMask & KSWORD_ARK_PROCESS_PROTECT_ACCESS_VM_READ) != 0UL) {
        stripMask |= THREAD_GET_CONTEXT;
    }
    if ((ProtectAccessMask & KSWORD_ARK_PROCESS_PROTECT_ACCESS_VM_WRITE) != 0UL) {
        stripMask |= (THREAD_SET_CONTEXT | THREAD_DIRECT_IMPERSONATION);
    }
    if ((ProtectAccessMask & KSWORD_ARK_PROCESS_PROTECT_ACCESS_SUSPEND_RESUME) != 0UL) {
        stripMask |= THREAD_SUSPEND_RESUME;
    }
    if ((ProtectAccessMask & KSWORD_ARK_PROCESS_PROTECT_ACCESS_SET_INFORMATION) != 0UL) {
        stripMask |= (THREAD_SET_INFORMATION | THREAD_SET_LIMITED_INFORMATION | WRITE_DAC | WRITE_OWNER);
    }
    return stripMask;
}

static VOID
KswordArkProcessProtectRecordLastBlocked(
    _Inout_ KSWORD_ARK_PROCESS_PROTECT_STATE* State,
    _In_ BOOLEAN TargetIsThreadObject,
    _In_ ULONG InitiatorProcessId,
    _In_ ULONG TargetProcessId,
    _In_ ULONG RuleId,
    _In_ ACCESS_MASK OriginalAccess,
    _In_ ACCESS_MASK GrantedAccess,
    _In_opt_z_ PCWSTR InitiatorImagePath,
    _In_opt_z_ PCWSTR TargetImagePath
    )
{
    LARGE_INTEGER nowUtc = { 0 };

    KeQuerySystemTimePrecise(&nowUtc);

    KswordARKAcquirePushLockExclusive(&State->LastBlockedLock);
    State->LastBlockedUtc100ns = nowUtc;
    State->LastBlockedInitiatorPid = InitiatorProcessId;
    State->LastBlockedTargetPid = TargetProcessId;
    State->LastBlockedRuleId = RuleId;
    State->LastBlockedOriginalAccess = (ULONG)OriginalAccess;
    State->LastBlockedGrantedAccess = (ULONG)GrantedAccess;
    State->LastBlockedIsThreadObject = TargetIsThreadObject ? 1UL : 0UL;
    KswordArkProcessProtectCopyFixedWide(
        State->LastBlockedInitiatorImage,
        KSWORD_ARK_PROCESS_PROTECT_IMAGE_CHARS,
        InitiatorImagePath);
    KswordArkProcessProtectCopyFixedWide(
        State->LastBlockedTargetImage,
        KSWORD_ARK_PROCESS_PROTECT_IMAGE_CHARS,
        TargetImagePath);
    KswordARKReleasePushLockExclusive(&State->LastBlockedLock);
}

BOOLEAN
KswordArkProcessProtectFilterHandleOperation(
    _In_ BOOLEAN TargetIsThreadObject,
    _In_opt_ PEPROCESS TargetProcess,
    _In_opt_z_ PCWSTR TargetImagePath,
    _In_opt_z_ PCWSTR InitiatorImagePath,
    _Inout_ ACCESS_MASK* DesiredAccess
    )
/*++

Routine Description:

    Evaluate one process/thread handle operation against the protection config
    and strip the configured access bits in place.

Arguments:

    TargetIsThreadObject - TRUE when the opened object is a thread.
    TargetProcess - Target process, or the thread's host process. May be NULL.
    TargetImagePath - Caller-resolved target image path. May be NULL or empty.
    InitiatorImagePath - Caller-resolved requestor image path.
    DesiredAccess - Object manager access mask, modified in place on a hit.

Return Value:

    TRUE when at least one access bit was removed.

--*/
{
    KSWORD_ARK_PROCESS_PROTECT_STATE* state = KswordArkProcessProtectGetState();
    PEPROCESS initiatorProcess = PsGetCurrentProcess();
    ULONG initiatorProcessId = HandleToULong(PsGetCurrentProcessId());
    ULONG targetProcessId = 0UL;
    ULONG globalFlags = 0UL;
    ULONG matchedRuleId = 0UL;
    ULONG matchedRuleIndex = 0UL;
    ULONG ruleIndex = 0UL;
    ACCESS_MASK stripMask = 0U;
    ACCESS_MASK originalAccess = 0U;
    ACCESS_MASK grantedAccess = 0U;
    BOOLEAN trustedInitiator = FALSE;
    BOOLEAN matched = FALSE;
    BOOLEAN logBlocked = FALSE;

    if (state == NULL || DesiredAccess == NULL) {
        return FALSE;
    }

    // 目标进程自己打开自己必须始终放行，否则受保护进程连自身句柄都拿不全。
    if (TargetProcess != NULL && TargetProcess == initiatorProcess) {
        return FALSE;
    }

    if (TargetProcess != NULL) {
        targetProcessId = HandleToULong(PsGetProcessId(TargetProcess));
    }

    KswordARKAcquirePushLockShared(&state->ConfigLock);

    globalFlags = state->GlobalFlags;
    if ((globalFlags & KSWORD_ARK_PROCESS_PROTECT_FLAG_ENABLED) == 0UL ||
        state->RuleCount == 0UL) {
        KswordARKReleasePushLockShared(&state->ConfigLock);
        return FALSE;
    }

    (VOID)InterlockedIncrement64(&state->EvaluatedCount);

    // System/Idle 承担进程创建与退出清理，默认信任；关闭该开关属于高风险配置。
    if ((globalFlags & KSWORD_ARK_PROCESS_PROTECT_FLAG_TRUST_SYSTEM) != 0UL &&
        initiatorProcessId <= 4UL) {
        trustedInitiator = TRUE;
    }

    for (ruleIndex = 0UL; !trustedInitiator && ruleIndex < state->TrustedCount; ++ruleIndex) {
        const KSWORD_ARK_PROCESS_PROTECT_TRUSTED* trustedEntry = &state->Trusted[ruleIndex];
        if ((trustedEntry->flags & KSWORD_ARK_PROCESS_PROTECT_TRUSTED_FLAG_ENABLED) == 0UL) {
            continue;
        }
        if (KswordArkProcessProtectIdentityMatch(
                trustedEntry->kind,
                trustedEntry->processId,
                trustedEntry->image,
                initiatorProcessId,
                InitiatorImagePath)) {
            trustedInitiator = TRUE;
        }
    }

    for (ruleIndex = 0UL; ruleIndex < state->RuleCount; ++ruleIndex) {
        const KSWORD_ARK_PROCESS_PROTECT_RULE* protectRule = &state->Rules[ruleIndex];

        if ((protectRule->flags & KSWORD_ARK_PROCESS_PROTECT_RULE_FLAG_ENABLED) == 0UL) {
            continue;
        }

        // 受保护进程互信：发起方只要也在这张表里就整体放行，不必再看目标命中哪条。
        if ((globalFlags & KSWORD_ARK_PROCESS_PROTECT_FLAG_TRUST_PROTECTED_PEERS) != 0UL &&
            KswordArkProcessProtectIdentityMatch(
                protectRule->targetKind,
                protectRule->targetProcessId,
                protectRule->targetImage,
                initiatorProcessId,
                InitiatorImagePath)) {
            trustedInitiator = TRUE;
            break;
        }

        if (!matched &&
            (!TargetIsThreadObject ||
                (protectRule->flags & KSWORD_ARK_PROCESS_PROTECT_RULE_FLAG_PROTECT_THREADS) != 0UL) &&
            KswordArkProcessProtectIdentityMatch(
                protectRule->targetKind,
                protectRule->targetProcessId,
                protectRule->targetImage,
                targetProcessId,
                TargetImagePath)) {
            matched = TRUE;
            matchedRuleId = protectRule->ruleId;
            matchedRuleIndex = ruleIndex;
            stripMask = TargetIsThreadObject
                ? KswordArkProcessProtectBuildThreadStripMask(protectRule->protectAccessMask)
                : KswordArkProcessProtectBuildProcessStripMask(protectRule->protectAccessMask);
        }

        // 句柄创建是热路径：目标已命中且不需要继续搜索互信发起方时立即收尾。
        if (matched &&
            (globalFlags & KSWORD_ARK_PROCESS_PROTECT_FLAG_TRUST_PROTECTED_PEERS) == 0UL) {
            break;
        }
    }

    logBlocked = ((globalFlags & KSWORD_ARK_PROCESS_PROTECT_FLAG_LOG_BLOCKED) != 0UL) ? TRUE : FALSE;
    KswordARKReleasePushLockShared(&state->ConfigLock);

    if (trustedInitiator) {
        (VOID)InterlockedIncrement64(&state->TrustedBypassCount);
        return FALSE;
    }

    if (!matched || stripMask == 0U) {
        return FALSE;
    }

    originalAccess = *DesiredAccess;
    grantedAccess = originalAccess & (~stripMask);
    if (grantedAccess == originalAccess) {
        return FALSE;
    }

    *DesiredAccess = grantedAccess;
    (VOID)InterlockedIncrement64(&state->StrippedCount);
    (VOID)InterlockedIncrement64(&state->RuleHitCounts[matchedRuleIndex]);
    KswordArkProcessProtectRecordLastBlocked(
        state,
        TargetIsThreadObject,
        initiatorProcessId,
        targetProcessId,
        matchedRuleId,
        originalAccess,
        grantedAccess,
        InitiatorImagePath,
        TargetImagePath);

    if (logBlocked) {
        KswordArkProcessProtectLog(
            state,
            "Warn",
            "Process protection stripped access, object=%s, initiatorPid=%lu, targetPid=%lu, "
            "ruleId=%lu, desired=0x%08lX->0x%08lX.",
            TargetIsThreadObject ? "Thread" : "Process",
            (unsigned long)initiatorProcessId,
            (unsigned long)targetProcessId,
            (unsigned long)matchedRuleId,
            (unsigned long)originalAccess,
            (unsigned long)grantedAccess);
    }
    return TRUE;
}

VOID
KswordArkProcessProtectNoteObjectCallbackState(
    _In_ BOOLEAN Registered,
    _In_ NTSTATUS RegisterStatus
    )
{
    KSWORD_ARK_PROCESS_PROTECT_STATE* state = KswordArkProcessProtectGetState();

    if (state == NULL) {
        return;
    }

    (VOID)InterlockedExchange(&state->ObjectCallbackRegistered, Registered ? 1L : 0L);
    (VOID)InterlockedExchange(&state->ObjectCallbackStatus, (LONG)RegisterStatus);
}

NTSTATUS
KswordARKProcessProtectInitialize(
    _In_ WDFDEVICE Device
    )
{
    KSWORD_ARK_PROCESS_PROTECT_STATE* state = NULL;

    if (Device == WDF_NO_HANDLE) {
        return STATUS_INVALID_PARAMETER;
    }

    KswordARKAcquirePushLockExclusive(&g_KswordArkProcessProtectPublishLock);
    if (g_KswordArkProcessProtectState != NULL) {
        KswordARKReleasePushLockExclusive(&g_KswordArkProcessProtectPublishLock);
        return STATUS_SUCCESS;
    }

    state = (KSWORD_ARK_PROCESS_PROTECT_STATE*)KswordArkAllocateNonPaged(
        sizeof(KSWORD_ARK_PROCESS_PROTECT_STATE),
        KSWORD_ARK_PROCESS_PROTECT_TAG_STATE);
    if (state == NULL) {
        KswordARKReleasePushLockExclusive(&g_KswordArkProcessProtectPublishLock);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(state, sizeof(*state));
    state->Device = Device;
    ExInitializePushLock(&state->ConfigLock);
    ExInitializePushLock(&state->LastBlockedLock);
    // 默认信任 System，避免用户还没配白名单就把系统清理路径也削权。
    state->GlobalFlags = KSWORD_ARK_PROCESS_PROTECT_FLAG_TRUST_SYSTEM;
    state->ObjectCallbackStatus = (LONG)STATUS_NOT_SUPPORTED;

    g_KswordArkProcessProtectState = state;
    KswordARKReleasePushLockExclusive(&g_KswordArkProcessProtectPublishLock);
    return STATUS_SUCCESS;
}

VOID
KswordARKProcessProtectUninitialize(
    VOID
    )
{
    KSWORD_ARK_PROCESS_PROTECT_STATE* state = NULL;

    KswordARKAcquirePushLockExclusive(&g_KswordArkProcessProtectPublishLock);
    state = g_KswordArkProcessProtectState;
    g_KswordArkProcessProtectState = NULL;
    KswordARKReleasePushLockExclusive(&g_KswordArkProcessProtectPublishLock);

    if (state != NULL) {
        ExFreePoolWithTag(state, KSWORD_ARK_PROCESS_PROTECT_TAG_STATE);
    }
}

static NTSTATUS
KswordArkProcessProtectValidateRule(
    _In_ const KSWORD_ARK_PROCESS_PROTECT_RULE* Rule
    )
{
    if ((Rule->flags & KSWORD_ARK_PROCESS_PROTECT_RULE_FLAG_ENABLED) == 0UL) {
        // 未启用的规则是 R3 的草稿行，只做长度裁剪，不做语义校验。
        return STATUS_SUCCESS;
    }

    if ((Rule->protectAccessMask & KSWORD_ARK_PROCESS_PROTECT_ACCESS_ALL) == 0UL) {
        return STATUS_INVALID_PARAMETER;
    }

    switch (Rule->targetKind) {
    case KSWORD_ARK_PROCESS_PROTECT_TARGET_KIND_PID:
        return (Rule->targetProcessId != 0UL) ? STATUS_SUCCESS : STATUS_INVALID_PARAMETER;

    case KSWORD_ARK_PROCESS_PROTECT_TARGET_KIND_IMAGE_NAME:
    case KSWORD_ARK_PROCESS_PROTECT_TARGET_KIND_IMAGE_PATH:
        return (Rule->targetImage[0] != L'\0') ? STATUS_SUCCESS : STATUS_INVALID_PARAMETER;

    default:
        return STATUS_INVALID_PARAMETER;
    }
}

static NTSTATUS
KswordArkProcessProtectValidateTrusted(
    _In_ const KSWORD_ARK_PROCESS_PROTECT_TRUSTED* Trusted
    )
{
    if ((Trusted->flags & KSWORD_ARK_PROCESS_PROTECT_TRUSTED_FLAG_ENABLED) == 0UL) {
        return STATUS_SUCCESS;
    }

    switch (Trusted->kind) {
    case KSWORD_ARK_PROCESS_PROTECT_TARGET_KIND_PID:
        return (Trusted->processId != 0UL) ? STATUS_SUCCESS : STATUS_INVALID_PARAMETER;

    case KSWORD_ARK_PROCESS_PROTECT_TARGET_KIND_IMAGE_NAME:
    case KSWORD_ARK_PROCESS_PROTECT_TARGET_KIND_IMAGE_PATH:
        return (Trusted->image[0] != L'\0') ? STATUS_SUCCESS : STATUS_INVALID_PARAMETER;

    default:
        return STATUS_INVALID_PARAMETER;
    }
}

NTSTATUS
KswordARKProcessProtectIoctlSetConfig(
    _In_ WDFREQUEST Request,
    _In_ size_t InputBufferLength,
    _Out_ size_t* CompleteBytesOut
    )
/*++

Routine Description:

    Validate and install one complete protection configuration. The packet is a
    full replacement: whatever is absent from it stops being protected.

--*/
{
    KSWORD_ARK_PROCESS_PROTECT_STATE* state = KswordArkProcessProtectGetState();
    const KSWORD_ARK_PROCESS_PROTECT_CONFIG_REQUEST* requestPacket = NULL;
    PVOID inputBuffer = NULL;
    size_t inputLength = 0U;
    LARGE_INTEGER nowUtc = { 0 };
    ULONG64 appliedConfigVersion = 0ULL;
    ULONG entryIndex = 0UL;
    NTSTATUS status = STATUS_SUCCESS;

    if (CompleteBytesOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *CompleteBytesOut = 0U;

    if (state == NULL) {
        return STATUS_DEVICE_NOT_READY;
    }
    if (InputBufferLength < sizeof(KSWORD_ARK_PROCESS_PROTECT_CONFIG_REQUEST)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    status = WdfRequestRetrieveInputBuffer(
        Request,
        sizeof(KSWORD_ARK_PROCESS_PROTECT_CONFIG_REQUEST),
        &inputBuffer,
        &inputLength);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    if (inputLength < sizeof(KSWORD_ARK_PROCESS_PROTECT_CONFIG_REQUEST)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    requestPacket = (const KSWORD_ARK_PROCESS_PROTECT_CONFIG_REQUEST*)inputBuffer;
    if (requestPacket->size < sizeof(KSWORD_ARK_PROCESS_PROTECT_CONFIG_REQUEST) ||
        requestPacket->version != KSWORD_ARK_PROCESS_PROTECT_PROTOCOL_VERSION ||
        requestPacket->ruleCount > KSWORD_ARK_PROCESS_PROTECT_MAX_RULES ||
        requestPacket->trustedCount > KSWORD_ARK_PROCESS_PROTECT_MAX_TRUSTED) {
        return STATUS_INVALID_PARAMETER;
    }

    KswordARKAcquirePushLockExclusive(&state->ConfigLock);

    RtlZeroMemory(state->Rules, sizeof(state->Rules));
    RtlZeroMemory(state->Trusted, sizeof(state->Trusted));

    for (entryIndex = 0UL; entryIndex < requestPacket->ruleCount; ++entryIndex) {
        KSWORD_ARK_PROCESS_PROTECT_RULE* targetRule = &state->Rules[entryIndex];

        *targetRule = requestPacket->rules[entryIndex];
        // R3 送来的字符串未必带终止符；先裁剪再校验，后续比较全部按 NUL 结尾处理。
        targetRule->targetImage[KSWORD_ARK_PROCESS_PROTECT_IMAGE_CHARS - 1U] = L'\0';
        targetRule->ruleName[KSWORD_ARK_PROCESS_PROTECT_NAME_CHARS - 1U] = L'\0';
        targetRule->protectAccessMask &= KSWORD_ARK_PROCESS_PROTECT_ACCESS_ALL;
        if (targetRule->targetKind != KSWORD_ARK_PROCESS_PROTECT_TARGET_KIND_PID) {
            targetRule->targetProcessId = 0UL;
        }

        status = KswordArkProcessProtectValidateRule(targetRule);
        if (!NT_SUCCESS(status)) {
            break;
        }
    }

    if (NT_SUCCESS(status)) {
        for (entryIndex = 0UL; entryIndex < requestPacket->trustedCount; ++entryIndex) {
            KSWORD_ARK_PROCESS_PROTECT_TRUSTED* targetTrusted = &state->Trusted[entryIndex];

            *targetTrusted = requestPacket->trusted[entryIndex];
            targetTrusted->image[KSWORD_ARK_PROCESS_PROTECT_IMAGE_CHARS - 1U] = L'\0';
            if (targetTrusted->kind != KSWORD_ARK_PROCESS_PROTECT_TARGET_KIND_PID) {
                targetTrusted->processId = 0UL;
            }

            status = KswordArkProcessProtectValidateTrusted(targetTrusted);
            if (!NT_SUCCESS(status)) {
                break;
            }
        }
    }

    if (!NT_SUCCESS(status)) {
        // 校验失败时不保留半张表：整体回退到"无规则"，比留下残缺配置安全。
        RtlZeroMemory(state->Rules, sizeof(state->Rules));
        RtlZeroMemory(state->Trusted, sizeof(state->Trusted));
        state->RuleCount = 0UL;
        state->TrustedCount = 0UL;
        KswordARKReleasePushLockExclusive(&state->ConfigLock);
        KswordArkProcessProtectLog(
            state,
            "Warn",
            "Process protection config rejected, status=0x%08lX.",
            (unsigned long)status);
        return status;
    }

    KeQuerySystemTimePrecise(&nowUtc);
    state->GlobalFlags = requestPacket->globalFlags;
    state->RuleCount = requestPacket->ruleCount;
    state->TrustedCount = requestPacket->trustedCount;
    state->ConfigVersion += 1ULL;
    state->AppliedAtUtc100ns = nowUtc;
    // 规则表已整体替换，旧命中计数不再对应任何一行，逐项清零而不是整块 memset：
    // RuleHitCounts 是 volatile 数组，整块清零需要丢弃 volatile 限定。
    for (entryIndex = 0UL; entryIndex < KSWORD_ARK_PROCESS_PROTECT_MAX_RULES; ++entryIndex) {
        state->RuleHitCounts[entryIndex] = 0LL;
    }
    appliedConfigVersion = state->ConfigVersion;

    KswordARKReleasePushLockExclusive(&state->ConfigLock);

    KswordArkProcessProtectLog(
        state,
        "Info",
        "Process protection config applied, enabled=%lu, rules=%lu, trusted=%lu, version=%I64u.",
        (unsigned long)((requestPacket->globalFlags & KSWORD_ARK_PROCESS_PROTECT_FLAG_ENABLED) != 0UL ? 1UL : 0UL),
        (unsigned long)requestPacket->ruleCount,
        (unsigned long)requestPacket->trustedCount,
        (unsigned long long)appliedConfigVersion);

    *CompleteBytesOut = sizeof(KSWORD_ARK_PROCESS_PROTECT_CONFIG_REQUEST);
    return STATUS_SUCCESS;
}

NTSTATUS
KswordARKProcessProtectIoctlQueryState(
    _In_ WDFREQUEST Request,
    _In_ size_t OutputBufferLength,
    _Out_ size_t* CompleteBytesOut
    )
{
    KSWORD_ARK_PROCESS_PROTECT_STATE* state = KswordArkProcessProtectGetState();
    KSWORD_ARK_PROCESS_PROTECT_STATE_RESPONSE* responsePacket = NULL;
    size_t outputLength = 0U;
    ULONG entryIndex = 0UL;
    NTSTATUS status = STATUS_SUCCESS;

    if (CompleteBytesOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *CompleteBytesOut = 0U;

    if (state == NULL) {
        return STATUS_DEVICE_NOT_READY;
    }
    if (OutputBufferLength < sizeof(KSWORD_ARK_PROCESS_PROTECT_STATE_RESPONSE)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    status = WdfRequestRetrieveOutputBuffer(
        Request,
        sizeof(KSWORD_ARK_PROCESS_PROTECT_STATE_RESPONSE),
        (PVOID*)&responsePacket,
        &outputLength);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    if (outputLength < sizeof(KSWORD_ARK_PROCESS_PROTECT_STATE_RESPONSE)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    RtlZeroMemory(responsePacket, sizeof(*responsePacket));
    responsePacket->size = sizeof(*responsePacket);
    responsePacket->version = KSWORD_ARK_PROCESS_PROTECT_PROTOCOL_VERSION;

    KswordARKAcquirePushLockShared(&state->ConfigLock);
    responsePacket->globalFlags = state->GlobalFlags;
    responsePacket->ruleCount = state->RuleCount;
    responsePacket->trustedCount = state->TrustedCount;
    responsePacket->configVersion = (unsigned long long)state->ConfigVersion;
    responsePacket->appliedAtUtc100ns = (unsigned long long)state->AppliedAtUtc100ns.QuadPart;
    RtlCopyMemory(responsePacket->rules, state->Rules, sizeof(responsePacket->rules));
    RtlCopyMemory(responsePacket->trusted, state->Trusted, sizeof(responsePacket->trusted));
    for (entryIndex = 0UL; entryIndex < KSWORD_ARK_PROCESS_PROTECT_MAX_RULES; ++entryIndex) {
        responsePacket->ruleHitCounts[entryIndex] =
            (unsigned long long)state->RuleHitCounts[entryIndex];
    }
    KswordARKReleasePushLockShared(&state->ConfigLock);

    responsePacket->objectCallbackStatus = (long)InterlockedCompareExchange(&state->ObjectCallbackStatus, 0L, 0L);
    responsePacket->capabilityStatus =
        (InterlockedCompareExchange(&state->ObjectCallbackRegistered, 0L, 0L) != 0L)
        ? KSWORD_ARK_PROCESS_PROTECT_STATUS_ACTIVE
        : KSWORD_ARK_PROCESS_PROTECT_STATUS_CALLBACK_UNAVAILABLE;

    responsePacket->evaluatedCount = (unsigned long long)InterlockedCompareExchange64(&state->EvaluatedCount, 0LL, 0LL);
    responsePacket->strippedCount = (unsigned long long)InterlockedCompareExchange64(&state->StrippedCount, 0LL, 0LL);
    responsePacket->trustedBypassCount = (unsigned long long)InterlockedCompareExchange64(&state->TrustedBypassCount, 0LL, 0LL);

    KswordARKAcquirePushLockShared(&state->LastBlockedLock);
    responsePacket->lastBlockedUtc100ns = (unsigned long long)state->LastBlockedUtc100ns.QuadPart;
    responsePacket->lastBlockedInitiatorPid = state->LastBlockedInitiatorPid;
    responsePacket->lastBlockedTargetPid = state->LastBlockedTargetPid;
    responsePacket->lastBlockedRuleId = state->LastBlockedRuleId;
    responsePacket->lastBlockedOriginalAccess = state->LastBlockedOriginalAccess;
    responsePacket->lastBlockedGrantedAccess = state->LastBlockedGrantedAccess;
    responsePacket->lastBlockedIsThreadObject = state->LastBlockedIsThreadObject;
    KswordArkProcessProtectCopyFixedWide(
        responsePacket->lastBlockedInitiatorImage,
        KSWORD_ARK_PROCESS_PROTECT_IMAGE_CHARS,
        state->LastBlockedInitiatorImage);
    KswordArkProcessProtectCopyFixedWide(
        responsePacket->lastBlockedTargetImage,
        KSWORD_ARK_PROCESS_PROTECT_IMAGE_CHARS,
        state->LastBlockedTargetImage);
    KswordARKReleasePushLockShared(&state->LastBlockedLock);

    *CompleteBytesOut = sizeof(*responsePacket);
    return STATUS_SUCCESS;
}
