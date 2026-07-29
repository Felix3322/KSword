/*++

Module Name:

    callback_extended_bugcheck.c

Abstract:

    枚举经典 BugCheck 与 BugCheckReason 回调，并显式展示 Ksword 自身记录。

Environment:

    Kernel-mode Driver Framework

--*/

#include "callback_extended_internal.h"
#include "callback_extended_kernel.h"
#include "../bugcheck/bugcheck_internal.h"

#define KSWORD_ARK_CALLBACK_BUGCHECK_WALK_LIMIT 512UL

static ULONG
KswordArkCallbackExtendedBugcheckReasonType(
    _In_ KBUGCHECK_CALLBACK_REASON Reason
    )
/*++

Routine Description:

    把 WDK BugCheckReason 枚举映射到共享协议注册子类型。

Arguments:

    Reason - KBUGCHECK_CALLBACK_REASON。

Return Value:

    返回稳定的 KSWORD_ARK_CALLBACK_REGISTRATION_TYPE_* 值。

--*/
{
    switch (Reason) {
    case KbCallbackSecondaryDumpData:
    case KbCallbackSecondaryMultiPartDumpData:
        return KSWORD_ARK_CALLBACK_REGISTRATION_TYPE_BUGCHECK_SECONDARY_DUMP;

    case KbCallbackDumpIo:
        return KSWORD_ARK_CALLBACK_REGISTRATION_TYPE_BUGCHECK_DUMP_IO;

    case KbCallbackTriageDumpData:
        return KSWORD_ARK_CALLBACK_REGISTRATION_TYPE_BUGCHECK_TRIAGE_DUMP;

    default:
        return KSWORD_ARK_CALLBACK_REGISTRATION_TYPE_BUGCHECK_REASON_OTHER;
    }
}

static VOID
KswordArkCallbackExtendedAddSelfBugcheckRow(
    _Inout_ KSWORD_ARK_CALLBACK_ENUM_BUILDER* Builder,
    _Inout_ KSWORD_ARK_CALLBACK_MODULE_CACHE* ModuleCache,
    _In_ BOOLEAN Registered,
    _In_ ULONG CallbackClass,
    _In_ ULONG RegistrationType,
    _In_ ULONG64 CallbackAddress,
    _In_ ULONG64 ContextAddress,
    _In_ ULONG64 RecordAddress,
    _In_z_ PCWSTR NameText,
    _In_z_ PCWSTR DetailText
    )
/*++

Routine Description:

    写入一条 Ksword 自身 BugCheck 注册记录。

Arguments:

    Builder - 响应构建器。
    ModuleCache - 模块缓存。
    Registered - 当前记录是否已经注册。
    CallbackClass - Classic 或 Reason 类别。
    RegistrationType - 具体 BugCheck 注册类型。
    CallbackAddress - 回调函数地址。
    ContextAddress - Reason 数值或缓冲区地址。
    RecordAddress - KBUGCHECK_*_RECORD 地址。
    NameText - 行名称。
    DetailText - 详情文本。

Return Value:

    无返回值。

--*/
{
    KswordArkCallbackExtendedAddRow(
        Builder,
        ModuleCache,
        CallbackClass,
        KSWORD_ARK_CALLBACK_ENUM_SOURCE_KSWORD_SELF,
        Registered
            ? KSWORD_ARK_CALLBACK_ENUM_STATUS_OK
            : KSWORD_ARK_CALLBACK_ENUM_STATUS_NOT_REGISTERED,
        Registered ? STATUS_SUCCESS : STATUS_NOT_FOUND,
        RegistrationType,
        0UL,
        0UL,
        CallbackAddress,
        ContextAddress,
        RecordAddress,
        0UL,
        NameText,
        DetailText);
}

VOID
KswordArkCallbackExtendedAddSelfBugcheckCallbacks(
    _Inout_ KSWORD_ARK_CALLBACK_ENUM_BUILDER* Builder
    )
/*++

Routine Description:

    展示驱动实际注册的一个经典 BugCheck 与三个 BugCheckReason 回调。

Arguments:

    Builder - 响应构建器。

Return Value:

    无返回值。

--*/
{
    KSWORD_ARK_CALLBACK_MODULE_CACHE moduleCache;
    KSWORD_ARK_BUGCHECK_STATE* state = &g_KswordArkBugcheckState;

    if (Builder == NULL) {
        return;
    }

    KswordArkCallbackEnumInitModuleCache(&moduleCache);
    KswordArkCallbackExtendedAddSelfBugcheckRow(
        Builder,
        &moduleCache,
        state->ClassicRegistered,
        KSWORD_ARK_CALLBACK_ENUM_CLASS_BUGCHECK,
        KSWORD_ARK_CALLBACK_REGISTRATION_TYPE_BUGCHECK_CLASSIC,
        (ULONG64)(ULONG_PTR)state->ClassicRecord.CallbackRoutine,
        (ULONG64)(ULONG_PTR)state->ClassicRecord.Buffer,
        (ULONG64)(ULONG_PTR)&state->ClassicRecord,
        L"KswordARK BugCheck callback",
        L"KeRegisterBugCheckCallback 注册的经典蓝屏回调；该行直接来自本驱动运行时记录。");
    KswordArkCallbackExtendedAddSelfBugcheckRow(
        Builder,
        &moduleCache,
        state->SecondaryRegistered,
        KSWORD_ARK_CALLBACK_ENUM_CLASS_BUGCHECK_REASON,
        KSWORD_ARK_CALLBACK_REGISTRATION_TYPE_BUGCHECK_SECONDARY_DUMP,
        (ULONG64)(ULONG_PTR)state->SecondaryRecord.CallbackRoutine,
        (ULONG64)state->SecondaryRecord.Reason,
        (ULONG64)(ULONG_PTR)&state->SecondaryRecord,
        L"KswordARK SecondaryDumpData callback",
        L"KeRegisterBugCheckReasonCallback 注册的 SecondaryDumpData 回调。");
    KswordArkCallbackExtendedAddSelfBugcheckRow(
        Builder,
        &moduleCache,
        state->DumpIoRegistered,
        KSWORD_ARK_CALLBACK_ENUM_CLASS_BUGCHECK_REASON,
        KSWORD_ARK_CALLBACK_REGISTRATION_TYPE_BUGCHECK_DUMP_IO,
        (ULONG64)(ULONG_PTR)state->DumpIoRecord.CallbackRoutine,
        (ULONG64)state->DumpIoRecord.Reason,
        (ULONG64)(ULONG_PTR)&state->DumpIoRecord,
        L"KswordARK DumpIo callback",
        L"KeRegisterBugCheckReasonCallback 注册的 DumpIo 回调。");
    KswordArkCallbackExtendedAddSelfBugcheckRow(
        Builder,
        &moduleCache,
        state->TriageRegistered,
        KSWORD_ARK_CALLBACK_ENUM_CLASS_BUGCHECK_REASON,
        KSWORD_ARK_CALLBACK_REGISTRATION_TYPE_BUGCHECK_TRIAGE_DUMP,
        (ULONG64)(ULONG_PTR)state->TriageRecord.CallbackRoutine,
        (ULONG64)state->TriageRecord.Reason,
        (ULONG64)(ULONG_PTR)&state->TriageRecord,
        L"KswordARK TriageDumpData callback",
        L"KeRegisterBugCheckReasonCallback 注册的 TriageDumpData 回调。");
    KswordArkCallbackEnumFreeModuleCache(&moduleCache);
}

static BOOLEAN
KswordArkCallbackExtendedIsOwnBugcheckRecord(
    _In_ ULONG64 RecordAddress
    )
/*++

Routine Description:

    判断链表节点是否属于前面已经展示的 Ksword 自身记录。

Arguments:

    RecordAddress - KBUGCHECK_*_RECORD 起始地址。

Return Value:

    属于自身四条记录返回 TRUE，否则返回 FALSE。

--*/
{
    return RecordAddress == (ULONG64)(ULONG_PTR)&g_KswordArkBugcheckState.ClassicRecord ||
        RecordAddress == (ULONG64)(ULONG_PTR)&g_KswordArkBugcheckState.SecondaryRecord ||
        RecordAddress == (ULONG64)(ULONG_PTR)&g_KswordArkBugcheckState.DumpIoRecord ||
        RecordAddress == (ULONG64)(ULONG_PTR)&g_KswordArkBugcheckState.TriageRecord;
}

static VOID
KswordArkCallbackExtendedWalkClassicBugcheckList(
    _Inout_ KSWORD_ARK_CALLBACK_ENUM_BUILDER* Builder,
    _Inout_ KSWORD_ARK_CALLBACK_MODULE_CACHE* ModuleCache
    )
/*++

Routine Description:

    以本驱动已注册记录为安全锚点遍历经典 BugCheck 链。

Arguments:

    Builder - 响应构建器。
    ModuleCache - 模块缓存。

Return Value:

    无返回值。

--*/
{
    ULONG index = 0UL;
    ULONG64 anchorAddress = 0ULL;
    ULONG64 currentAddress = 0ULL;
    KBUGCHECK_CALLBACK_RECORD anchorRecord;

    if (!g_KswordArkBugcheckState.ClassicRegistered) {
        KswordArkCallbackExtendedAddRow(
            Builder,
            ModuleCache,
            KSWORD_ARK_CALLBACK_ENUM_CLASS_BUGCHECK,
            KSWORD_ARK_CALLBACK_ENUM_SOURCE_PRIVATE_BUGCHECK_LIST,
            KSWORD_ARK_CALLBACK_ENUM_STATUS_QUERY_FAILED,
            STATUS_NOT_FOUND,
            KSWORD_ARK_CALLBACK_REGISTRATION_TYPE_BUGCHECK_CLASSIC,
            0UL,
            0UL,
            0ULL,
            0ULL,
            0ULL,
            0UL,
            L"KeBugCheckCallbackListHead anchor unavailable",
            L"Ksword 自身经典 BugCheck 记录未注册，无法在不全局盲扫的情况下取得链表锚点。");
        return;
    }

    anchorAddress = (ULONG64)(ULONG_PTR)&g_KswordArkBugcheckState.ClassicRecord;
    RtlZeroMemory(&anchorRecord, sizeof(anchorRecord));
    if (!KswordArkCallbackEnumReadMemory(
            (const VOID*)(ULONG_PTR)anchorAddress,
            &anchorRecord,
            sizeof(anchorRecord))) {
        return;
    }

    currentAddress = (ULONG64)(ULONG_PTR)anchorRecord.Entry.Flink;
    while (currentAddress != 0ULL &&
        currentAddress != anchorAddress &&
        index < KSWORD_ARK_CALLBACK_BUGCHECK_WALK_LIMIT) {
        KBUGCHECK_CALLBACK_RECORD record;
        ULONG64 nextAddress = 0ULL;

        RtlZeroMemory(&record, sizeof(record));
        if (!KswordArkCallbackEnumReadMemory(
                (const VOID*)(ULONG_PTR)currentAddress,
                &record,
                sizeof(record))) {
            break;
        }
        nextAddress = (ULONG64)(ULONG_PTR)record.Entry.Flink;

        if (!KswordArkCallbackExtendedIsOwnBugcheckRecord(currentAddress) &&
            record.State == BufferInserted &&
            record.CallbackRoutine != NULL &&
            KswordArkCallbackEnumIsKernelModuleAddress(
                ModuleCache,
                (ULONG64)(ULONG_PTR)record.CallbackRoutine)) {
            WCHAR nameText[KSWORD_ARK_CALLBACK_ENUM_NAME_CHARS];
            WCHAR detailText[KSWORD_ARK_CALLBACK_ENUM_DETAIL_CHARS];

            RtlZeroMemory(nameText, sizeof(nameText));
            RtlZeroMemory(detailText, sizeof(detailText));
            (VOID)RtlStringCbPrintfW(
                nameText,
                sizeof(nameText),
                L"KeBugCheckCallback[%lu]",
                (unsigned long)index);
            (VOID)RtlStringCbPrintfW(
                detailText,
                sizeof(detailText),
                L"经典 BugCheck 公共记录链只读项；Record=0x%p，Buffer=0x%p，Length=%lu，Component=0x%p。",
                (PVOID)(ULONG_PTR)currentAddress,
                record.Buffer,
                (unsigned long)record.Length,
                record.Component);
            KswordArkCallbackExtendedAddRow(
                Builder,
                ModuleCache,
                KSWORD_ARK_CALLBACK_ENUM_CLASS_BUGCHECK,
                KSWORD_ARK_CALLBACK_ENUM_SOURCE_PRIVATE_BUGCHECK_LIST,
                KSWORD_ARK_CALLBACK_ENUM_STATUS_OK,
                STATUS_SUCCESS,
                KSWORD_ARK_CALLBACK_REGISTRATION_TYPE_BUGCHECK_CLASSIC,
                0UL,
                0UL,
                (ULONG64)(ULONG_PTR)record.CallbackRoutine,
                (ULONG64)(ULONG_PTR)record.Buffer,
                currentAddress,
                0UL,
                nameText,
                detailText);
        }

        if (nextAddress == currentAddress) {
            break;
        }
        currentAddress = nextAddress;
        ++index;
    }
}

static PKBUGCHECK_REASON_CALLBACK_RECORD
KswordArkCallbackExtendedReasonAnchor(
    VOID
    )
/*++

Routine Description:

    选择一个已注册的 BugCheckReason 记录作为全局链锚点。

Arguments:

    无。

Return Value:

    返回已注册记录；全部未注册返回 NULL。

--*/
{
    if (g_KswordArkBugcheckState.SecondaryRegistered) {
        return &g_KswordArkBugcheckState.SecondaryRecord;
    }
    if (g_KswordArkBugcheckState.DumpIoRegistered) {
        return &g_KswordArkBugcheckState.DumpIoRecord;
    }
    if (g_KswordArkBugcheckState.TriageRegistered) {
        return &g_KswordArkBugcheckState.TriageRecord;
    }
    return NULL;
}

static VOID
KswordArkCallbackExtendedWalkReasonBugcheckList(
    _Inout_ KSWORD_ARK_CALLBACK_ENUM_BUILDER* Builder,
    _Inout_ KSWORD_ARK_CALLBACK_MODULE_CACHE* ModuleCache
    )
/*++

Routine Description:

    以一个已注册 Reason 记录为锚点遍历 BugCheckReason 全局链。

Arguments:

    Builder - 响应构建器。
    ModuleCache - 模块缓存。

Return Value:

    无返回值。

--*/
{
    ULONG index = 0UL;
    PKBUGCHECK_REASON_CALLBACK_RECORD anchor = NULL;
    ULONG64 anchorAddress = 0ULL;
    ULONG64 currentAddress = 0ULL;
    KBUGCHECK_REASON_CALLBACK_RECORD anchorRecord;

    anchor = KswordArkCallbackExtendedReasonAnchor();
    if (anchor == NULL) {
        KswordArkCallbackExtendedAddRow(
            Builder,
            ModuleCache,
            KSWORD_ARK_CALLBACK_ENUM_CLASS_BUGCHECK_REASON,
            KSWORD_ARK_CALLBACK_ENUM_SOURCE_PRIVATE_BUGCHECK_LIST,
            KSWORD_ARK_CALLBACK_ENUM_STATUS_QUERY_FAILED,
            STATUS_NOT_FOUND,
            KSWORD_ARK_CALLBACK_REGISTRATION_TYPE_BUGCHECK_REASON_OTHER,
            0UL,
            0UL,
            0ULL,
            0ULL,
            0ULL,
            0UL,
            L"KeBugCheckReasonCallbackListHead anchor unavailable",
            L"Ksword 自身三个 BugCheckReason 记录均未注册，无法取得安全链表锚点。");
        return;
    }

    anchorAddress = (ULONG64)(ULONG_PTR)anchor;
    RtlZeroMemory(&anchorRecord, sizeof(anchorRecord));
    if (!KswordArkCallbackEnumReadMemory(
            (const VOID*)(ULONG_PTR)anchorAddress,
            &anchorRecord,
            sizeof(anchorRecord))) {
        return;
    }

    currentAddress = (ULONG64)(ULONG_PTR)anchorRecord.Entry.Flink;
    while (currentAddress != 0ULL &&
        currentAddress != anchorAddress &&
        index < KSWORD_ARK_CALLBACK_BUGCHECK_WALK_LIMIT) {
        KBUGCHECK_REASON_CALLBACK_RECORD record;
        ULONG64 nextAddress = 0ULL;

        RtlZeroMemory(&record, sizeof(record));
        if (!KswordArkCallbackEnumReadMemory(
                (const VOID*)(ULONG_PTR)currentAddress,
                &record,
                sizeof(record))) {
            break;
        }
        nextAddress = (ULONG64)(ULONG_PTR)record.Entry.Flink;

        if (!KswordArkCallbackExtendedIsOwnBugcheckRecord(currentAddress) &&
            record.State == BufferInserted &&
            record.CallbackRoutine != NULL &&
            KswordArkCallbackEnumIsKernelModuleAddress(
                ModuleCache,
                (ULONG64)(ULONG_PTR)record.CallbackRoutine)) {
            WCHAR nameText[KSWORD_ARK_CALLBACK_ENUM_NAME_CHARS];
            WCHAR detailText[KSWORD_ARK_CALLBACK_ENUM_DETAIL_CHARS];

            RtlZeroMemory(nameText, sizeof(nameText));
            RtlZeroMemory(detailText, sizeof(detailText));
            (VOID)RtlStringCbPrintfW(
                nameText,
                sizeof(nameText),
                L"KeBugCheckReasonCallback[%lu]",
                (unsigned long)index);
            (VOID)RtlStringCbPrintfW(
                detailText,
                sizeof(detailText),
                L"BugCheckReason 公共记录链只读项；Record=0x%p，Reason=%lu，Component=0x%p。",
                (PVOID)(ULONG_PTR)currentAddress,
                (unsigned long)record.Reason,
                record.Component);
            KswordArkCallbackExtendedAddRow(
                Builder,
                ModuleCache,
                KSWORD_ARK_CALLBACK_ENUM_CLASS_BUGCHECK_REASON,
                KSWORD_ARK_CALLBACK_ENUM_SOURCE_PRIVATE_BUGCHECK_LIST,
                KSWORD_ARK_CALLBACK_ENUM_STATUS_OK,
                STATUS_SUCCESS,
                KswordArkCallbackExtendedBugcheckReasonType(record.Reason),
                0UL,
                0UL,
                (ULONG64)(ULONG_PTR)record.CallbackRoutine,
                (ULONG64)record.Reason,
                currentAddress,
                0UL,
                nameText,
                detailText);
        }

        if (nextAddress == currentAddress) {
            break;
        }
        currentAddress = nextAddress;
        ++index;
    }
}

VOID
KswordArkCallbackExtendedAddBugcheckCallbacks(
    _Inout_ KSWORD_ARK_CALLBACK_ENUM_BUILDER* Builder
    )
/*++

Routine Description:

    枚举系统经典 BugCheck 与 BugCheckReason 链中的外部回调。

Arguments:

    Builder - 响应构建器。

Return Value:

    无返回值。

--*/
{
    KSWORD_ARK_CALLBACK_MODULE_CACHE moduleCache;

    if (Builder == NULL) {
        return;
    }

    KswordArkCallbackEnumInitModuleCache(&moduleCache);
    if (!NT_SUCCESS(KswordArkCallbackEnumEnsureModuleCache(&moduleCache))) {
        KswordArkCallbackEnumFreeModuleCache(&moduleCache);
        return;
    }

    KswordArkCallbackExtendedWalkClassicBugcheckList(Builder, &moduleCache);
    KswordArkCallbackExtendedWalkReasonBugcheckList(Builder, &moduleCache);
    KswordArkCallbackEnumFreeModuleCache(&moduleCache);
}
