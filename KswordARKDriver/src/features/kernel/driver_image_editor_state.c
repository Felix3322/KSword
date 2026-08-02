/*++

Module Name:

    driver_image_editor_state.c

Abstract:

    Target identity resolution, live loader binding, transaction-state refresh,
    and response serialization for the unrestricted driver image editor.

Environment:

    Kernel-mode Driver Framework, PASSIVE_LEVEL control path.

--*/

#include "driver_image_editor_internal.h"

#include <ntstrsafe.h>

// 中文说明：IoDriverObjectType 让对象管理器解析始终限定为真正的 DriverObject。
extern POBJECT_TYPE* IoDriverObjectType;

// 中文说明：WDK 头未声明该对象管理器入口；签名与仓库其他 DriverObject 解析器保持一致。
NTSYSAPI
NTSTATUS
NTAPI
ObReferenceObjectByName(
    _In_ PUNICODE_STRING ObjectName,
    _In_ ULONG Attributes,
    _In_opt_ PACCESS_STATE PassedAccessState,
    _In_opt_ ACCESS_MASK DesiredAccess,
    _In_ POBJECT_TYPE ObjectType,
    _In_ KPROCESSOR_MODE AccessMode,
    _Inout_opt_ PVOID ParseContext,
    _Out_ PVOID* Object
    );

// 中文说明：协议尺寸同时固定 x64 对齐和 260 WCHAR 对象名，防止 R0/R3 静默漂移。
C_ASSERT(sizeof(KSWORD_ARK_DRIVER_IMAGE_REQUEST) == 664U);
C_ASSERT(sizeof(KSWORD_ARK_DRIVER_IMAGE_RESPONSE) == 816U);

// 中文说明：固定数组中必须出现终止符，之后才允许初始化 UNICODE_STRING。
BOOLEAN
KswordARKDriverImageHasTerminatedName(
    _In_reads_(KSWORD_ARK_DRIVER_OBJECT_NAME_CHARS) const WCHAR* DriverName
    )
{
    ULONG index = 0UL;

    if (DriverName == NULL) {
        return FALSE;
    }
    for (index = 0UL;
        index < KSWORD_ARK_DRIVER_OBJECT_NAME_CHARS;
        ++index) {
        if (DriverName[index] == L'\0') {
            return TRUE;
        }
    }
    return FALSE;
}

// 中文说明：对象名比较与 ObReferenceObjectByName 一致地忽略大小写。
BOOLEAN
KswordARKDriverImageNamesEqual(
    _In_z_ const WCHAR* Left,
    _In_z_ const WCHAR* Right
    )
{
    UNICODE_STRING leftName;
    UNICODE_STRING rightName;

    if (Left == NULL || Right == NULL ||
        Left[0] == L'\0' || Right[0] == L'\0') {
        return FALSE;
    }
    RtlInitUnicodeString(&leftName, Left);
    RtlInitUnicodeString(&rightName, Right);
    return RtlEqualUnicodeString(&leftName, &rightName, TRUE);
}

// 中文说明：解析优先使用稳定对象名，允许 DriverStart 被编辑后仍能继续查询和恢复。
NTSTATUS
KswordARKDriverImageResolveTarget(
    _In_ const KSWORD_ARK_DRIVER_IMAGE_REQUEST* Request,
    _Outptr_ PDRIVER_OBJECT* DriverObjectOut,
    _Out_writes_(NameChars) PWCHAR CanonicalNameOut,
    _In_ ULONG NameChars,
    _Out_ ULONGLONG* TargetModuleBaseOut
    )
{
    PDRIVER_OBJECT driverObject = NULL;
    UNICODE_STRING objectName;
    KSW_DRIVER_IMAGE_RECORD temporaryRecord;
    KSWORD_ARK_DRIVER_IMAGE_VALUES currentValues;
    ULONG availableMask = 0UL;
    NTSTATUS status = STATUS_SUCCESS;

    if (Request == NULL || DriverObjectOut == NULL ||
        CanonicalNameOut == NULL || NameChars == 0UL ||
        TargetModuleBaseOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *DriverObjectOut = NULL;
    *TargetModuleBaseOut = 0ULL;
    CanonicalNameOut[0] = L'\0';
    RtlZeroMemory(&temporaryRecord, sizeof(temporaryRecord));
    RtlZeroMemory(&currentValues, sizeof(currentValues));

    if (Request->driverName[0] != L'\0') {
        // 中文说明：不按驱动类别、产品或命名目录过滤，唯一类型约束是 DriverObject。
        if (IoDriverObjectType == NULL || *IoDriverObjectType == NULL) {
            return STATUS_NOT_SUPPORTED;
        }
        RtlInitUnicodeString(&objectName, Request->driverName);
        status = ObReferenceObjectByName(
            &objectName,
            OBJ_CASE_INSENSITIVE,
            NULL,
            0UL,
            *IoDriverObjectType,
            KernelMode,
            NULL,
            (PVOID*)&driverObject);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        status = RtlStringCchCopyW(
            CanonicalNameOut,
            NameChars,
            Request->driverName);
        if (!NT_SUCCESS(status)) {
            ObDereferenceObject(driverObject);
            return status;
        }
    }
    else {
        // 中文说明：无对象名的只读首查可沿用仓库现有的模块基址到 DriverObject 解析器。
        if ((Request->flags &
            KSWORD_ARK_DRIVER_IMAGE_FLAG_TARGET_MODULE_BASE_PRESENT) == 0UL ||
            Request->targetModuleBase == 0ULL) {
            return STATUS_INVALID_PARAMETER;
        }
        status = KswordARKDriverReferenceObjectByModuleBase(
            Request->targetModuleBase,
            &driverObject,
            CanonicalNameOut,
            NameChars);
        if (!NT_SUCCESS(status)) {
            return status;
        }
    }

    // 中文说明：变更请求携带的对象地址必须与对象管理器当前返回的精确对象一致。
    if ((Request->flags &
        KSWORD_ARK_DRIVER_IMAGE_FLAG_EXPECTED_DRIVER_OBJECT_PRESENT) != 0UL &&
        Request->expectedDriverObjectAddress !=
            (ULONGLONG)(ULONG_PTR)driverObject) {
        ObDereferenceObject(driverObject);
        return STATUS_OBJECT_TYPE_MISMATCH;
    }

    if ((Request->flags &
        KSWORD_ARK_DRIVER_IMAGE_FLAG_TARGET_MODULE_BASE_PRESENT) != 0UL) {
        *TargetModuleBaseOut = Request->targetModuleBase;
    }
    else {
        // 中文说明：没有显式初始基址时原子采样当前 DriverStart 作为记录提示，不限制其值。
        temporaryRecord.DriverObject = driverObject;
        status = KswordARKDriverImageReadValuesLocked(
            NULL,
            &temporaryRecord,
            &currentValues,
            &availableMask);
        if (!NT_SUCCESS(status) ||
            (availableMask &
             KSWORD_ARK_DRIVER_IMAGE_FIELD_DRIVER_START) == 0UL) {
            ObDereferenceObject(driverObject);
            return NT_SUCCESS(status) ? STATUS_NOT_SUPPORTED : status;
        }
        *TargetModuleBaseOut = currentValues.driverStart;
    }

    *DriverObjectOut = driverObject;
    return STATUS_SUCCESS;
}

// 中文说明：统一打开实际模块资源；失败时 Runtime 仍保留已解析布局供部分响应诊断。
NTSTATUS
KswordARKDriverImageOpenRuntime(
    _Out_ KSW_DRIVER_IMAGE_RUNTIME* Runtime,
    _In_ BOOLEAN Exclusive
    )
{
    NTSTATUS status = STATUS_SUCCESS;

    if (Runtime == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    status = KswordARKDriverImageResolveRuntime(Runtime);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    return KswordARKDriverImageAcquireRuntime(Runtime, Exclusive);
}

// 中文说明：第一次绑定精确 DllBase 项；已有绑定必须重新通过活动布局和链校验。
NTSTATUS
KswordARKDriverImageAttachLoaderLocked(
    _In_ const KSW_DRIVER_IMAGE_RUNTIME* Runtime,
    _Inout_ KSW_DRIVER_IMAGE_RECORD* Record,
    _Out_ BOOLEAN* StateChanged
    )
{
    KSW_DRIVER_IMAGE_LINK_VIEW view;
    KSWORD_ARK_DRIVER_IMAGE_VALUES currentValues;
    ULONG availableMask = 0UL;
    ULONGLONG lookupBase = 0ULL;
    NTSTATUS status = STATUS_SUCCESS;

    if (Runtime == NULL || Record == NULL || StateChanged == NULL ||
        Runtime->ResourceAcquired == FALSE) {
        return STATUS_INVALID_PARAMETER;
    }
    *StateChanged = FALSE;
    RtlZeroMemory(&view, sizeof(view));
    RtlZeroMemory(&currentValues, sizeof(currentValues));

    if (Record->LoaderEntry != NULL && Record->LoaderLink != NULL) {
        return KswordARKDriverImageInspectRecordLinkLocked(
            Runtime,
            Record,
            &view);
    }

    // 中文说明：首次绑定先采样公开 DriverObject 身份；随后要求至少一个字段与 KLDR 精确对应。
    status = KswordARKDriverImageReadValuesLocked(
        Runtime,
        Record,
        &currentValues,
        &availableMask);
    if (!NT_SUCCESS(status) ||
        (availableMask &
         (KSWORD_ARK_DRIVER_IMAGE_FIELD_DRIVER_START |
          KSWORD_ARK_DRIVER_IMAGE_FIELD_DRIVER_SECTION)) !=
        (KSWORD_ARK_DRIVER_IMAGE_FIELD_DRIVER_START |
         KSWORD_ARK_DRIVER_IMAGE_FIELD_DRIVER_SECTION)) {
        return NT_SUCCESS(status) ? STATUS_NOT_SUPPORTED : status;
    }
    lookupBase = Record->TargetModuleBase;
    if (lookupBase == 0ULL) {
        // 中文说明：没有冻结基址时仅用当前 DriverStart 作精确 DllBase 查询，不做区间模糊匹配。
        lookupBase = currentValues.driverStart;
    }

    status = KswordARKDriverImageLocateLoaderLocked(
        Runtime,
        lookupBase,
        &view);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    // 中文说明：目标基址来自陈旧 UI 行时，不能把此 DriverObject 与另一模块的 KLDR 误配。
    if (currentValues.driverStart != view.DllBase &&
        currentValues.driverSection != view.EntryAddress) {
        return STATUS_OBJECT_TYPE_MISMATCH;
    }
    Record->LoaderEntry = (PVOID)(ULONG_PTR)view.EntryAddress;
    Record->LoaderLink = (PLIST_ENTRY)(ULONG_PTR)view.LinkAddress;
    // 中文说明：R0 以实际匹配的 DllBase 规范化冻结身份，后续 DriverStart 改写不影响恢复。
    Record->TargetModuleBase = view.DllBase;
    *StateChanged = TRUE;
    return STATUS_SUCCESS;
}

// 中文说明：链刷新采用保守所有权规则；外部恢复到主链可退役，未知悬空态只标冲突。
NTSTATUS
KswordARKDriverImageRefreshRecordLocked(
    _In_opt_ const KSW_DRIVER_IMAGE_RUNTIME* Runtime,
    _Inout_ KSW_DRIVER_IMAGE_RECORD* Record,
    _Out_ BOOLEAN* StateChanged
    )
{
    KSW_DRIVER_IMAGE_LINK_VIEW view;
    BOOLEAN fieldChanged = FALSE;
    BOOLEAN oldLinkManaged = FALSE;
    BOOLEAN oldLinkOwned = FALSE;
    BOOLEAN oldLinkConflict = FALSE;
    NTSTATUS fieldStatus = STATUS_SUCCESS;
    NTSTATUS linkStatus = STATUS_SUCCESS;

    if (Record == NULL || StateChanged == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *StateChanged = FALSE;
    RtlZeroMemory(&view, sizeof(view));
    oldLinkManaged = Record->LinkManaged;
    oldLinkOwned = Record->LinkOwned;
    oldLinkConflict = Record->LinkConflict;

    fieldStatus = KswordARKDriverImageRefreshFieldsLocked(
        Runtime,
        Record,
        &fieldChanged);

    if (Record->LinkManaged != FALSE || Record->LinkConflict != FALSE) {
        if (Runtime == NULL || Runtime->ResourceAcquired == FALSE ||
            Record->LoaderEntry == NULL || Record->LoaderLink == NULL) {
            // 中文说明：资源暂时不可用只返回能力状态，不丢失以后恢复自环链所需的所有权。
            linkStatus = STATUS_NOT_SUPPORTED;
        }
        else {
            linkStatus = KswordARKDriverImageInspectRecordLinkLocked(
                Runtime,
                Record,
                &view);
            if (!NT_SUCCESS(linkStatus)) {
                Record->LinkOwned = FALSE;
                Record->LinkConflict = TRUE;
            }
            else if (view.InList != FALSE) {
                // 中文说明：主链内的有效项视为已恢复，无论是否回到原邻居都不再阻止卸载。
                Record->LinkManaged = FALSE;
                Record->LinkOwned = FALSE;
                Record->LinkConflict = FALSE;
            }
            else if (view.SelfLinked != FALSE &&
                Record->LinkOwned != FALSE) {
                Record->LinkConflict = FALSE;
            }
            else {
                Record->LinkOwned = FALSE;
                Record->LinkConflict = TRUE;
            }
        }
    }

    *StateChanged = fieldChanged ||
        oldLinkManaged != Record->LinkManaged ||
        oldLinkOwned != Record->LinkOwned ||
        oldLinkConflict != Record->LinkConflict;
    if (!NT_SUCCESS(fieldStatus)) {
        return fieldStatus;
    }
    return linkStatus;
}

// 中文说明：响应包含当前/原始/applied/requested 四组值和链/锁地址，便于 R3 明确判断风险。
VOID
KswordARKDriverImageFillResponseLocked(
    _In_ const KSW_DRIVER_IMAGE_STATE* State,
    _In_ const KSW_DRIVER_IMAGE_RESPONSE_CONTEXT* Context,
    _Out_ KSWORD_ARK_DRIVER_IMAGE_RESPONSE* Response
    )
{
    const KSW_DRIVER_IMAGE_RECORD* record = NULL;
    KSW_DRIVER_IMAGE_LINK_VIEW linkView;
    KSWORD_ARK_DRIVER_IMAGE_VALUES currentValues;
    ULONG availableMask = 0UL;
    NTSTATUS valueStatus = STATUS_SUCCESS;
    NTSTATUS loaderStatus = STATUS_NOT_SUPPORTED;
    BOOLEAN loaderAvailable = FALSE;

    if (State == NULL || Context == NULL || Context->Request == NULL ||
        Context->Record == NULL || Response == NULL) {
        return;
    }
    record = Context->Record;
    loaderStatus = Context->LoaderStatus;
    RtlZeroMemory(Response, sizeof(*Response));
    RtlZeroMemory(&linkView, sizeof(linkView));
    RtlZeroMemory(&currentValues, sizeof(currentValues));

    Response->version = KSWORD_ARK_DRIVER_IMAGE_PROTOCOL_VERSION;
    Response->action = Context->Request->action;
    Response->lastStatus = Context->LastStatus;
    Response->generation = Context->RecordPresent != FALSE
        ? record->Generation
        : State->Generation;
    Response->managedFieldMask = record->ManagedFieldMask;
    Response->ownedFieldMask = record->OwnedFieldMask;
    Response->conflictFieldMask = record->ConflictFieldMask;
    Response->changedFieldMask = Context->ChangedFieldMask;
    Response->targetModuleBase = record->TargetModuleBase;
    Response->driverObjectAddress =
        (ULONGLONG)(ULONG_PTR)record->DriverObject;
    Response->selfDriverObjectAddress =
        (ULONGLONG)(ULONG_PTR)State->SelfDriverObject;
    Response->loaderEntryAddress =
        (ULONGLONG)(ULONG_PTR)record->LoaderEntry;
    Response->loaderLinkAddress =
        (ULONGLONG)(ULONG_PTR)record->LoaderLink;
    Response->originalLinkFlink =
        (ULONGLONG)(ULONG_PTR)record->OriginalLinkFlink;
    Response->originalLinkBlink =
        (ULONGLONG)(ULONG_PTR)record->OriginalLinkBlink;
    Response->originalValues = record->OriginalValues;
    Response->appliedValues = record->AppliedValues;
    Response->requestedValues = Context->Request->desiredValues;
    Response->responseFlags =
        KSWORD_ARK_DRIVER_IMAGE_RESPONSE_FLAG_WARN_ONLY_POLICY;

    if (Context->Runtime != NULL) {
        Response->layoutFlags = Context->Runtime->LayoutFlags;
        Response->listHeadAddress =
            (ULONGLONG)(ULONG_PTR)Context->Runtime->ListHead;
        Response->listResourceAddress =
            (ULONGLONG)(ULONG_PTR)Context->Runtime->ListResource;
        if (Context->Runtime->LayoutFlags != 0UL) {
            Response->responseFlags |=
                KSWORD_ARK_DRIVER_IMAGE_RESPONSE_FLAG_LAYOUT_AVAILABLE;
        }
        if (Context->Runtime->ListResource != NULL) {
            Response->responseFlags |=
                KSWORD_ARK_DRIVER_IMAGE_RESPONSE_FLAG_LIST_LOCK_AVAILABLE;
        }
    }

    valueStatus = KswordARKDriverImageReadValuesLocked(
        Context->Runtime,
        record,
        &currentValues,
        &availableMask);
    if (NT_SUCCESS(valueStatus)) {
        Response->currentValues = currentValues;
    }

    if (Context->Runtime != NULL &&
        Context->Runtime->ResourceAcquired != FALSE &&
        record->LoaderEntry != NULL && record->LoaderLink != NULL) {
        loaderStatus = KswordARKDriverImageInspectRecordLinkLocked(
            Context->Runtime,
            record,
            &linkView);
        if (NT_SUCCESS(loaderStatus)) {
            loaderAvailable = TRUE;
            Response->currentLinkFlink =
                (ULONGLONG)(ULONG_PTR)linkView.Flink;
            Response->currentLinkBlink =
                (ULONGLONG)(ULONG_PTR)linkView.Blink;
        }
    }
    Response->loaderStatus = loaderStatus;

    if (Context->RecordPresent != FALSE) {
        Response->responseFlags |=
            KSWORD_ARK_DRIVER_IMAGE_RESPONSE_FLAG_RECORD_PRESENT;
    }
    if (record->DriverObject == State->SelfDriverObject) {
        Response->responseFlags |=
            KSWORD_ARK_DRIVER_IMAGE_RESPONSE_FLAG_SELF_TARGET;
    }
    if (record->OwnedFieldMask != 0UL) {
        Response->responseFlags |=
            KSWORD_ARK_DRIVER_IMAGE_RESPONSE_FLAG_FIELDS_OWNED;
    }
    if (record->ConflictFieldMask != 0UL) {
        Response->responseFlags |=
            KSWORD_ARK_DRIVER_IMAGE_RESPONSE_FLAG_FIELDS_CONFLICT;
    }
    if (record->LinkOwned != FALSE) {
        Response->responseFlags |=
            KSWORD_ARK_DRIVER_IMAGE_RESPONSE_FLAG_LINK_OWNED;
    }
    if (record->LinkConflict != FALSE) {
        Response->responseFlags |=
            KSWORD_ARK_DRIVER_IMAGE_RESPONSE_FLAG_LINK_CONFLICT;
    }
    if (Context->ChangedFieldMask != 0UL ||
        Context->LinkChanged != FALSE) {
        Response->responseFlags |=
            KSWORD_ARK_DRIVER_IMAGE_RESPONSE_FLAG_CHANGED;
    }
    if (Context->RestoredOriginalPosition != FALSE) {
        Response->responseFlags |=
            KSWORD_ARK_DRIVER_IMAGE_RESPONSE_FLAG_RESTORED_ORIGINAL_POSITION;
    }
    if (Context->RestoredListTail != FALSE) {
        Response->responseFlags |=
            KSWORD_ARK_DRIVER_IMAGE_RESPONSE_FLAG_RESTORED_LIST_TAIL;
    }

    if (loaderAvailable != FALSE) {
        Response->responseFlags |=
            KSWORD_ARK_DRIVER_IMAGE_RESPONSE_FLAG_LOADER_AVAILABLE;
        if (linkView.InList != FALSE) {
            Response->responseFlags |=
                KSWORD_ARK_DRIVER_IMAGE_RESPONSE_FLAG_LINK_VISIBLE;
        }
        if (linkView.SelfLinked != FALSE) {
            Response->responseFlags |=
                KSWORD_ARK_DRIVER_IMAGE_RESPONSE_FLAG_LINK_HIDDEN;
        }
        if ((availableMask &
            KSWORD_ARK_DRIVER_IMAGE_FIELD_DRIVER_SECTION) != 0UL &&
            currentValues.driverSection ==
                (ULONGLONG)(ULONG_PTR)record->LoaderEntry) {
            Response->responseFlags |=
                KSWORD_ARK_DRIVER_IMAGE_RESPONSE_FLAG_DRIVER_SECTION_MATCH;
        }
        if ((availableMask &
            (KSWORD_ARK_DRIVER_IMAGE_FIELD_DRIVER_START |
             KSWORD_ARK_DRIVER_IMAGE_FIELD_KLDR_DLL_BASE)) ==
            (KSWORD_ARK_DRIVER_IMAGE_FIELD_DRIVER_START |
             KSWORD_ARK_DRIVER_IMAGE_FIELD_KLDR_DLL_BASE) &&
            currentValues.driverStart == currentValues.kldrDllBase) {
            Response->responseFlags |=
                KSWORD_ARK_DRIVER_IMAGE_RESPONSE_FLAG_DRIVER_START_MATCH;
        }
    }

    if (!NT_SUCCESS(valueStatus) ||
        availableMask != KSWORD_ARK_DRIVER_IMAGE_FIELD_ALL ||
        loaderAvailable == FALSE) {
        Response->responseFlags |=
            KSWORD_ARK_DRIVER_IMAGE_RESPONSE_FLAG_PARTIAL_VIEW;
    }

    if (record->ConflictFieldMask != 0UL ||
        record->LinkConflict != FALSE) {
        Response->state = KSWORD_ARK_DRIVER_IMAGE_STATE_CONFLICT;
    }
    else if (record->ManagedFieldMask != 0UL ||
        record->LinkManaged != FALSE) {
        Response->state = KSWORD_ARK_DRIVER_IMAGE_STATE_ACTIVE;
    }
    else {
        Response->state = KSWORD_ARK_DRIVER_IMAGE_STATE_INACTIVE;
    }

    (VOID)RtlStringCchCopyW(
        Response->driverName,
        RTL_NUMBER_OF(Response->driverName),
        record->CanonicalName);
}
