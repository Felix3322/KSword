/*++

Module Name:

    driver_image_editor.c

Abstract:

    Unrestricted transactional controller for DriverObject image metadata and
    PsLoadedModuleList membership.

    No driver class, product, owner, PnP, file-system, security role, self
    identity, or requested pointer-value policy is applied. Mutations require
    exact object identity, a transaction generation, expected-current values or
    links, explicit confirmation, CAS, and the real loader resource.

Environment:

    Kernel-mode Driver Framework, PASSIVE_LEVEL control path.

--*/

#include "driver_image_editor_internal.h"

#include <ntstrsafe.h>

// 中文说明：全局表只保存有限数量的活动/冲突事务和对应 DriverObject 引用。
static KSW_DRIVER_IMAGE_STATE g_KswordArkDriverImageState;

// 中文说明：代次零保留为“未查询”，每次可观察状态变化都跳到新的非零值。
static ULONG
KswordARKDriverImageAdvanceGenerationLocked(
    _Inout_opt_ KSW_DRIVER_IMAGE_RECORD* Record
    )
{
    ++g_KswordArkDriverImageState.Generation;
    if (g_KswordArkDriverImageState.Generation == 0UL) {
        ++g_KswordArkDriverImageState.Generation;
    }
    if (Record != NULL) {
        Record->Generation = g_KswordArkDriverImageState.Generation;
    }
    return g_KswordArkDriverImageState.Generation;
}

// 中文说明：查找优先使用精确对象地址，其次使用冻结模块基址或对象名。
static KSW_DRIVER_IMAGE_RECORD*
KswordARKDriverImageFindRecordLocked(
    _In_ const KSWORD_ARK_DRIVER_IMAGE_REQUEST* Request
    )
{
    ULONG index = 0UL;

    if (Request == NULL) {
        return NULL;
    }
    for (index = 0UL; index < KSW_DRIVER_IMAGE_RECORD_LIMIT; ++index) {
        KSW_DRIVER_IMAGE_RECORD* record =
            &g_KswordArkDriverImageState.Records[index];
        BOOLEAN candidate = FALSE;

        if (record->InUse == FALSE) {
            continue;
        }
        if ((Request->flags &
            KSWORD_ARK_DRIVER_IMAGE_FLAG_EXPECTED_DRIVER_OBJECT_PRESENT) != 0UL) {
            candidate = Request->expectedDriverObjectAddress ==
                (ULONGLONG)(ULONG_PTR)record->DriverObject;
        }
        else if ((Request->flags &
            KSWORD_ARK_DRIVER_IMAGE_FLAG_TARGET_MODULE_BASE_PRESENT) != 0UL) {
            candidate = Request->targetModuleBase ==
                record->TargetModuleBase;
        }
        else if (Request->driverName[0] != L'\0') {
            candidate = KswordARKDriverImageNamesEqual(
                Request->driverName,
                record->CanonicalName);
        }
        if (candidate != FALSE) {
            return record;
        }
    }
    return NULL;
}

// 中文说明：分配器不立即发布 InUse，只有目标引用和规范名都写入后才成为有效记录。
static KSW_DRIVER_IMAGE_RECORD*
KswordARKDriverImageAllocateRecordLocked(
    VOID
    )
{
    ULONG index = 0UL;

    for (index = 0UL; index < KSW_DRIVER_IMAGE_RECORD_LIMIT; ++index) {
        KSW_DRIVER_IMAGE_RECORD* record =
            &g_KswordArkDriverImageState.Records[index];
        if (record->InUse == FALSE) {
            RtlZeroMemory(record, sizeof(*record));
            return record;
        }
    }
    return NULL;
}

// 中文说明：已有记录必须同时满足请求中出现的每个身份字段，不能只命中其中一个。
static BOOLEAN
KswordARKDriverImageRecordMatchesRequest(
    _In_ const KSW_DRIVER_IMAGE_RECORD* Record,
    _In_ const KSWORD_ARK_DRIVER_IMAGE_REQUEST* Request
    )
{
    if (Record == NULL || Request == NULL || Record->InUse == FALSE) {
        return FALSE;
    }
    if ((Request->flags &
        KSWORD_ARK_DRIVER_IMAGE_FLAG_EXPECTED_DRIVER_OBJECT_PRESENT) != 0UL &&
        Request->expectedDriverObjectAddress !=
            (ULONGLONG)(ULONG_PTR)Record->DriverObject) {
        return FALSE;
    }
    if ((Request->flags &
        KSWORD_ARK_DRIVER_IMAGE_FLAG_TARGET_MODULE_BASE_PRESENT) != 0UL &&
        Request->targetModuleBase != Record->TargetModuleBase) {
        return FALSE;
    }
    if (Request->driverName[0] != L'\0' &&
        !KswordARKDriverImageNamesEqual(
            Request->driverName,
            Record->CanonicalName)) {
        return FALSE;
    }
    return TRUE;
}

// 中文说明：没有受管字段、字段冲突、链管理或链冲突时记录可安全退役。
static BOOLEAN
KswordARKDriverImageRecordIsClean(
    _In_ const KSW_DRIVER_IMAGE_RECORD* Record
    )
{
    return Record != NULL &&
        Record->ManagedFieldMask == 0UL &&
        Record->OwnedFieldMask == 0UL &&
        Record->ConflictFieldMask == 0UL &&
        Record->LinkManaged == FALSE &&
        Record->LinkOwned == FALSE &&
        Record->LinkConflict == FALSE;
}

// 中文说明：新记录接管调用方的一份对象引用，并冻结首次解析得到的模块基址。
static NTSTATUS
KswordARKDriverImageInitializeRecordLocked(
    _Inout_ KSW_DRIVER_IMAGE_RECORD* Record,
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ ULONGLONG TargetModuleBase,
    _In_z_ const WCHAR* CanonicalName
    )
{
    NTSTATUS status = STATUS_SUCCESS;

    if (Record == NULL || DriverObject == NULL ||
        CanonicalName == NULL || CanonicalName[0] == L'\0') {
        return STATUS_INVALID_PARAMETER;
    }
    RtlZeroMemory(Record, sizeof(*Record));
    Record->DriverObject = DriverObject;
    Record->TargetModuleBase = TargetModuleBase;
    Record->Generation = g_KswordArkDriverImageState.Generation;
    status = RtlStringCchCopyW(
        Record->CanonicalName,
        RTL_NUMBER_OF(Record->CanonicalName),
        CanonicalName);
    if (!NT_SUCCESS(status)) {
        RtlZeroMemory(Record, sizeof(*Record));
        return status;
    }
    Record->InUse = TRUE;
    return STATUS_SUCCESS;
}

// 中文说明：运行时失败不会阻止纯 DriverObject 字段操作，但会显式返回 loaderStatus。
static NTSTATUS
KswordARKDriverImagePrepareRuntimeLocked(
    _Inout_ KSW_DRIVER_IMAGE_RECORD* Record,
    _In_ BOOLEAN Exclusive,
    _Out_ KSW_DRIVER_IMAGE_RUNTIME* Runtime,
    _Out_ NTSTATUS* LoaderStatus,
    _Out_ BOOLEAN* StateChanged
    )
{
    NTSTATUS status = STATUS_SUCCESS;

    if (Record == NULL || Runtime == NULL ||
        LoaderStatus == NULL || StateChanged == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *StateChanged = FALSE;
    *LoaderStatus = STATUS_NOT_SUPPORTED;
    RtlZeroMemory(Runtime, sizeof(*Runtime));

    status = KswordARKDriverImageOpenRuntime(Runtime, Exclusive);
    if (!NT_SUCCESS(status)) {
        *LoaderStatus = status;
        return status;
    }
    status = KswordARKDriverImageAttachLoaderLocked(
        Runtime,
        Record,
        StateChanged);
    *LoaderStatus = status;
    return status;
}

// 中文说明：统一释放只检查实际获取位，解析成功但获取失败的 Runtime 不会误释放系统资源。
static VOID
KswordARKDriverImageCloseRuntime(
    _Inout_ KSW_DRIVER_IMAGE_RUNTIME* Runtime
    )
{
    if (Runtime != NULL && Runtime->ResourceAcquired != FALSE) {
        KswordARKDriverImageReleaseRuntime(Runtime);
    }
}

// 中文说明：无可引用对象时构造最小失败响应，绝不把 R3 地址当成可读 DriverObject。
static VOID
KswordARKDriverImageFillBasicResponse(
    _In_ const KSWORD_ARK_DRIVER_IMAGE_REQUEST* Request,
    _In_ NTSTATUS Status,
    _Out_ KSWORD_ARK_DRIVER_IMAGE_RESPONSE* Response
    )
{
    RtlZeroMemory(Response, sizeof(*Response));
    Response->version = KSWORD_ARK_DRIVER_IMAGE_PROTOCOL_VERSION;
    Response->action = Request->action;
    Response->state = KSWORD_ARK_DRIVER_IMAGE_STATE_INACTIVE;
    Response->responseFlags =
        KSWORD_ARK_DRIVER_IMAGE_RESPONSE_FLAG_WARN_ONLY_POLICY |
        KSWORD_ARK_DRIVER_IMAGE_RESPONSE_FLAG_PARTIAL_VIEW;
    Response->lastStatus = Status;
    Response->loaderStatus = STATUS_NOT_SUPPORTED;
    Response->generation = g_KswordArkDriverImageState.Generation;
    Response->targetModuleBase = Request->targetModuleBase;
    Response->driverObjectAddress =
        Request->expectedDriverObjectAddress;
    Response->selfDriverObjectAddress = (ULONGLONG)(ULONG_PTR)
        g_KswordArkDriverImageState.SelfDriverObject;
    Response->requestedValues = Request->desiredValues;
    if (KswordARKDriverImageHasTerminatedName(Request->driverName)) {
        (VOID)RtlStringCchCopyW(
            Response->driverName,
            RTL_NUMBER_OF(Response->driverName),
            Request->driverName);
    }
}

// 中文说明：退役复制完整快照供本次响应使用，并把对象引用交给锁外释放。
static PDRIVER_OBJECT
KswordARKDriverImageRetireRecordLocked(
    _Inout_ KSW_DRIVER_IMAGE_RECORD* Record,
    _Out_ KSW_DRIVER_IMAGE_RECORD* Snapshot,
    _In_ BOOLEAN AdvanceGeneration
    )
{
    PDRIVER_OBJECT releaseObject = NULL;

    *Snapshot = *Record;
    releaseObject = Record->DriverObject;
    RtlZeroMemory(Record, sizeof(*Record));
    if (AdvanceGeneration != FALSE) {
        (VOID)KswordARKDriverImageAdvanceGenerationLocked(NULL);
    }
    return releaseObject;
}

// 中文说明：QUERY 解析实时对象并优先复用记录，返回字段/链的原子一致快照。
static NTSTATUS
KswordARKDriverImageQuery(
    _In_ const KSWORD_ARK_DRIVER_IMAGE_REQUEST* Request,
    _Out_ KSWORD_ARK_DRIVER_IMAGE_RESPONSE* Response
    )
{
    KSW_DRIVER_IMAGE_RUNTIME runtime;
    KSW_DRIVER_IMAGE_RECORD temporaryRecord;
    KSW_DRIVER_IMAGE_RECORD retiredSnapshot;
    KSW_DRIVER_IMAGE_RESPONSE_CONTEXT context;
    KSW_DRIVER_IMAGE_RECORD* record = NULL;
    PDRIVER_OBJECT resolvedObject = NULL;
    PDRIVER_OBJECT retiredObject = NULL;
    WCHAR canonicalName[KSWORD_ARK_DRIVER_OBJECT_NAME_CHARS] = { 0 };
    ULONGLONG targetModuleBase = 0ULL;
    NTSTATUS status = STATUS_SUCCESS;
    NTSTATUS loaderStatus = STATUS_NOT_SUPPORTED;
    BOOLEAN attachChanged = FALSE;
    BOOLEAN refreshChanged = FALSE;

    RtlZeroMemory(&runtime, sizeof(runtime));
    RtlZeroMemory(&temporaryRecord, sizeof(temporaryRecord));
    RtlZeroMemory(&retiredSnapshot, sizeof(retiredSnapshot));
    RtlZeroMemory(&context, sizeof(context));

    status = KswordARKDriverImageResolveTarget(
        Request,
        &resolvedObject,
        canonicalName,
        RTL_NUMBER_OF(canonicalName),
        &targetModuleBase);
    if (!NT_SUCCESS(status)) {
        KswordARKDriverImageFillBasicResponse(Request, status, Response);
        return status;
    }

    ExAcquireFastMutex(&g_KswordArkDriverImageState.Lock);
    record = KswordARKDriverImageFindRecordLocked(Request);
    if (record != NULL &&
        (record->DriverObject != resolvedObject ||
         !KswordARKDriverImageRecordMatchesRequest(record, Request))) {
        status = STATUS_OBJECT_TYPE_MISMATCH;
        KswordARKDriverImageFillBasicResponse(Request, status, Response);
        ExReleaseFastMutex(&g_KswordArkDriverImageState.Lock);
        ObDereferenceObject(resolvedObject);
        return status;
    }
    if (record == NULL) {
        temporaryRecord.DriverObject = resolvedObject;
        temporaryRecord.TargetModuleBase = targetModuleBase;
        (VOID)RtlStringCchCopyW(
            temporaryRecord.CanonicalName,
            RTL_NUMBER_OF(temporaryRecord.CanonicalName),
            canonicalName);
        record = &temporaryRecord;
    }

    (VOID)KswordARKDriverImagePrepareRuntimeLocked(
        record,
        FALSE,
        &runtime,
        &loaderStatus,
        &attachChanged);
    if (record != &temporaryRecord) {
        (VOID)KswordARKDriverImageRefreshRecordLocked(
            runtime.ResourceAcquired != FALSE ? &runtime : NULL,
            record,
            &refreshChanged);
        if (attachChanged != FALSE || refreshChanged != FALSE) {
            (VOID)KswordARKDriverImageAdvanceGenerationLocked(record);
        }
    }

    context.Request = Request;
    context.Record = record;
    context.Runtime = &runtime;
    context.LastStatus = STATUS_SUCCESS;
    context.LoaderStatus = loaderStatus;
    context.RecordPresent = record != &temporaryRecord;

    if (record != &temporaryRecord &&
        KswordARKDriverImageRecordIsClean(record)) {
        retiredObject = KswordARKDriverImageRetireRecordLocked(
            record,
            &retiredSnapshot,
            TRUE);
        context.Record = &retiredSnapshot;
        context.RecordPresent = FALSE;
    }
    KswordARKDriverImageFillResponseLocked(
        &g_KswordArkDriverImageState,
        &context,
        Response);
    KswordARKDriverImageCloseRuntime(&runtime);
    ExReleaseFastMutex(&g_KswordArkDriverImageState.Lock);

    ObDereferenceObject(resolvedObject);
    if (retiredObject != NULL) {
        ObDereferenceObject(retiredObject);
    }
    return STATUS_SUCCESS;
}

// 中文说明：APPLY_FIELDS 与 HIDE 共用身份、代次、资源和记录生命周期，只在最终原语处分支。
static NTSTATUS
KswordARKDriverImageApplyOrHide(
    _In_ const KSWORD_ARK_DRIVER_IMAGE_REQUEST* Request,
    _Out_ KSWORD_ARK_DRIVER_IMAGE_RESPONSE* Response
    )
{
    KSW_DRIVER_IMAGE_RUNTIME runtime;
    KSW_DRIVER_IMAGE_RECORD retiredSnapshot;
    KSW_DRIVER_IMAGE_RECORD beforeAction;
    KSW_DRIVER_IMAGE_RESPONSE_CONTEXT context;
    KSW_DRIVER_IMAGE_RECORD* record = NULL;
    PDRIVER_OBJECT resolvedObject = NULL;
    PDRIVER_OBJECT retiredObject = NULL;
    WCHAR canonicalName[KSWORD_ARK_DRIVER_OBJECT_NAME_CHARS] = { 0 };
    ULONGLONG targetModuleBase = 0ULL;
    ULONG changedFieldMask = 0UL;
    ULONG rollbackConflictMask = 0UL;
    NTSTATUS status = STATUS_SUCCESS;
    NTSTATUS loaderStatus = STATUS_NOT_SUPPORTED;
    BOOLEAN newRecord = FALSE;
    BOOLEAN attachChanged = FALSE;
    BOOLEAN refreshChanged = FALSE;
    BOOLEAN linkChanged = FALSE;
    BOOLEAN recordChanged = FALSE;

    RtlZeroMemory(&runtime, sizeof(runtime));
    RtlZeroMemory(&retiredSnapshot, sizeof(retiredSnapshot));
    RtlZeroMemory(&beforeAction, sizeof(beforeAction));
    RtlZeroMemory(&context, sizeof(context));

    status = KswordARKDriverImageResolveTarget(
        Request,
        &resolvedObject,
        canonicalName,
        RTL_NUMBER_OF(canonicalName),
        &targetModuleBase);
    if (!NT_SUCCESS(status)) {
        KswordARKDriverImageFillBasicResponse(Request, status, Response);
        return status;
    }

    ExAcquireFastMutex(&g_KswordArkDriverImageState.Lock);
    if (g_KswordArkDriverImageState.ShuttingDown != FALSE) {
        status = STATUS_DELETE_PENDING;
        goto ApplyOrHideFailure;
    }

    record = KswordARKDriverImageFindRecordLocked(Request);
    if (record != NULL) {
        if (record->DriverObject != resolvedObject ||
            !KswordARKDriverImageRecordMatchesRequest(record, Request)) {
            status = STATUS_OBJECT_TYPE_MISMATCH;
            goto ApplyOrHideFailure;
        }
    }
    else {
        record = KswordARKDriverImageAllocateRecordLocked();
        if (record == NULL) {
            status = STATUS_INSUFFICIENT_RESOURCES;
            goto ApplyOrHideFailure;
        }
        status = KswordARKDriverImageInitializeRecordLocked(
            record,
            resolvedObject,
            targetModuleBase,
            canonicalName);
        if (!NT_SUCCESS(status)) {
            record = NULL;
            goto ApplyOrHideFailure;
        }
        resolvedObject = NULL;
        newRecord = TRUE;
    }

    (VOID)KswordARKDriverImagePrepareRuntimeLocked(
        record,
        TRUE,
        &runtime,
        &loaderStatus,
        &attachChanged);
    if (newRecord == FALSE) {
        (VOID)KswordARKDriverImageRefreshRecordLocked(
            runtime.ResourceAcquired != FALSE ? &runtime : NULL,
            record,
            &refreshChanged);
        if (attachChanged != FALSE || refreshChanged != FALSE) {
            (VOID)KswordARKDriverImageAdvanceGenerationLocked(record);
        }
        if (Request->expectedGeneration != record->Generation) {
            status = STATUS_RETRY;
            goto ApplyOrHideRespond;
        }
    }

    beforeAction = *record;
    if (Request->action ==
        KSWORD_ARK_DRIVER_IMAGE_ACTION_APPLY_FIELDS) {
        if ((Request->fieldMask &
            (KSWORD_ARK_DRIVER_IMAGE_FIELD_KLDR_DLL_BASE |
             KSWORD_ARK_DRIVER_IMAGE_FIELD_KLDR_SIZE_OF_IMAGE)) != 0UL &&
            (runtime.ResourceAcquired == FALSE ||
             !NT_SUCCESS(loaderStatus))) {
            status = NT_SUCCESS(loaderStatus)
                ? STATUS_NOT_SUPPORTED
                : loaderStatus;
        }
        else {
            status = KswordARKDriverImageApplyFieldsLocked(
                runtime.ResourceAcquired != FALSE ? &runtime : NULL,
                record,
                Request->fieldMask,
                &Request->expectedValues,
                &Request->desiredValues,
                &changedFieldMask,
                &rollbackConflictMask);
        }
    }
    else {
        if (runtime.ResourceAcquired == FALSE ||
            !NT_SUCCESS(loaderStatus)) {
            status = NT_SUCCESS(loaderStatus)
                ? STATUS_NOT_SUPPORTED
                : loaderStatus;
        }
        else {
            status = KswordARKDriverImageHideLinkLocked(
                &runtime,
                record,
                (PLIST_ENTRY)(ULONG_PTR)Request->expectedLinkFlink,
                (PLIST_ENTRY)(ULONG_PTR)Request->expectedLinkBlink,
                &linkChanged);
        }
    }

    recordChanged =
        changedFieldMask != 0UL ||
        rollbackConflictMask != 0UL ||
        linkChanged != FALSE ||
        beforeAction.ManagedFieldMask != record->ManagedFieldMask ||
        beforeAction.OwnedFieldMask != record->OwnedFieldMask ||
        beforeAction.ConflictFieldMask != record->ConflictFieldMask ||
        beforeAction.LinkManaged != record->LinkManaged ||
        beforeAction.LinkOwned != record->LinkOwned ||
        beforeAction.LinkConflict != record->LinkConflict;
    if (recordChanged != FALSE) {
        (VOID)KswordARKDriverImageAdvanceGenerationLocked(record);
    }

ApplyOrHideRespond:
    context.Request = Request;
    context.Record = record;
    context.Runtime = &runtime;
    context.LastStatus = status;
    context.LoaderStatus = loaderStatus;
    context.ChangedFieldMask = changedFieldMask;
    context.LinkChanged = linkChanged;
    context.RecordPresent = TRUE;

    if (KswordARKDriverImageRecordIsClean(record)) {
        retiredObject = KswordARKDriverImageRetireRecordLocked(
            record,
            &retiredSnapshot,
            newRecord == FALSE || recordChanged != FALSE);
        context.Record = &retiredSnapshot;
        context.RecordPresent = FALSE;
    }
    KswordARKDriverImageFillResponseLocked(
        &g_KswordArkDriverImageState,
        &context,
        Response);
    KswordARKDriverImageCloseRuntime(&runtime);
    ExReleaseFastMutex(&g_KswordArkDriverImageState.Lock);

    if (resolvedObject != NULL) {
        ObDereferenceObject(resolvedObject);
    }
    if (retiredObject != NULL) {
        ObDereferenceObject(retiredObject);
    }
    return status;

ApplyOrHideFailure:
    KswordARKDriverImageFillBasicResponse(Request, status, Response);
    KswordARKDriverImageCloseRuntime(&runtime);
    ExReleaseFastMutex(&g_KswordArkDriverImageState.Lock);
    if (resolvedObject != NULL) {
        ObDereferenceObject(resolvedObject);
    }
    return status;
}

// 中文说明：RESTORE 可以按字段和链部分恢复；ABANDON 则明确保留所有当前危险值并丢弃记录。
static NTSTATUS
KswordARKDriverImageRestoreOrAbandon(
    _In_ const KSWORD_ARK_DRIVER_IMAGE_REQUEST* Request,
    _Out_ KSWORD_ARK_DRIVER_IMAGE_RESPONSE* Response
    )
{
    KSW_DRIVER_IMAGE_RUNTIME runtime;
    KSW_DRIVER_IMAGE_RECORD retiredSnapshot;
    KSW_DRIVER_IMAGE_RECORD beforeAction;
    KSW_DRIVER_IMAGE_RESPONSE_CONTEXT context;
    KSW_DRIVER_IMAGE_RECORD* record = NULL;
    PDRIVER_OBJECT retiredObject = NULL;
    ULONG changedFieldMask = 0UL;
    ULONG failedFieldMask = 0UL;
    NTSTATUS status = STATUS_SUCCESS;
    NTSTATUS fieldStatus = STATUS_SUCCESS;
    NTSTATUS linkStatus = STATUS_SUCCESS;
    NTSTATUS loaderStatus = STATUS_NOT_SUPPORTED;
    BOOLEAN attachChanged = FALSE;
    BOOLEAN refreshChanged = FALSE;
    BOOLEAN linkChanged = FALSE;
    BOOLEAN originalPosition = FALSE;
    BOOLEAN recordChanged = FALSE;

    RtlZeroMemory(&runtime, sizeof(runtime));
    RtlZeroMemory(&retiredSnapshot, sizeof(retiredSnapshot));
    RtlZeroMemory(&beforeAction, sizeof(beforeAction));
    RtlZeroMemory(&context, sizeof(context));

    ExAcquireFastMutex(&g_KswordArkDriverImageState.Lock);
    record = KswordARKDriverImageFindRecordLocked(Request);
    if (record == NULL) {
        status = STATUS_NOT_FOUND;
        KswordARKDriverImageFillBasicResponse(Request, status, Response);
        ExReleaseFastMutex(&g_KswordArkDriverImageState.Lock);
        return status;
    }
    if (!KswordARKDriverImageRecordMatchesRequest(record, Request)) {
        status = STATUS_OBJECT_TYPE_MISMATCH;
        goto RestoreRespond;
    }

    if (Request->action == KSWORD_ARK_DRIVER_IMAGE_ACTION_ABANDON) {
        if (Request->expectedGeneration != record->Generation) {
            status = STATUS_RETRY;
            goto RestoreRespond;
        }
        (VOID)KswordARKDriverImagePrepareRuntimeLocked(
            record,
            FALSE,
            &runtime,
            &loaderStatus,
            &attachChanged);
        retiredObject = KswordARKDriverImageRetireRecordLocked(
            record,
            &retiredSnapshot,
            TRUE);
        context.Request = Request;
        context.Record = &retiredSnapshot;
        context.Runtime = &runtime;
        context.LastStatus = STATUS_SUCCESS;
        context.LoaderStatus = loaderStatus;
        context.RecordPresent = FALSE;
        KswordARKDriverImageFillResponseLocked(
            &g_KswordArkDriverImageState,
            &context,
            Response);
        KswordARKDriverImageCloseRuntime(&runtime);
        ExReleaseFastMutex(&g_KswordArkDriverImageState.Lock);
        ObDereferenceObject(retiredObject);
        return STATUS_SUCCESS;
    }

    (VOID)KswordARKDriverImagePrepareRuntimeLocked(
        record,
        TRUE,
        &runtime,
        &loaderStatus,
        &attachChanged);
    (VOID)KswordARKDriverImageRefreshRecordLocked(
        runtime.ResourceAcquired != FALSE ? &runtime : NULL,
        record,
        &refreshChanged);
    if (attachChanged != FALSE || refreshChanged != FALSE) {
        (VOID)KswordARKDriverImageAdvanceGenerationLocked(record);
    }
    if (Request->expectedGeneration != record->Generation) {
        status = STATUS_RETRY;
        goto RestoreRespond;
    }

    beforeAction = *record;
    fieldStatus = KswordARKDriverImageRestoreFieldsLocked(
        runtime.ResourceAcquired != FALSE ? &runtime : NULL,
        record,
        Request->fieldMask,
        &changedFieldMask,
        &failedFieldMask);
    status = fieldStatus;

    if ((Request->flags &
        KSWORD_ARK_DRIVER_IMAGE_FLAG_RESTORE_LINK) != 0UL) {
        if (runtime.ResourceAcquired == FALSE ||
            !NT_SUCCESS(loaderStatus)) {
            linkStatus = NT_SUCCESS(loaderStatus)
                ? STATUS_NOT_SUPPORTED
                : loaderStatus;
        }
        else {
            linkStatus = KswordARKDriverImageRestoreLinkLocked(
                &runtime,
                record,
                &linkChanged,
                &originalPosition);
        }
        if (NT_SUCCESS(status) && !NT_SUCCESS(linkStatus)) {
            status = linkStatus;
        }
    }

    recordChanged =
        changedFieldMask != 0UL ||
        failedFieldMask != 0UL ||
        linkChanged != FALSE ||
        beforeAction.ManagedFieldMask != record->ManagedFieldMask ||
        beforeAction.OwnedFieldMask != record->OwnedFieldMask ||
        beforeAction.ConflictFieldMask != record->ConflictFieldMask ||
        beforeAction.LinkManaged != record->LinkManaged ||
        beforeAction.LinkOwned != record->LinkOwned ||
        beforeAction.LinkConflict != record->LinkConflict;
    if (recordChanged != FALSE) {
        (VOID)KswordARKDriverImageAdvanceGenerationLocked(record);
    }

RestoreRespond:
    context.Request = Request;
    context.Record = record;
    context.Runtime = &runtime;
    context.LastStatus = status;
    context.LoaderStatus = loaderStatus;
    context.ChangedFieldMask = changedFieldMask;
    context.LinkChanged = linkChanged;
    context.RestoredOriginalPosition =
        linkChanged != FALSE && originalPosition != FALSE;
    context.RestoredListTail =
        linkChanged != FALSE && originalPosition == FALSE;
    context.RecordPresent = TRUE;

    if (NT_SUCCESS(status) && KswordARKDriverImageRecordIsClean(record)) {
        retiredObject = KswordARKDriverImageRetireRecordLocked(
            record,
            &retiredSnapshot,
            TRUE);
        context.Record = &retiredSnapshot;
        context.RecordPresent = FALSE;
    }
    KswordARKDriverImageFillResponseLocked(
        &g_KswordArkDriverImageState,
        &context,
        Response);
    KswordARKDriverImageCloseRuntime(&runtime);
    ExReleaseFastMutex(&g_KswordArkDriverImageState.Lock);
    if (retiredObject != NULL) {
        ObDereferenceObject(retiredObject);
    }
    return status;
}

// 中文说明：初始化不引用自身 DriverObject，其生命周期天然覆盖整个 WDF 驱动实例。
NTSTATUS
KswordARKDriverImageInitialize(
    _In_ PDRIVER_OBJECT DriverObject
    )
{
    if (DriverObject == NULL || KeGetCurrentIrql() != PASSIVE_LEVEL) {
        return STATUS_INVALID_PARAMETER;
    }
    if (InterlockedCompareExchange(
        &g_KswordArkDriverImageState.Initialized,
        0L,
        0L) != 0L) {
        return g_KswordArkDriverImageState.SelfDriverObject == DriverObject
            ? STATUS_SUCCESS
            : STATUS_INVALID_DEVICE_STATE;
    }

    RtlZeroMemory(
        &g_KswordArkDriverImageState,
        sizeof(g_KswordArkDriverImageState));
    ExInitializeFastMutex(&g_KswordArkDriverImageState.Lock);
    g_KswordArkDriverImageState.Generation = 1UL;
    g_KswordArkDriverImageState.SelfDriverObject = DriverObject;
    InterlockedExchange(
        &g_KswordArkDriverImageState.Initialized,
        1L);
    return STATUS_SUCCESS;
}

// 中文说明：正常卸载尽力恢复仍由事务拥有的字段和自环链；竞争值保持不变后释放记录。
VOID
KswordARKDriverImageUninitialize(
    VOID
    )
{
    KSW_DRIVER_IMAGE_RUNTIME runtime;
    PDRIVER_OBJECT releaseObjects[KSW_DRIVER_IMAGE_RECORD_LIMIT] = { 0 };
    ULONG releaseCount = 0UL;
    ULONG index = 0UL;
    BOOLEAN runtimeOpened = FALSE;

    if (InterlockedCompareExchange(
        &g_KswordArkDriverImageState.Initialized,
        0L,
        0L) == 0L) {
        return;
    }
    RtlZeroMemory(&runtime, sizeof(runtime));

    ExAcquireFastMutex(&g_KswordArkDriverImageState.Lock);
    g_KswordArkDriverImageState.ShuttingDown = TRUE;
    if (NT_SUCCESS(KswordARKDriverImageOpenRuntime(&runtime, TRUE))) {
        runtimeOpened = TRUE;
    }

    for (index = 0UL; index < KSW_DRIVER_IMAGE_RECORD_LIMIT; ++index) {
        KSW_DRIVER_IMAGE_RECORD* record =
            &g_KswordArkDriverImageState.Records[index];
        ULONG changedMask = 0UL;
        ULONG failedMask = 0UL;
        BOOLEAN linkChanged = FALSE;
        BOOLEAN originalPosition = FALSE;
        BOOLEAN refreshChanged = FALSE;

        if (record->InUse == FALSE || record->DriverObject == NULL) {
            continue;
        }
        (VOID)KswordARKDriverImageRefreshRecordLocked(
            runtimeOpened != FALSE ? &runtime : NULL,
            record,
            &refreshChanged);
        (VOID)KswordARKDriverImageRestoreFieldsLocked(
            runtimeOpened != FALSE ? &runtime : NULL,
            record,
            record->ManagedFieldMask,
            &changedMask,
            &failedMask);
        if (record->LinkManaged != FALSE &&
            record->LinkOwned != FALSE &&
            runtimeOpened != FALSE) {
            (VOID)KswordARKDriverImageRestoreLinkLocked(
                &runtime,
                record,
                &linkChanged,
                &originalPosition);
        }
        releaseObjects[releaseCount++] = record->DriverObject;
        RtlZeroMemory(record, sizeof(*record));
    }

    KswordARKDriverImageCloseRuntime(&runtime);
    ExReleaseFastMutex(&g_KswordArkDriverImageState.Lock);
    InterlockedExchange(
        &g_KswordArkDriverImageState.Initialized,
        0L);

    for (index = 0UL; index < releaseCount; ++index) {
        ObDereferenceObject(releaseObjects[index]);
    }
    RtlZeroMemory(
        &g_KswordArkDriverImageState,
        sizeof(g_KswordArkDriverImageState));
}

// 中文说明：协议入口只做结构/确认/并发前提校验，不增加目标类别或值域策略。
NTSTATUS
KswordARKDriverControlImage(
    _In_ const KSWORD_ARK_DRIVER_IMAGE_REQUEST* Request,
    _Out_ KSWORD_ARK_DRIVER_IMAGE_RESPONSE* Response
    )
{
    const ULONG allowedFlags =
        KSWORD_ARK_DRIVER_IMAGE_FLAG_TARGET_MODULE_BASE_PRESENT |
        KSWORD_ARK_DRIVER_IMAGE_FLAG_EXPECTED_DRIVER_OBJECT_PRESENT |
        KSWORD_ARK_DRIVER_IMAGE_FLAG_EXPECTED_GENERATION_PRESENT |
        KSWORD_ARK_DRIVER_IMAGE_FLAG_EXPECTED_VALUES_PRESENT |
        KSWORD_ARK_DRIVER_IMAGE_FLAG_EXPECTED_LINKS_PRESENT |
        KSWORD_ARK_DRIVER_IMAGE_FLAG_UI_CONFIRMED |
        KSWORD_ARK_DRIVER_IMAGE_FLAG_RESTORE_LINK;
    NTSTATUS status = STATUS_SUCCESS;

    if (Request == NULL || Response == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    KswordARKDriverImageFillBasicResponse(
        Request,
        STATUS_INVALID_PARAMETER,
        Response);

    if (KeGetCurrentIrql() != PASSIVE_LEVEL ||
        InterlockedCompareExchange(
            &g_KswordArkDriverImageState.Initialized,
            0L,
            0L) == 0L) {
        status = STATUS_DEVICE_NOT_READY;
    }
    else if (Request->version !=
        KSWORD_ARK_DRIVER_IMAGE_PROTOCOL_VERSION ||
        Request->action > KSWORD_ARK_DRIVER_IMAGE_ACTION_ABANDON ||
        (Request->flags & ~allowedFlags) != 0UL ||
        Request->reserved0 != 0UL || Request->reserved1 != 0UL ||
        !KswordARKDriverImageHasTerminatedName(Request->driverName) ||
        (Request->fieldMask &
         ~KSWORD_ARK_DRIVER_IMAGE_FIELD_ALL) != 0UL) {
        status = STATUS_INVALID_PARAMETER;
    }
    else if (Request->driverName[0] == L'\0' &&
        (((Request->flags &
           KSWORD_ARK_DRIVER_IMAGE_FLAG_TARGET_MODULE_BASE_PRESENT) == 0UL) ||
         Request->targetModuleBase == 0ULL)) {
        status = STATUS_INVALID_PARAMETER;
    }
    else if (Request->action != KSWORD_ARK_DRIVER_IMAGE_ACTION_QUERY &&
        (((Request->flags &
           KSWORD_ARK_DRIVER_IMAGE_FLAG_EXPECTED_DRIVER_OBJECT_PRESENT) == 0UL) ||
         ((Request->flags &
           KSWORD_ARK_DRIVER_IMAGE_FLAG_EXPECTED_GENERATION_PRESENT) == 0UL) ||
         ((Request->flags &
           KSWORD_ARK_DRIVER_IMAGE_FLAG_UI_CONFIRMED) == 0UL) ||
         Request->expectedDriverObjectAddress == 0ULL ||
         Request->expectedGeneration == 0UL ||
         Request->driverName[0] == L'\0' ||
         Request->confirmationToken !=
            KSWORD_ARK_DRIVER_IMAGE_CONFIRMATION_TOKEN)) {
        status = STATUS_INVALID_PARAMETER;
    }
    else if (Request->action ==
        KSWORD_ARK_DRIVER_IMAGE_ACTION_APPLY_FIELDS &&
        (Request->fieldMask == 0UL ||
         (Request->flags &
          KSWORD_ARK_DRIVER_IMAGE_FLAG_EXPECTED_VALUES_PRESENT) == 0UL)) {
        status = STATUS_INVALID_PARAMETER;
    }
    else if (Request->action == KSWORD_ARK_DRIVER_IMAGE_ACTION_HIDE &&
        (Request->flags &
         KSWORD_ARK_DRIVER_IMAGE_FLAG_EXPECTED_LINKS_PRESENT) == 0UL) {
        status = STATUS_INVALID_PARAMETER;
    }
    else {
        switch (Request->action) {
        case KSWORD_ARK_DRIVER_IMAGE_ACTION_QUERY:
            return KswordARKDriverImageQuery(Request, Response);
        case KSWORD_ARK_DRIVER_IMAGE_ACTION_APPLY_FIELDS:
        case KSWORD_ARK_DRIVER_IMAGE_ACTION_HIDE:
            return KswordARKDriverImageApplyOrHide(Request, Response);
        case KSWORD_ARK_DRIVER_IMAGE_ACTION_RESTORE:
        case KSWORD_ARK_DRIVER_IMAGE_ACTION_ABANDON:
            return KswordARKDriverImageRestoreOrAbandon(Request, Response);
        default:
            status = STATUS_INVALID_PARAMETER;
            break;
        }
    }

    Response->lastStatus = status;
    return status;
}

// 中文说明：任一活动或冲突记录都会阻止 KSword 自己的强制卸载路径，放弃后才解除。
BOOLEAN
KswordARKDriverImageHasBlockingRecord(
    _In_ PDRIVER_OBJECT TargetDriverObject,
    _In_ ULONGLONG OriginalRequestModuleBase
    )
{
    ULONG index = 0UL;
    BOOLEAN blocked = FALSE;

    if (TargetDriverObject == NULL) {
        return TRUE;
    }
    if (InterlockedCompareExchange(
        &g_KswordArkDriverImageState.Initialized,
        0L,
        0L) == 0L) {
        return FALSE;
    }
    if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
        return TRUE;
    }

    ExAcquireFastMutex(&g_KswordArkDriverImageState.Lock);
    for (index = 0UL; index < KSW_DRIVER_IMAGE_RECORD_LIMIT; ++index) {
        const KSW_DRIVER_IMAGE_RECORD* record =
            &g_KswordArkDriverImageState.Records[index];
        if (record->InUse != FALSE &&
            (record->DriverObject == TargetDriverObject ||
             (OriginalRequestModuleBase != 0ULL &&
              record->TargetModuleBase == OriginalRequestModuleBase))) {
            blocked = TRUE;
            break;
        }
    }
    ExReleaseFastMutex(&g_KswordArkDriverImageState.Lock);
    return blocked;
}
