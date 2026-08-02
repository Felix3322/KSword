/*++

Module Name:

    driver_dispatch_editor.c

Abstract:

    Unrestricted, transactional DriverObject MajorFunction editor.

    This component intentionally applies no target class, module owner, PnP,
    file-system, security-product, or pointer-range policy.  Mutation safety is
    limited to stable object identity, an exact expected-current value, a
    mandatory mutation generation, and InterlockedCompareExchangePointer.

Environment:

    Kernel-mode Driver Framework, PASSIVE_LEVEL control path.

--*/

#include <ntifs.h>

#include "ark/ark_driver.h"

#include <ntstrsafe.h>

#define KSW_DRIVER_DISPATCH_RECORD_LIMIT 128UL

typedef struct _KSW_DRIVER_DISPATCH_RECORD
{
    BOOLEAN InUse;
    BOOLEAN Owned;
    BOOLEAN Conflict;
    UCHAR MajorFunction;
    ULONG Generation;
    ULONGLONG TargetModuleBase;
    PDRIVER_OBJECT DriverObject;
    PDRIVER_DISPATCH OriginalDispatch;
    PDRIVER_DISPATCH AppliedDispatch;
    WCHAR CanonicalName[KSWORD_ARK_DRIVER_OBJECT_NAME_CHARS];
} KSW_DRIVER_DISPATCH_RECORD, *PKSW_DRIVER_DISPATCH_RECORD;

typedef struct _KSW_DRIVER_DISPATCH_STATE
{
    FAST_MUTEX Lock;
    volatile LONG Initialized;
    BOOLEAN ShuttingDown;
    UCHAR Padding[3];
    ULONG Generation;
    PDRIVER_OBJECT SelfDriverObject;
    KSW_DRIVER_DISPATCH_RECORD Records[KSW_DRIVER_DISPATCH_RECORD_LIMIT];
} KSW_DRIVER_DISPATCH_STATE, *PKSW_DRIVER_DISPATCH_STATE;

static KSW_DRIVER_DISPATCH_STATE g_KswordArkDriverDispatchState;

C_ASSERT(sizeof(KSWORD_ARK_DRIVER_DISPATCH_REQUEST) == 584U);
C_ASSERT(sizeof(KSWORD_ARK_DRIVER_DISPATCH_RESPONSE) == 608U);
C_ASSERT(IRP_MJ_MAXIMUM_FUNCTION <= 0xFFU);

static PDRIVER_DISPATCH
KswordARKDriverDispatchRead(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ UCHAR MajorFunction
    )
{
    return (PDRIVER_DISPATCH)InterlockedCompareExchangePointer(
        (PVOID volatile*)&DriverObject->MajorFunction[MajorFunction],
        NULL,
        NULL);
}

static PDRIVER_DISPATCH
KswordARKDriverDispatchCompareExchange(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ UCHAR MajorFunction,
    _In_ PDRIVER_DISPATCH Exchange,
    _In_ PDRIVER_DISPATCH Expected
    )
{
    return (PDRIVER_DISPATCH)InterlockedCompareExchangePointer(
        (PVOID volatile*)&DriverObject->MajorFunction[MajorFunction],
        (PVOID)Exchange,
        (PVOID)Expected);
}

static ULONG
KswordARKDriverDispatchAdvanceGenerationLocked(
    _Inout_opt_ KSW_DRIVER_DISPATCH_RECORD* Record
    )
{
    ++g_KswordArkDriverDispatchState.Generation;
    if (g_KswordArkDriverDispatchState.Generation == 0UL) {
        ++g_KswordArkDriverDispatchState.Generation;
    }
    if (Record != NULL) {
        Record->Generation = g_KswordArkDriverDispatchState.Generation;
    }
    return g_KswordArkDriverDispatchState.Generation;
}

static KSW_DRIVER_DISPATCH_RECORD*
KswordARKDriverDispatchFindRecordLocked(
    _In_ ULONGLONG TargetModuleBase,
    _In_ UCHAR MajorFunction
    )
{
    ULONG index = 0UL;

    for (index = 0UL; index < KSW_DRIVER_DISPATCH_RECORD_LIMIT; ++index) {
        KSW_DRIVER_DISPATCH_RECORD* record =
            &g_KswordArkDriverDispatchState.Records[index];
        if (record->InUse != FALSE &&
            record->TargetModuleBase == TargetModuleBase &&
            record->MajorFunction == MajorFunction) {
            return record;
        }
    }
    return NULL;
}

static KSW_DRIVER_DISPATCH_RECORD*
KswordARKDriverDispatchAllocateRecordLocked(
    VOID
    )
{
    ULONG index = 0UL;

    for (index = 0UL; index < KSW_DRIVER_DISPATCH_RECORD_LIMIT; ++index) {
        KSW_DRIVER_DISPATCH_RECORD* record =
            &g_KswordArkDriverDispatchState.Records[index];
        if (record->InUse == FALSE) {
            RtlZeroMemory(record, sizeof(*record));
            return record;
        }
    }
    return NULL;
}

static BOOLEAN
KswordARKDriverDispatchHasTerminatedName(
    _In_reads_(KSWORD_ARK_DRIVER_OBJECT_NAME_CHARS) const WCHAR* DriverName
    )
{
    ULONG index = 0UL;

    if (DriverName == NULL) {
        return FALSE;
    }
    for (index = 0UL; index < KSWORD_ARK_DRIVER_OBJECT_NAME_CHARS; ++index) {
        if (DriverName[index] == L'\0') {
            return TRUE;
        }
    }
    return FALSE;
}

static BOOLEAN
KswordARKDriverDispatchNamesEqual(
    _In_z_ const WCHAR* Left,
    _In_z_ const WCHAR* Right
    )
{
    UNICODE_STRING leftName;
    UNICODE_STRING rightName;

    if (Left == NULL || Right == NULL || Left[0] == L'\0' || Right[0] == L'\0') {
        return FALSE;
    }
    RtlInitUnicodeString(&leftName, Left);
    RtlInitUnicodeString(&rightName, Right);
    return RtlEqualUnicodeString(&leftName, &rightName, TRUE);
}

static BOOLEAN
KswordARKDriverDispatchRecordMatchesRequest(
    _In_ const KSW_DRIVER_DISPATCH_RECORD* Record,
    _In_ const KSWORD_ARK_DRIVER_DISPATCH_REQUEST* Request
    )
{
    if (Record == NULL || Request == NULL || Record->InUse == FALSE) {
        return FALSE;
    }
    if ((Request->flags &
        KSWORD_ARK_DRIVER_DISPATCH_FLAG_EXPECTED_DRIVER_OBJECT_PRESENT) != 0UL &&
        Request->expectedDriverObjectAddress !=
            (ULONGLONG)(ULONG_PTR)Record->DriverObject) {
        return FALSE;
    }
    if (Request->driverName[0] != L'\0' &&
        !KswordARKDriverDispatchNamesEqual(
            Request->driverName,
            Record->CanonicalName)) {
        return FALSE;
    }
    return TRUE;
}

static VOID
KswordARKDriverDispatchRefreshRecordLocked(
    _Inout_ KSW_DRIVER_DISPATCH_RECORD* Record
    )
{
    PDRIVER_DISPATCH current = NULL;
    BOOLEAN oldOwned = FALSE;
    BOOLEAN oldConflict = FALSE;

    if (Record == NULL || Record->InUse == FALSE || Record->DriverObject == NULL) {
        return;
    }

    oldOwned = Record->Owned;
    oldConflict = Record->Conflict;
    current = KswordARKDriverDispatchRead(
        Record->DriverObject,
        Record->MajorFunction);

    if (Record->Owned != FALSE) {
        if (current == Record->AppliedDispatch) {
            /* Still exactly owned by this transaction. */
        }
        else if (current == Record->OriginalDispatch) {
            Record->Owned = FALSE;
        }
        else {
            Record->Owned = FALSE;
            Record->Conflict = TRUE;
        }
    }
    else if (current != Record->OriginalDispatch) {
        Record->Conflict = TRUE;
    }

    if (oldOwned != Record->Owned || oldConflict != Record->Conflict) {
        (VOID)KswordARKDriverDispatchAdvanceGenerationLocked(Record);
    }
}

static VOID
KswordARKDriverDispatchFillResponse(
    _Out_ KSWORD_ARK_DRIVER_DISPATCH_RESPONSE* Response,
    _In_ ULONG Action,
    _In_ UCHAR MajorFunction,
    _In_ NTSTATUS LastStatus,
    _In_ ULONGLONG RequestedDispatch,
    _In_opt_ const KSW_DRIVER_DISPATCH_RECORD* Record,
    _In_opt_ PDRIVER_OBJECT DriverObject,
    _In_ ULONGLONG TargetModuleBase,
    _In_opt_z_ const WCHAR* CanonicalName,
    _In_ BOOLEAN Changed
    )
{
    PDRIVER_DISPATCH current = NULL;

    RtlZeroMemory(Response, sizeof(*Response));
    Response->version = KSWORD_ARK_DRIVER_DISPATCH_PROTOCOL_VERSION;
    Response->action = Action;
    Response->majorFunction = MajorFunction;
    Response->lastStatus = LastStatus;
    Response->requestedDispatchAddress = RequestedDispatch;
    Response->targetModuleBase = TargetModuleBase;
    Response->selfDriverObjectAddress = (ULONGLONG)(ULONG_PTR)
        g_KswordArkDriverDispatchState.SelfDriverObject;
    Response->responseFlags =
        KSWORD_ARK_DRIVER_DISPATCH_RESPONSE_FLAG_WARN_ONLY_POLICY;
    if (Changed != FALSE) {
        Response->responseFlags |=
            KSWORD_ARK_DRIVER_DISPATCH_RESPONSE_FLAG_CHANGED;
    }

    if (Record != NULL && Record->InUse != FALSE) {
        DriverObject = Record->DriverObject;
        TargetModuleBase = Record->TargetModuleBase;
        CanonicalName = Record->CanonicalName;
        current = KswordARKDriverDispatchRead(
            Record->DriverObject,
            Record->MajorFunction);
        Response->responseFlags |=
            KSWORD_ARK_DRIVER_DISPATCH_RESPONSE_FLAG_RECORD_PRESENT;
        if (Record->Owned != FALSE) {
            Response->responseFlags |=
                KSWORD_ARK_DRIVER_DISPATCH_RESPONSE_FLAG_OWNED;
        }
        if (Record->Conflict != FALSE) {
            Response->responseFlags |=
                KSWORD_ARK_DRIVER_DISPATCH_RESPONSE_FLAG_FOREIGN_CHANGE;
        }
        Response->state = Record->Conflict != FALSE
            ? KSWORD_ARK_DRIVER_DISPATCH_STATE_CONFLICT
            : (Record->Owned != FALSE
                ? KSWORD_ARK_DRIVER_DISPATCH_STATE_ACTIVE
                : KSWORD_ARK_DRIVER_DISPATCH_STATE_INACTIVE);
        Response->generation = Record->Generation;
        Response->originalDispatchAddress =
            (ULONGLONG)(ULONG_PTR)Record->OriginalDispatch;
        Response->appliedDispatchAddress =
            (ULONGLONG)(ULONG_PTR)Record->AppliedDispatch;
    }
    else {
        Response->state = KSWORD_ARK_DRIVER_DISPATCH_STATE_INACTIVE;
        Response->generation = g_KswordArkDriverDispatchState.Generation;
        if (DriverObject != NULL) {
            current = KswordARKDriverDispatchRead(DriverObject, MajorFunction);
        }
    }

    Response->targetModuleBase = TargetModuleBase;
    Response->driverObjectAddress = (ULONGLONG)(ULONG_PTR)DriverObject;
    Response->currentDispatchAddress = (ULONGLONG)(ULONG_PTR)current;
    if (current == (PDRIVER_DISPATCH)(ULONG_PTR)Response->originalDispatchAddress &&
        (Record != NULL && Record->InUse != FALSE)) {
        Response->responseFlags |=
            KSWORD_ARK_DRIVER_DISPATCH_RESPONSE_FLAG_CURRENT_IS_ORIGINAL;
    }
    if (current == (PDRIVER_DISPATCH)(ULONG_PTR)Response->appliedDispatchAddress &&
        (Record != NULL && Record->InUse != FALSE)) {
        Response->responseFlags |=
            KSWORD_ARK_DRIVER_DISPATCH_RESPONSE_FLAG_CURRENT_IS_APPLIED;
    }
    if (DriverObject != NULL &&
        DriverObject == g_KswordArkDriverDispatchState.SelfDriverObject) {
        Response->responseFlags |=
            KSWORD_ARK_DRIVER_DISPATCH_RESPONSE_FLAG_SELF_TARGET;
        if (MajorFunction == IRP_MJ_DEVICE_CONTROL) {
            Response->responseFlags |=
                KSWORD_ARK_DRIVER_DISPATCH_RESPONSE_FLAG_SELF_CONTROL_CHANNEL;
        }
    }
    if (CanonicalName != NULL) {
        (VOID)RtlStringCchCopyW(
            Response->driverName,
            RTL_NUMBER_OF(Response->driverName),
            CanonicalName);
    }
}

static VOID
KswordARKDriverDispatchFillRetiredResponse(
    _Out_ KSWORD_ARK_DRIVER_DISPATCH_RESPONSE* Response,
    _In_ ULONG Action,
    _In_ UCHAR MajorFunction,
    _In_ NTSTATUS LastStatus,
    _In_ ULONGLONG RequestedDispatch,
    _In_ const KSW_DRIVER_DISPATCH_RECORD* Snapshot,
    _In_ PDRIVER_DISPATCH CurrentDispatch,
    _In_ BOOLEAN Changed
    )
{
    KswordARKDriverDispatchFillResponse(
        Response,
        Action,
        MajorFunction,
        LastStatus,
        RequestedDispatch,
        NULL,
        Snapshot->DriverObject,
        Snapshot->TargetModuleBase,
        Snapshot->CanonicalName,
        Changed);
    Response->generation = g_KswordArkDriverDispatchState.Generation;
    Response->currentDispatchAddress = (ULONGLONG)(ULONG_PTR)CurrentDispatch;
    Response->originalDispatchAddress =
        (ULONGLONG)(ULONG_PTR)Snapshot->OriginalDispatch;
    Response->appliedDispatchAddress =
        (ULONGLONG)(ULONG_PTR)Snapshot->AppliedDispatch;
    if (CurrentDispatch == Snapshot->OriginalDispatch) {
        Response->responseFlags |=
            KSWORD_ARK_DRIVER_DISPATCH_RESPONSE_FLAG_CURRENT_IS_ORIGINAL;
    }
}

static NTSTATUS
KswordARKDriverDispatchResolveTarget(
    _In_ const KSWORD_ARK_DRIVER_DISPATCH_REQUEST* Request,
    _Outptr_ PDRIVER_OBJECT* DriverObjectOut,
    _Out_writes_(NameChars) PWCHAR CanonicalNameOut,
    _In_ ULONG NameChars
    )
{
    PDRIVER_OBJECT driverObject = NULL;
    NTSTATUS status = STATUS_SUCCESS;

    status = KswordARKDriverReferenceObjectByModuleBase(
        Request->targetModuleBase,
        &driverObject,
        CanonicalNameOut,
        NameChars);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    if ((ULONGLONG)(ULONG_PTR)driverObject->DriverStart !=
        Request->targetModuleBase) {
        ObDereferenceObject(driverObject);
        return STATUS_OBJECT_TYPE_MISMATCH;
    }
    if ((Request->flags &
        KSWORD_ARK_DRIVER_DISPATCH_FLAG_EXPECTED_DRIVER_OBJECT_PRESENT) != 0UL &&
        Request->expectedDriverObjectAddress !=
            (ULONGLONG)(ULONG_PTR)driverObject) {
        ObDereferenceObject(driverObject);
        return STATUS_OBJECT_TYPE_MISMATCH;
    }
    if (Request->driverName[0] != L'\0' &&
        !KswordARKDriverDispatchNamesEqual(
            Request->driverName,
            CanonicalNameOut)) {
        ObDereferenceObject(driverObject);
        return STATUS_OBJECT_TYPE_MISMATCH;
    }
    *DriverObjectOut = driverObject;
    return STATUS_SUCCESS;
}

static NTSTATUS
KswordARKDriverDispatchQuery(
    _In_ const KSWORD_ARK_DRIVER_DISPATCH_REQUEST* Request,
    _Out_ KSWORD_ARK_DRIVER_DISPATCH_RESPONSE* Response
    )
{
    KSW_DRIVER_DISPATCH_RECORD* record = NULL;
    PDRIVER_OBJECT driverObject = NULL;
    WCHAR canonicalName[KSWORD_ARK_DRIVER_OBJECT_NAME_CHARS] = { 0 };
    NTSTATUS status = STATUS_SUCCESS;

    ExAcquireFastMutex(&g_KswordArkDriverDispatchState.Lock);
    record = KswordARKDriverDispatchFindRecordLocked(
        Request->targetModuleBase,
        (UCHAR)Request->majorFunction);
    if (record != NULL) {
        if (!KswordARKDriverDispatchRecordMatchesRequest(record, Request)) {
            KswordARKDriverDispatchFillResponse(
                Response,
                Request->action,
                (UCHAR)Request->majorFunction,
                STATUS_OBJECT_TYPE_MISMATCH,
                Request->desiredDispatchAddress,
                record,
                NULL,
                0ULL,
                NULL,
                FALSE);
            ExReleaseFastMutex(&g_KswordArkDriverDispatchState.Lock);
            return STATUS_OBJECT_TYPE_MISMATCH;
        }
        KswordARKDriverDispatchRefreshRecordLocked(record);
        KswordARKDriverDispatchFillResponse(
            Response,
            Request->action,
            (UCHAR)Request->majorFunction,
            STATUS_SUCCESS,
            Request->desiredDispatchAddress,
            record,
            NULL,
            0ULL,
            NULL,
            FALSE);
        ExReleaseFastMutex(&g_KswordArkDriverDispatchState.Lock);
        return STATUS_SUCCESS;
    }
    ExReleaseFastMutex(&g_KswordArkDriverDispatchState.Lock);

    status = KswordARKDriverDispatchResolveTarget(
        Request,
        &driverObject,
        canonicalName,
        RTL_NUMBER_OF(canonicalName));
    if (!NT_SUCCESS(status)) {
        KswordARKDriverDispatchFillResponse(
            Response,
            Request->action,
            (UCHAR)Request->majorFunction,
            status,
            Request->desiredDispatchAddress,
            NULL,
            NULL,
            Request->targetModuleBase,
            canonicalName,
            FALSE);
        return status;
    }
    KswordARKDriverDispatchFillResponse(
        Response,
        Request->action,
        (UCHAR)Request->majorFunction,
        STATUS_SUCCESS,
        Request->desiredDispatchAddress,
        NULL,
        driverObject,
        Request->targetModuleBase,
        canonicalName,
        FALSE);
    ObDereferenceObject(driverObject);
    return STATUS_SUCCESS;
}

static NTSTATUS
KswordARKDriverDispatchApply(
    _In_ const KSWORD_ARK_DRIVER_DISPATCH_REQUEST* Request,
    _Out_ KSWORD_ARK_DRIVER_DISPATCH_RESPONSE* Response
    )
{
    KSW_DRIVER_DISPATCH_RECORD* record = NULL;
    PDRIVER_OBJECT driverObject = NULL;
    PDRIVER_OBJECT releaseObject = NULL;
    PDRIVER_DISPATCH current = NULL;
    PDRIVER_DISPATCH previous = NULL;
    PDRIVER_DISPATCH desired =
        (PDRIVER_DISPATCH)(ULONG_PTR)Request->desiredDispatchAddress;
    KSW_DRIVER_DISPATCH_RECORD retiredSnapshot;
    WCHAR canonicalName[KSWORD_ARK_DRIVER_OBJECT_NAME_CHARS] = { 0 };
    BOOLEAN newRecord = FALSE;
    NTSTATUS status = STATUS_SUCCESS;

    RtlZeroMemory(&retiredSnapshot, sizeof(retiredSnapshot));
    status = KswordARKDriverDispatchResolveTarget(
        Request,
        &driverObject,
        canonicalName,
        RTL_NUMBER_OF(canonicalName));
    if (!NT_SUCCESS(status)) {
        KswordARKDriverDispatchFillResponse(
            Response,
            Request->action,
            (UCHAR)Request->majorFunction,
            status,
            Request->desiredDispatchAddress,
            NULL,
            NULL,
            Request->targetModuleBase,
            canonicalName,
            FALSE);
        return status;
    }

    ExAcquireFastMutex(&g_KswordArkDriverDispatchState.Lock);
    if (g_KswordArkDriverDispatchState.ShuttingDown != FALSE) {
        status = STATUS_DELETE_PENDING;
        goto ApplyFailureLocked;
    }
    record = KswordARKDriverDispatchFindRecordLocked(
        Request->targetModuleBase,
        (UCHAR)Request->majorFunction);
    if (record != NULL) {
        if (record->DriverObject != driverObject ||
            !KswordARKDriverDispatchNamesEqual(
                record->CanonicalName,
                canonicalName)) {
            status = STATUS_OBJECT_TYPE_MISMATCH;
            goto ApplyFailureLocked;
        }
        KswordARKDriverDispatchRefreshRecordLocked(record);
        if ((Request->flags &
            KSWORD_ARK_DRIVER_DISPATCH_FLAG_EXPECTED_GENERATION_PRESENT) != 0UL &&
            Request->expectedGeneration != record->Generation) {
            status = STATUS_RETRY;
            goto ApplyFailureLocked;
        }
        if (record->Conflict != FALSE) {
            status = STATUS_DEVICE_BUSY;
            goto ApplyFailureLocked;
        }
    }

    current = KswordARKDriverDispatchRead(
        driverObject,
        (UCHAR)Request->majorFunction);
    if (current != (PDRIVER_DISPATCH)(ULONG_PTR)
        Request->expectedCurrentDispatchAddress) {
        status = STATUS_RETRY;
        goto ApplyFailureLocked;
    }
    if (current == desired) {
        KswordARKDriverDispatchFillResponse(
            Response,
            Request->action,
            (UCHAR)Request->majorFunction,
            STATUS_SUCCESS,
            Request->desiredDispatchAddress,
            record,
            driverObject,
            Request->targetModuleBase,
            canonicalName,
            FALSE);
        ExReleaseFastMutex(&g_KswordArkDriverDispatchState.Lock);
        ObDereferenceObject(driverObject);
        return STATUS_SUCCESS;
    }

    if (record == NULL) {
        record = KswordARKDriverDispatchAllocateRecordLocked();
        if (record == NULL) {
            status = STATUS_INSUFFICIENT_RESOURCES;
            goto ApplyFailureLocked;
        }
        newRecord = TRUE;
    }

    previous = KswordARKDriverDispatchCompareExchange(
        driverObject,
        (UCHAR)Request->majorFunction,
        desired,
        current);
    if (previous != current) {
        if (newRecord != FALSE) {
            RtlZeroMemory(record, sizeof(*record));
            record = NULL;
        }
        else {
            KswordARKDriverDispatchRefreshRecordLocked(record);
        }
        status = STATUS_RETRY;
        goto ApplyFailureLocked;
    }

    if (newRecord != FALSE) {
        record->InUse = TRUE;
        record->Owned = TRUE;
        record->Conflict = FALSE;
        record->MajorFunction = (UCHAR)Request->majorFunction;
        record->TargetModuleBase = Request->targetModuleBase;
        record->DriverObject = driverObject;
        record->OriginalDispatch = current;
        record->AppliedDispatch = desired;
        (VOID)RtlStringCchCopyW(
            record->CanonicalName,
            RTL_NUMBER_OF(record->CanonicalName),
            canonicalName);
        (VOID)KswordARKDriverDispatchAdvanceGenerationLocked(record);
        driverObject = NULL;
    }
    else {
        record->Owned = TRUE;
        record->AppliedDispatch = desired;
        (VOID)KswordARKDriverDispatchAdvanceGenerationLocked(record);
    }

    if (record->AppliedDispatch == record->OriginalDispatch) {
        retiredSnapshot = *record;
        releaseObject = record->DriverObject;
        current = record->OriginalDispatch;
        RtlZeroMemory(record, sizeof(*record));
        (VOID)KswordARKDriverDispatchAdvanceGenerationLocked(NULL);
        KswordARKDriverDispatchFillRetiredResponse(
            Response,
            Request->action,
            (UCHAR)Request->majorFunction,
            STATUS_SUCCESS,
            Request->desiredDispatchAddress,
            &retiredSnapshot,
            current,
            TRUE);
    }
    else {
        KswordARKDriverDispatchFillResponse(
            Response,
            Request->action,
            (UCHAR)Request->majorFunction,
            STATUS_SUCCESS,
            Request->desiredDispatchAddress,
            record,
            NULL,
            0ULL,
            NULL,
            TRUE);
    }
    ExReleaseFastMutex(&g_KswordArkDriverDispatchState.Lock);
    if (driverObject != NULL) {
        ObDereferenceObject(driverObject);
    }
    if (releaseObject != NULL) {
        ObDereferenceObject(releaseObject);
    }
    return STATUS_SUCCESS;

ApplyFailureLocked:
    KswordARKDriverDispatchFillResponse(
        Response,
        Request->action,
        (UCHAR)Request->majorFunction,
        status,
        Request->desiredDispatchAddress,
        record,
        driverObject,
        Request->targetModuleBase,
        canonicalName,
        FALSE);
    ExReleaseFastMutex(&g_KswordArkDriverDispatchState.Lock);
    ObDereferenceObject(driverObject);
    return status;
}

static NTSTATUS
KswordARKDriverDispatchRestoreOrAbandon(
    _In_ const KSWORD_ARK_DRIVER_DISPATCH_REQUEST* Request,
    _Out_ KSWORD_ARK_DRIVER_DISPATCH_RESPONSE* Response
    )
{
    KSW_DRIVER_DISPATCH_RECORD* record = NULL;
    KSW_DRIVER_DISPATCH_RECORD retiredSnapshot;
    PDRIVER_OBJECT releaseObject = NULL;
    PDRIVER_DISPATCH current = NULL;
    PDRIVER_DISPATCH previous = NULL;
    NTSTATUS status = STATUS_SUCCESS;
    BOOLEAN changed = FALSE;

    RtlZeroMemory(&retiredSnapshot, sizeof(retiredSnapshot));
    ExAcquireFastMutex(&g_KswordArkDriverDispatchState.Lock);
    record = KswordARKDriverDispatchFindRecordLocked(
        Request->targetModuleBase,
        (UCHAR)Request->majorFunction);
    if (record == NULL) {
        KswordARKDriverDispatchFillResponse(
            Response,
            Request->action,
            (UCHAR)Request->majorFunction,
            STATUS_NOT_FOUND,
            Request->desiredDispatchAddress,
            NULL,
            NULL,
            Request->targetModuleBase,
            NULL,
            FALSE);
        ExReleaseFastMutex(&g_KswordArkDriverDispatchState.Lock);
        return STATUS_NOT_FOUND;
    }
    if (!KswordARKDriverDispatchRecordMatchesRequest(record, Request)) {
        KswordARKDriverDispatchFillResponse(
            Response,
            Request->action,
            (UCHAR)Request->majorFunction,
            STATUS_OBJECT_TYPE_MISMATCH,
            Request->desiredDispatchAddress,
            record,
            NULL,
            0ULL,
            NULL,
            FALSE);
        ExReleaseFastMutex(&g_KswordArkDriverDispatchState.Lock);
        return STATUS_OBJECT_TYPE_MISMATCH;
    }
    KswordARKDriverDispatchRefreshRecordLocked(record);
    if ((Request->flags &
        KSWORD_ARK_DRIVER_DISPATCH_FLAG_EXPECTED_GENERATION_PRESENT) != 0UL &&
        Request->expectedGeneration != record->Generation) {
        KswordARKDriverDispatchFillResponse(
            Response,
            Request->action,
            (UCHAR)Request->majorFunction,
            STATUS_RETRY,
            Request->desiredDispatchAddress,
            record,
            NULL,
            0ULL,
            NULL,
            FALSE);
        ExReleaseFastMutex(&g_KswordArkDriverDispatchState.Lock);
        return STATUS_RETRY;
    }

    current = KswordARKDriverDispatchRead(
        record->DriverObject,
        record->MajorFunction);
    if (Request->action == KSWORD_ARK_DRIVER_DISPATCH_ACTION_RESTORE) {
        if (current == record->OriginalDispatch) {
            status = STATUS_SUCCESS;
        }
        else if (record->Owned != FALSE &&
            current == record->AppliedDispatch) {
            previous = KswordARKDriverDispatchCompareExchange(
                record->DriverObject,
                record->MajorFunction,
                record->OriginalDispatch,
                record->AppliedDispatch);
            if (previous == record->AppliedDispatch) {
                current = record->OriginalDispatch;
                changed = TRUE;
                status = STATUS_SUCCESS;
            }
            else {
                KswordARKDriverDispatchRefreshRecordLocked(record);
                status = STATUS_RETRY;
            }
        }
        else {
            record->Owned = FALSE;
            record->Conflict = TRUE;
            (VOID)KswordARKDriverDispatchAdvanceGenerationLocked(record);
            status = STATUS_OBJECT_TYPE_MISMATCH;
        }
    }

    if (Request->action == KSWORD_ARK_DRIVER_DISPATCH_ACTION_ABANDON ||
        (Request->action == KSWORD_ARK_DRIVER_DISPATCH_ACTION_RESTORE &&
        NT_SUCCESS(status) && current == record->OriginalDispatch)) {
        retiredSnapshot = *record;
        releaseObject = record->DriverObject;
        RtlZeroMemory(record, sizeof(*record));
        (VOID)KswordARKDriverDispatchAdvanceGenerationLocked(NULL);
        KswordARKDriverDispatchFillRetiredResponse(
            Response,
            Request->action,
            (UCHAR)Request->majorFunction,
            STATUS_SUCCESS,
            Request->desiredDispatchAddress,
            &retiredSnapshot,
            current,
            changed);
        ExReleaseFastMutex(&g_KswordArkDriverDispatchState.Lock);
        ObDereferenceObject(releaseObject);
        return STATUS_SUCCESS;
    }

    KswordARKDriverDispatchFillResponse(
        Response,
        Request->action,
        (UCHAR)Request->majorFunction,
        status,
        Request->desiredDispatchAddress,
        record,
        NULL,
        0ULL,
        NULL,
        changed);
    ExReleaseFastMutex(&g_KswordArkDriverDispatchState.Lock);
    return status;
}

NTSTATUS
KswordARKDriverDispatchInitialize(
    _In_ PDRIVER_OBJECT DriverObject
    )
{
    if (DriverObject == NULL || KeGetCurrentIrql() != PASSIVE_LEVEL) {
        return STATUS_INVALID_PARAMETER;
    }
    if (InterlockedCompareExchange(
        &g_KswordArkDriverDispatchState.Initialized,
        0L,
        0L) != 0L) {
        return g_KswordArkDriverDispatchState.SelfDriverObject == DriverObject
            ? STATUS_SUCCESS
            : STATUS_INVALID_DEVICE_STATE;
    }
    RtlZeroMemory(
        &g_KswordArkDriverDispatchState,
        sizeof(g_KswordArkDriverDispatchState));
    ExInitializeFastMutex(&g_KswordArkDriverDispatchState.Lock);
    g_KswordArkDriverDispatchState.Generation = 1UL;
    g_KswordArkDriverDispatchState.SelfDriverObject = DriverObject;
    InterlockedExchange(&g_KswordArkDriverDispatchState.Initialized, 1L);
    return STATUS_SUCCESS;
}

VOID
KswordARKDriverDispatchUninitialize(
    VOID
    )
{
    PDRIVER_OBJECT releaseObjects[KSW_DRIVER_DISPATCH_RECORD_LIMIT] = { 0 };
    ULONG releaseCount = 0UL;
    ULONG index = 0UL;

    if (InterlockedCompareExchange(
        &g_KswordArkDriverDispatchState.Initialized,
        0L,
        0L) == 0L) {
        return;
    }
    ExAcquireFastMutex(&g_KswordArkDriverDispatchState.Lock);
    g_KswordArkDriverDispatchState.ShuttingDown = TRUE;
    for (index = 0UL; index < KSW_DRIVER_DISPATCH_RECORD_LIMIT; ++index) {
        KSW_DRIVER_DISPATCH_RECORD* record =
            &g_KswordArkDriverDispatchState.Records[index];
        if (record->InUse == FALSE || record->DriverObject == NULL) {
            continue;
        }
        KswordARKDriverDispatchRefreshRecordLocked(record);
        if (record->Owned != FALSE &&
            KswordARKDriverDispatchRead(
                record->DriverObject,
                record->MajorFunction) == record->AppliedDispatch) {
            (VOID)KswordARKDriverDispatchCompareExchange(
                record->DriverObject,
                record->MajorFunction,
                record->OriginalDispatch,
                record->AppliedDispatch);
        }
        releaseObjects[releaseCount++] = record->DriverObject;
        RtlZeroMemory(record, sizeof(*record));
    }
    ExReleaseFastMutex(&g_KswordArkDriverDispatchState.Lock);
    InterlockedExchange(&g_KswordArkDriverDispatchState.Initialized, 0L);
    for (index = 0UL; index < releaseCount; ++index) {
        ObDereferenceObject(releaseObjects[index]);
    }
    RtlZeroMemory(
        &g_KswordArkDriverDispatchState,
        sizeof(g_KswordArkDriverDispatchState));
}

NTSTATUS
KswordARKDriverControlDispatch(
    _In_ const KSWORD_ARK_DRIVER_DISPATCH_REQUEST* Request,
    _Out_ KSWORD_ARK_DRIVER_DISPATCH_RESPONSE* Response
    )
{
    NTSTATUS status = STATUS_SUCCESS;

    if (Request == NULL || Response == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    RtlZeroMemory(Response, sizeof(*Response));
    Response->version = KSWORD_ARK_DRIVER_DISPATCH_PROTOCOL_VERSION;
    Response->action = Request->action;
    Response->majorFunction = Request->majorFunction;
    Response->requestedDispatchAddress = Request->desiredDispatchAddress;
    Response->targetModuleBase = Request->targetModuleBase;
    Response->driverObjectAddress = Request->expectedDriverObjectAddress;
    Response->responseFlags =
        KSWORD_ARK_DRIVER_DISPATCH_RESPONSE_FLAG_WARN_ONLY_POLICY;

    if (KeGetCurrentIrql() != PASSIVE_LEVEL ||
        InterlockedCompareExchange(
            &g_KswordArkDriverDispatchState.Initialized,
            0L,
            0L) == 0L) {
        status = STATUS_DEVICE_NOT_READY;
    }
    else if (Request->version != KSWORD_ARK_DRIVER_DISPATCH_PROTOCOL_VERSION ||
        Request->majorFunction > IRP_MJ_MAXIMUM_FUNCTION ||
        (Request->flags &
            KSWORD_ARK_DRIVER_DISPATCH_FLAG_TARGET_MODULE_BASE_PRESENT) == 0UL ||
        Request->targetModuleBase == 0ULL ||
        !KswordARKDriverDispatchHasTerminatedName(Request->driverName)) {
        status = STATUS_INVALID_PARAMETER;
    }
    else if (Request->action > KSWORD_ARK_DRIVER_DISPATCH_ACTION_ABANDON) {
        status = STATUS_INVALID_PARAMETER;
    }
    else if (Request->action != KSWORD_ARK_DRIVER_DISPATCH_ACTION_QUERY &&
        (((Request->flags &
            KSWORD_ARK_DRIVER_DISPATCH_FLAG_EXPECTED_DRIVER_OBJECT_PRESENT) == 0UL) ||
         ((Request->flags &
            KSWORD_ARK_DRIVER_DISPATCH_FLAG_EXPECTED_GENERATION_PRESENT) == 0UL) ||
         Request->expectedDriverObjectAddress == 0ULL ||
         Request->expectedGeneration == 0UL ||
         Request->driverName[0] == L'\0')) {
        status = STATUS_INVALID_PARAMETER;
    }
    else if (Request->action == KSWORD_ARK_DRIVER_DISPATCH_ACTION_APPLY &&
        (((Request->flags &
            KSWORD_ARK_DRIVER_DISPATCH_FLAG_EXPECTED_CURRENT_PRESENT) == 0UL) ||
         ((Request->flags &
            KSWORD_ARK_DRIVER_DISPATCH_FLAG_UI_CONFIRMED) == 0UL) ||
         Request->confirmationToken !=
            KSWORD_ARK_DRIVER_DISPATCH_CONFIRMATION_TOKEN)) {
        status = STATUS_INVALID_PARAMETER;
    }
    else if (Request->action == KSWORD_ARK_DRIVER_DISPATCH_ACTION_ABANDON &&
        (((Request->flags &
            KSWORD_ARK_DRIVER_DISPATCH_FLAG_UI_CONFIRMED) == 0UL) ||
         Request->confirmationToken !=
            KSWORD_ARK_DRIVER_DISPATCH_CONFIRMATION_TOKEN)) {
        status = STATUS_INVALID_PARAMETER;
    }
    else {
        switch (Request->action) {
        case KSWORD_ARK_DRIVER_DISPATCH_ACTION_QUERY:
            return KswordARKDriverDispatchQuery(Request, Response);
        case KSWORD_ARK_DRIVER_DISPATCH_ACTION_APPLY:
            return KswordARKDriverDispatchApply(Request, Response);
        case KSWORD_ARK_DRIVER_DISPATCH_ACTION_RESTORE:
        case KSWORD_ARK_DRIVER_DISPATCH_ACTION_ABANDON:
            return KswordARKDriverDispatchRestoreOrAbandon(Request, Response);
        default:
            status = STATUS_INVALID_PARAMETER;
            break;
        }
    }

    Response->lastStatus = status;
    return status;
}

BOOLEAN
KswordARKDriverDispatchHasBlockingRecord(
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
        &g_KswordArkDriverDispatchState.Initialized,
        0L,
        0L) == 0L) {
        return FALSE;
    }
    if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
        return TRUE;
    }

    ExAcquireFastMutex(&g_KswordArkDriverDispatchState.Lock);
    for (index = 0UL; index < KSW_DRIVER_DISPATCH_RECORD_LIMIT; ++index) {
        const KSW_DRIVER_DISPATCH_RECORD* record =
            &g_KswordArkDriverDispatchState.Records[index];
        if (record->InUse != FALSE &&
            (record->DriverObject == TargetDriverObject ||
             (OriginalRequestModuleBase != 0ULL &&
              record->TargetModuleBase == OriginalRequestModuleBase))) {
            blocked = TRUE;
            break;
        }
    }
    ExReleaseFastMutex(&g_KswordArkDriverDispatchState.Lock);
    return blocked;
}
