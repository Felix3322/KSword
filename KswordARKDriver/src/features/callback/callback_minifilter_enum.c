/*++

Module Name:

    callback_minifilter_enum.c

Abstract:

    Enumerates Filter Manager filters and their registered Pre/Post operation
    callbacks without modifying Filter Manager state.

Environment:

    Kernel-mode Driver Framework / Filter Manager

--*/

#include <fltKernel.h>
#include "callback_internal.h"
#include "../dyndata/dyndata_v4_internal.h"

#define KSWORD_ARK_MINIFILTER_ENUM_TAG 'mCbK'
#define KSWORD_ARK_MINIFILTER_MAX_OPERATION_ROWS 64UL
#define KSWORD_ARK_MINIFILTER_FALLBACK_SCAN_START 0x80UL
#define KSWORD_ARK_MINIFILTER_FALLBACK_SCAN_END 0x500UL
#define KSWORD_ARK_MINIFILTER_MAX_PDB_STRUCT_OFFSET 0x1000UL
#define KSWORD_ARK_MINIFILTER_KNOWN_OPERATION_FLAGS 0x0000000FUL

typedef struct _KSWORD_ARK_MINIFILTER_OPERATION_LAYOUT
{
    PFLT_OPERATION_REGISTRATION Operations;
    ULONG OperationsOffset;
    ULONG OperationCount;
    BOOLEAN UsedPdbProfile;
} KSWORD_ARK_MINIFILTER_OPERATION_LAYOUT;

static BOOLEAN
KswordArkMinifilterIsKnownMajorFunction(
    _In_ UCHAR MajorFunction
    )
/*++

Routine Description:

    Validate one FLT_OPERATION_REGISTRATION MajorFunction value.

Return Value:

    TRUE for documented IRP or Filter Manager operation codes.

--*/
{
    if (MajorFunction <= IRP_MJ_MAXIMUM_FUNCTION) {
        return TRUE;
    }

    switch (MajorFunction) {
    case IRP_MJ_ACQUIRE_FOR_SECTION_SYNCHRONIZATION:
    case IRP_MJ_RELEASE_FOR_SECTION_SYNCHRONIZATION:
    case IRP_MJ_ACQUIRE_FOR_MOD_WRITE:
    case IRP_MJ_RELEASE_FOR_MOD_WRITE:
    case IRP_MJ_ACQUIRE_FOR_CC_FLUSH:
    case IRP_MJ_RELEASE_FOR_CC_FLUSH:
    case IRP_MJ_QUERY_OPEN:
    case IRP_MJ_FAST_IO_CHECK_IF_POSSIBLE:
    case IRP_MJ_NETWORK_QUERY_OPEN:
    case IRP_MJ_MDL_READ:
    case IRP_MJ_MDL_READ_COMPLETE:
    case IRP_MJ_PREPARE_MDL_WRITE:
    case IRP_MJ_MDL_WRITE_COMPLETE:
    case IRP_MJ_VOLUME_MOUNT:
    case IRP_MJ_VOLUME_DISMOUNT:
        return TRUE;
    default:
        return FALSE;
    }
}

static PCWSTR
KswordArkMinifilterMajorFunctionName(
    _In_ UCHAR MajorFunction
    )
/*++

Routine Description:

    Map a documented minifilter operation code to its symbolic name.

Return Value:

    Stable symbolic text; unknown values use IRP_MJ_UNKNOWN.

--*/
{
    switch (MajorFunction) {
    case IRP_MJ_CREATE: return L"IRP_MJ_CREATE";
    case IRP_MJ_CREATE_NAMED_PIPE: return L"IRP_MJ_CREATE_NAMED_PIPE";
    case IRP_MJ_CLOSE: return L"IRP_MJ_CLOSE";
    case IRP_MJ_READ: return L"IRP_MJ_READ";
    case IRP_MJ_WRITE: return L"IRP_MJ_WRITE";
    case IRP_MJ_QUERY_INFORMATION: return L"IRP_MJ_QUERY_INFORMATION";
    case IRP_MJ_SET_INFORMATION: return L"IRP_MJ_SET_INFORMATION";
    case IRP_MJ_QUERY_EA: return L"IRP_MJ_QUERY_EA";
    case IRP_MJ_SET_EA: return L"IRP_MJ_SET_EA";
    case IRP_MJ_FLUSH_BUFFERS: return L"IRP_MJ_FLUSH_BUFFERS";
    case IRP_MJ_QUERY_VOLUME_INFORMATION: return L"IRP_MJ_QUERY_VOLUME_INFORMATION";
    case IRP_MJ_SET_VOLUME_INFORMATION: return L"IRP_MJ_SET_VOLUME_INFORMATION";
    case IRP_MJ_DIRECTORY_CONTROL: return L"IRP_MJ_DIRECTORY_CONTROL";
    case IRP_MJ_FILE_SYSTEM_CONTROL: return L"IRP_MJ_FILE_SYSTEM_CONTROL";
    case IRP_MJ_DEVICE_CONTROL: return L"IRP_MJ_DEVICE_CONTROL";
    case IRP_MJ_INTERNAL_DEVICE_CONTROL: return L"IRP_MJ_INTERNAL_DEVICE_CONTROL";
    case IRP_MJ_SHUTDOWN: return L"IRP_MJ_SHUTDOWN";
    case IRP_MJ_LOCK_CONTROL: return L"IRP_MJ_LOCK_CONTROL";
    case IRP_MJ_CLEANUP: return L"IRP_MJ_CLEANUP";
    case IRP_MJ_CREATE_MAILSLOT: return L"IRP_MJ_CREATE_MAILSLOT";
    case IRP_MJ_QUERY_SECURITY: return L"IRP_MJ_QUERY_SECURITY";
    case IRP_MJ_SET_SECURITY: return L"IRP_MJ_SET_SECURITY";
    case IRP_MJ_POWER: return L"IRP_MJ_POWER";
    case IRP_MJ_SYSTEM_CONTROL: return L"IRP_MJ_SYSTEM_CONTROL";
    case IRP_MJ_DEVICE_CHANGE: return L"IRP_MJ_DEVICE_CHANGE";
    case IRP_MJ_QUERY_QUOTA: return L"IRP_MJ_QUERY_QUOTA";
    case IRP_MJ_SET_QUOTA: return L"IRP_MJ_SET_QUOTA";
    case IRP_MJ_PNP: return L"IRP_MJ_PNP";
    case IRP_MJ_ACQUIRE_FOR_SECTION_SYNCHRONIZATION: return L"IRP_MJ_ACQUIRE_FOR_SECTION_SYNCHRONIZATION";
    case IRP_MJ_RELEASE_FOR_SECTION_SYNCHRONIZATION: return L"IRP_MJ_RELEASE_FOR_SECTION_SYNCHRONIZATION";
    case IRP_MJ_ACQUIRE_FOR_MOD_WRITE: return L"IRP_MJ_ACQUIRE_FOR_MOD_WRITE";
    case IRP_MJ_RELEASE_FOR_MOD_WRITE: return L"IRP_MJ_RELEASE_FOR_MOD_WRITE";
    case IRP_MJ_ACQUIRE_FOR_CC_FLUSH: return L"IRP_MJ_ACQUIRE_FOR_CC_FLUSH";
    case IRP_MJ_RELEASE_FOR_CC_FLUSH: return L"IRP_MJ_RELEASE_FOR_CC_FLUSH";
    case IRP_MJ_QUERY_OPEN: return L"IRP_MJ_QUERY_OPEN";
    case IRP_MJ_FAST_IO_CHECK_IF_POSSIBLE: return L"IRP_MJ_FAST_IO_CHECK_IF_POSSIBLE";
    case IRP_MJ_NETWORK_QUERY_OPEN: return L"IRP_MJ_NETWORK_QUERY_OPEN";
    case IRP_MJ_MDL_READ: return L"IRP_MJ_MDL_READ";
    case IRP_MJ_MDL_READ_COMPLETE: return L"IRP_MJ_MDL_READ_COMPLETE";
    case IRP_MJ_PREPARE_MDL_WRITE: return L"IRP_MJ_PREPARE_MDL_WRITE";
    case IRP_MJ_MDL_WRITE_COMPLETE: return L"IRP_MJ_MDL_WRITE_COMPLETE";
    case IRP_MJ_VOLUME_MOUNT: return L"IRP_MJ_VOLUME_MOUNT";
    case IRP_MJ_VOLUME_DISMOUNT: return L"IRP_MJ_VOLUME_DISMOUNT";
    default: return L"IRP_MJ_UNKNOWN";
    }
}

static BOOLEAN
KswordArkMinifilterValidateOperations(
    _Inout_ KSWORD_ARK_CALLBACK_MODULE_CACHE* ModuleCache,
    _In_ PFLT_OPERATION_REGISTRATION Operations,
    _Out_ ULONG* OperationCountOut
    )
/*++

Routine Description:

    Validate a candidate FLT_OPERATION_REGISTRATION array. 中文说明：候选必须在
    64 项内出现 IRP_MJ_OPERATION_END，所有回调都落入已加载模块，且保留字段、
    标志与 MajorFunction 均符合公开结构契约。

Return Value:

    TRUE only for a complete and strongly validated callback array.

--*/
{
    ULONG index = 0UL;
    ULONG callbackCount = 0UL;
    ULONG64 seenMajorMask = 0ULL;

    if (ModuleCache == NULL || Operations == NULL || OperationCountOut == NULL) {
        return FALSE;
    }
    *OperationCountOut = 0UL;

    for (index = 0UL; index < KSWORD_ARK_MINIFILTER_MAX_OPERATION_ROWS; ++index) {
        FLT_OPERATION_REGISTRATION operation;
        ULONG64 operationAddress = (ULONG64)(ULONG_PTR)&Operations[index];

        RtlZeroMemory(&operation, sizeof(operation));
        if (!KswordArkCallbackEnumReadMemory(
                (const VOID*)(ULONG_PTR)operationAddress,
                &operation,
                sizeof(operation))) {
            return FALSE;
        }

        if (operation.MajorFunction == IRP_MJ_OPERATION_END) {
            *OperationCountOut = index;
            return index != 0UL && callbackCount != 0UL;
        }
        if (!KswordArkMinifilterIsKnownMajorFunction(operation.MajorFunction) ||
            (operation.Flags & ~KSWORD_ARK_MINIFILTER_KNOWN_OPERATION_FLAGS) != 0UL ||
            operation.Reserved1 != NULL ||
            (operation.PreOperation == NULL && operation.PostOperation == NULL)) {
            return FALSE;
        }

        if (operation.MajorFunction < 64U) {
            const ULONG64 majorBit = 1ULL << operation.MajorFunction;
            if ((seenMajorMask & majorBit) != 0ULL) {
                return FALSE;
            }
            seenMajorMask |= majorBit;
        }

        if (operation.PreOperation != NULL) {
            if (!KswordArkCallbackEnumIsKernelModuleAddress(
                    ModuleCache,
                    (ULONG64)(ULONG_PTR)operation.PreOperation)) {
                return FALSE;
            }
            callbackCount += 1UL;
        }
        if (operation.PostOperation != NULL) {
            if (!KswordArkCallbackEnumIsKernelModuleAddress(
                    ModuleCache,
                    (ULONG64)(ULONG_PTR)operation.PostOperation)) {
                return FALSE;
            }
            callbackCount += 1UL;
        }
    }

    return FALSE;
}

static BOOLEAN
KswordArkMinifilterReadOperationsPointer(
    _In_ PFLT_FILTER FilterObject,
    _In_ ULONG OperationsOffset,
    _Out_ PFLT_OPERATION_REGISTRATION* OperationsOut
    )
/*++

Routine Description:

    Read the opaque _FLT_FILTER.Operations pointer at one bounded offset.

Return Value:

    TRUE when a non-NULL pointer is read without fault.

--*/
{
    PFLT_OPERATION_REGISTRATION operations = NULL;
    ULONG64 fieldAddress = 0ULL;

    if (FilterObject == NULL || OperationsOut == NULL ||
        OperationsOffset > KSWORD_ARK_MINIFILTER_MAX_PDB_STRUCT_OFFSET) {
        return FALSE;
    }
    *OperationsOut = NULL;
    fieldAddress = (ULONG64)(ULONG_PTR)FilterObject + (ULONG64)OperationsOffset;
    if (!KswordArkCallbackEnumReadMemory(
            (const VOID*)(ULONG_PTR)fieldAddress,
            &operations,
            sizeof(operations)) ||
        operations == NULL) {
        return FALSE;
    }

    *OperationsOut = operations;
    return TRUE;
}

static BOOLEAN
KswordArkMinifilterLocateOperations(
    _Inout_ KSWORD_ARK_CALLBACK_MODULE_CACHE* ModuleCache,
    _In_ PFLT_FILTER FilterObject,
    _Out_ KSWORD_ARK_MINIFILTER_OPERATION_LAYOUT* LayoutOut
    )
/*++

Routine Description:

    Locate _FLT_FILTER.Operations by exact fltMgr PDB layout first, then by a
    bounded strongly validated fallback scan.

Return Value:

    TRUE when a complete operation array is found.

--*/
{
    KSW_DYN_V4_FLTMGR_MINIFILTER_LAYOUT pdbLayout;
    ULONG candidateOffset = 0UL;

    if (ModuleCache == NULL || FilterObject == NULL || LayoutOut == NULL) {
        return FALSE;
    }
    RtlZeroMemory(LayoutOut, sizeof(*LayoutOut));
    RtlZeroMemory(&pdbLayout, sizeof(pdbLayout));

    if (NT_SUCCESS(KswordARKDynDataV4SnapshotFltMgrMinifilterLayout(&pdbLayout))) {
        PFLT_OPERATION_REGISTRATION operations = NULL;
        ULONG operationCount = 0UL;
        if (KswordArkMinifilterReadOperationsPointer(
                FilterObject,
                pdbLayout.FltFilterOperations,
                &operations) &&
            KswordArkMinifilterValidateOperations(ModuleCache, operations, &operationCount)) {
            LayoutOut->Operations = operations;
            LayoutOut->OperationsOffset = pdbLayout.FltFilterOperations;
            LayoutOut->OperationCount = operationCount;
            LayoutOut->UsedPdbProfile = TRUE;
            return TRUE;
        }
    }

    for (candidateOffset = KSWORD_ARK_MINIFILTER_FALLBACK_SCAN_START;
         candidateOffset <= KSWORD_ARK_MINIFILTER_FALLBACK_SCAN_END;
         candidateOffset += sizeof(PVOID)) {
        PFLT_OPERATION_REGISTRATION operations = NULL;
        ULONG operationCount = 0UL;

        if (!KswordArkMinifilterReadOperationsPointer(FilterObject, candidateOffset, &operations)) {
            continue;
        }
        if (!KswordArkMinifilterValidateOperations(ModuleCache, operations, &operationCount)) {
            continue;
        }

        LayoutOut->Operations = operations;
        LayoutOut->OperationsOffset = candidateOffset;
        LayoutOut->OperationCount = operationCount;
        LayoutOut->UsedPdbProfile = FALSE;
        return TRUE;
    }

    return FALSE;
}

static NTSTATUS
KswordArkMinifilterQueryFilterInfo(
    _In_ PFLT_FILTER FilterObject,
    _Outptr_result_maybenull_ FILTER_AGGREGATE_STANDARD_INFORMATION** FilterInfoOut
    )
/*++

Routine Description:

    Query public aggregate information for one referenced Filter object.

Return Value:

    STATUS_SUCCESS with an allocated buffer, or the query/allocation status.

--*/
{
    NTSTATUS status = STATUS_SUCCESS;
    ULONG bytesReturned = 0UL;
    FILTER_AGGREGATE_STANDARD_INFORMATION* filterInfo = NULL;

    if (FilterObject == NULL || FilterInfoOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *FilterInfoOut = NULL;

    status = FltGetFilterInformation(
        FilterObject,
        FilterAggregateStandardInformation,
        NULL,
        0UL,
        &bytesReturned);
    if (status != STATUS_BUFFER_TOO_SMALL ||
        bytesReturned < sizeof(FILTER_AGGREGATE_STANDARD_INFORMATION)) {
        return status;
    }

    filterInfo = (FILTER_AGGREGATE_STANDARD_INFORMATION*)KswordArkAllocateNonPaged(
        bytesReturned,
        KSWORD_ARK_MINIFILTER_ENUM_TAG);
    if (filterInfo == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlZeroMemory(filterInfo, bytesReturned);

    status = FltGetFilterInformation(
        FilterObject,
        FilterAggregateStandardInformation,
        filterInfo,
        bytesReturned,
        &bytesReturned);
    if (!NT_SUCCESS(status)) {
        ExFreePool(filterInfo);
        return status;
    }

    *FilterInfoOut = filterInfo;
    return STATUS_SUCCESS;
}

static VOID
KswordArkMinifilterCopyPublicText(
    _In_ const FILTER_AGGREGATE_STANDARD_INFORMATION* FilterInfo,
    _Out_writes_(NameChars) PWCHAR Name,
    _In_ ULONG NameChars,
    _Out_writes_(AltitudeChars) PWCHAR Altitude,
    _In_ ULONG AltitudeChars
    )
/*++

Routine Description:

    Copy the public filter name and altitude into bounded local buffers.

--*/
{
    UNICODE_STRING source;

    if (Name == NULL || NameChars == 0UL || Altitude == NULL || AltitudeChars == 0UL) {
        return;
    }
    Name[0] = L'\0';
    Altitude[0] = L'\0';
    if (FilterInfo == NULL || (FilterInfo->Flags & FLTFL_ASI_IS_MINIFILTER) == 0UL) {
        return;
    }

    RtlZeroMemory(&source, sizeof(source));
    if (FilterInfo->Type.MiniFilter.FilterNameBufferOffset != 0U &&
        FilterInfo->Type.MiniFilter.FilterNameLength != 0U) {
        source.Buffer = (PWCHAR)((PUCHAR)FilterInfo +
            FilterInfo->Type.MiniFilter.FilterNameBufferOffset);
        source.Length = FilterInfo->Type.MiniFilter.FilterNameLength;
        source.MaximumLength = source.Length;
        KswordArkCallbackEnumCopyUnicode(Name, NameChars, &source);
    }

    RtlZeroMemory(&source, sizeof(source));
    if (FilterInfo->Type.MiniFilter.FilterAltitudeBufferOffset != 0U &&
        FilterInfo->Type.MiniFilter.FilterAltitudeLength != 0U) {
        source.Buffer = (PWCHAR)((PUCHAR)FilterInfo +
            FilterInfo->Type.MiniFilter.FilterAltitudeBufferOffset);
        source.Length = FilterInfo->Type.MiniFilter.FilterAltitudeLength;
        source.MaximumLength = source.Length;
        KswordArkCallbackEnumCopyUnicode(Altitude, AltitudeChars, &source);
    }
}

static KSWORD_ARK_CALLBACK_ENUM_ENTRY*
KswordArkMinifilterAddParentRow(
    _Inout_ KSWORD_ARK_CALLBACK_ENUM_BUILDER* Builder,
    _In_ PFLT_FILTER FilterObject,
    _In_opt_ const FILTER_AGGREGATE_STANDARD_INFORMATION* FilterInfo,
    _In_ NTSTATUS FilterInfoStatus,
    _In_opt_ const KSWORD_ARK_MINIFILTER_OPERATION_LAYOUT* Layout,
    _In_z_ PCWSTR FilterName,
    _In_z_ PCWSTR Altitude
    )
/*++

Routine Description:

    Add the tree parent row. 中文说明：FilterObject 只写入注册/标识字段，
    callbackAddress 保持为 0，避免 UI 再把对象指针误报为 Pre/Post 函数。

Return Value:

    The reserved response row, or NULL when the output is full.

--*/
{
    KSWORD_ARK_CALLBACK_ENUM_ENTRY* entry = KswordArkCallbackEnumReserveEntry(Builder);

    if (entry == NULL) {
        return NULL;
    }

    entry->callbackClass = KSWORD_ARK_CALLBACK_ENUM_CLASS_MINIFILTER;
    entry->source = KSWORD_ARK_CALLBACK_ENUM_SOURCE_FLTMGR_ENUMERATION;
    entry->status = NT_SUCCESS(FilterInfoStatus)
        ? KSWORD_ARK_CALLBACK_ENUM_STATUS_OK
        : KSWORD_ARK_CALLBACK_ENUM_STATUS_QUERY_FAILED;
    entry->registrationAddress = (ULONG64)(ULONG_PTR)FilterObject;
    entry->fieldFlags = KSWORD_ARK_CALLBACK_ENUM_FIELD_HANDLE |
        KSWORD_ARK_CALLBACK_ENUM_FIELD_IDENTIFIER |
        KSWORD_ARK_CALLBACK_ENUM_FIELD_REGISTRATION_ADDRESS |
        KSWORD_ARK_CALLBACK_ENUM_FIELD_STORAGE_ADDRESS |
        KSWORD_ARK_CALLBACK_ENUM_FIELD_NAME |
        KSWORD_ARK_CALLBACK_ENUM_FIELD_REMOVABLE_CANDIDATE |
        KSWORD_ARK_CALLBACK_ENUM_FIELD_VERIFIED_REMOVE;
    entry->trustFlags = KSWORD_ARK_CALLBACK_TRUST_PUBLIC_API |
        KSWORD_ARK_CALLBACK_TRUST_STORAGE_VALIDATED;
    entry->removeBehavior = KSWORD_ARK_CALLBACK_REMOVE_BEHAVIOR_PUBLIC_API |
        KSWORD_ARK_CALLBACK_REMOVE_BEHAVIOR_REQUIRE_REVALIDATION;
    entry->lastStatus = FilterInfoStatus;
    KswordArkCallbackEnumCopyWide(entry->name, RTL_NUMBER_OF(entry->name), FilterName);

    if (Altitude[0] != L'\0') {
        entry->fieldFlags |= KSWORD_ARK_CALLBACK_ENUM_FIELD_ALTITUDE;
        KswordArkCallbackEnumCopyWide(entry->altitude, RTL_NUMBER_OF(entry->altitude), Altitude);
    }
    if (Layout != NULL && Layout->Operations != NULL) {
        entry->rawStorageValue = (ULONG64)(ULONG_PTR)Layout->Operations;
        entry->fieldFlags |= KSWORD_ARK_CALLBACK_ENUM_FIELD_RAW_STORAGE_VALUE;
    }

    if (NT_SUCCESS(FilterInfoStatus) && FilterInfo != NULL &&
        (FilterInfo->Flags & FLTFL_ASI_IS_MINIFILTER) != 0UL) {
        (VOID)RtlStringCbPrintfW(
            entry->detail,
            sizeof(entry->detail),
            L"Filter parent；FrameID=%lu，实例数=%lu，FilterObject=0x%p，"
            L"Operations=%p，布局来源=%ws，Operations偏移=0x%lX。",
            (unsigned long)FilterInfo->Type.MiniFilter.FrameID,
            (unsigned long)FilterInfo->Type.MiniFilter.NumberOfInstances,
            FilterObject,
            (Layout != NULL) ? Layout->Operations : NULL,
            (Layout == NULL) ? L"unavailable" :
                (Layout->UsedPdbProfile ? L"fltMgr PDB profile" : L"validated fallback scan"),
            (Layout != NULL) ? Layout->OperationsOffset : 0UL);
    }
    else {
        (VOID)RtlStringCbPrintfW(
            entry->detail,
            sizeof(entry->detail),
            L"FltGetFilterInformation 失败，FilterObject=0x%p，NTSTATUS=0x%08lX。",
            FilterObject,
            (unsigned long)FilterInfoStatus);
    }
    return entry;
}

static VOID
KswordArkMinifilterAddCallbackRow(
    _Inout_ KSWORD_ARK_CALLBACK_ENUM_BUILDER* Builder,
    _Inout_ KSWORD_ARK_CALLBACK_MODULE_CACHE* ModuleCache,
    _In_ PFLT_FILTER FilterObject,
    _In_ const KSWORD_ARK_MINIFILTER_OPERATION_LAYOUT* Layout,
    _In_ const FLT_OPERATION_REGISTRATION* Operation,
    _In_ ULONG OperationIndex,
    _In_ BOOLEAN IsPreOperation,
    _In_z_ PCWSTR FilterName,
    _In_z_ PCWSTR Altitude
    )
/*++

Routine Description:

    Add one real PreOperation or PostOperation callback row.

--*/
{
    KSWORD_ARK_CALLBACK_ENUM_ENTRY* entry = NULL;
    ULONG64 callbackAddress = 0ULL;
    PCWSTR stageName = IsPreOperation ? L"PreOperation" : L"PostOperation";
    PCWSTR majorName = KswordArkMinifilterMajorFunctionName(Operation->MajorFunction);

    callbackAddress = IsPreOperation
        ? (ULONG64)(ULONG_PTR)Operation->PreOperation
        : (ULONG64)(ULONG_PTR)Operation->PostOperation;
    if (callbackAddress == 0ULL) {
        return;
    }

    entry = KswordArkCallbackEnumReserveEntry(Builder);
    if (entry == NULL) {
        return;
    }

    entry->callbackClass = KSWORD_ARK_CALLBACK_ENUM_CLASS_MINIFILTER;
    entry->source = Layout->UsedPdbProfile
        ? KSWORD_ARK_CALLBACK_ENUM_SOURCE_PDB_PROFILE
        : KSWORD_ARK_CALLBACK_ENUM_SOURCE_PRIVATE_PATTERN_SCAN;
    entry->status = KSWORD_ARK_CALLBACK_ENUM_STATUS_OK;
    entry->callbackAddress = callbackAddress;
    entry->contextAddress = (ULONG64)(ULONG_PTR)FilterObject;
    entry->registrationAddress = (ULONG64)(ULONG_PTR)&Layout->Operations[OperationIndex];
    entry->rawStorageValue = (ULONG64)(ULONG_PTR)Layout->Operations;
    entry->fieldFlags = KSWORD_ARK_CALLBACK_ENUM_FIELD_CALLBACK_ADDRESS |
        KSWORD_ARK_CALLBACK_ENUM_FIELD_CONTEXT_ADDRESS |
        KSWORD_ARK_CALLBACK_ENUM_FIELD_REGISTRATION_ADDRESS |
        KSWORD_ARK_CALLBACK_ENUM_FIELD_RAW_STORAGE_VALUE |
        KSWORD_ARK_CALLBACK_ENUM_FIELD_STORAGE_ADDRESS |
        KSWORD_ARK_CALLBACK_ENUM_FIELD_NAME;
    entry->trustFlags = KSWORD_ARK_CALLBACK_TRUST_STORAGE_VALIDATED |
        (Layout->UsedPdbProfile
            ? (KSWORD_ARK_CALLBACK_TRUST_PDB_PROFILE | KSWORD_ARK_CALLBACK_TRUST_PROFILE_GATED)
            : KSWORD_ARK_CALLBACK_TRUST_FALLBACK_PATTERN);
    entry->lastStatus = STATUS_SUCCESS;

    if (Operation->MajorFunction < 32U) {
        entry->operationMask = 1UL << Operation->MajorFunction;
        entry->fieldFlags |= KSWORD_ARK_CALLBACK_ENUM_FIELD_OPERATION_MASK;
    }
    if (Layout->UsedPdbProfile) {
        entry->fieldFlags |= KSWORD_ARK_CALLBACK_ENUM_FIELD_PROFILE_GATED |
            KSWORD_ARK_CALLBACK_ENUM_FIELD_TRUSTED;
    }
    if (Altitude[0] != L'\0') {
        entry->fieldFlags |= KSWORD_ARK_CALLBACK_ENUM_FIELD_ALTITUDE;
        KswordArkCallbackEnumCopyWide(entry->altitude, RTL_NUMBER_OF(entry->altitude), Altitude);
    }

    (VOID)RtlStringCbPrintfW(
        entry->name,
        sizeof(entry->name),
        L"%ws / %ws",
        majorName,
        stageName);
    (VOID)RtlStringCbPrintfW(
        entry->detail,
        sizeof(entry->detail),
        L"Filter=%ws；MajorFunction=%ws (0x%02X)；阶段=%ws；Flags=0x%08lX；"
        L"FilterObject=0x%p；Operations=%p；Operations偏移=0x%lX；布局来源=%ws。",
        FilterName,
        majorName,
        (unsigned int)Operation->MajorFunction,
        stageName,
        (unsigned long)Operation->Flags,
        FilterObject,
        Layout->Operations,
        Layout->OperationsOffset,
        Layout->UsedPdbProfile ? L"fltMgr PDB profile" : L"validated fallback scan");
    KswordArkCallbackEnumFinalizeModuleCached(ModuleCache, entry);
}

static VOID
KswordArkMinifilterAddUnavailableChild(
    _Inout_ KSWORD_ARK_CALLBACK_ENUM_BUILDER* Builder,
    _In_ PFLT_FILTER FilterObject,
    _In_z_ PCWSTR Altitude
    )
/*++

Routine Description:

    Add an explicit child row when neither the exact PDB layout nor the
    validated fallback can recover operation callbacks.

--*/
{
    KSWORD_ARK_CALLBACK_ENUM_ENTRY* entry = KswordArkCallbackEnumReserveEntry(Builder);

    if (entry == NULL) {
        return;
    }
    entry->callbackClass = KSWORD_ARK_CALLBACK_ENUM_CLASS_MINIFILTER;
    entry->source = KSWORD_ARK_CALLBACK_ENUM_SOURCE_PRIVATE_UNSUPPORTED;
    entry->status = KSWORD_ARK_CALLBACK_ENUM_STATUS_UNSUPPORTED;
    entry->contextAddress = (ULONG64)(ULONG_PTR)FilterObject;
    entry->fieldFlags = KSWORD_ARK_CALLBACK_ENUM_FIELD_CONTEXT_ADDRESS |
        KSWORD_ARK_CALLBACK_ENUM_FIELD_NAME;
    entry->lastStatus = STATUS_NOT_SUPPORTED;
    KswordArkCallbackEnumCopyWide(
        entry->name,
        RTL_NUMBER_OF(entry->name),
        L"Pre/Post callback layout unavailable");
    if (Altitude[0] != L'\0') {
        entry->fieldFlags |= KSWORD_ARK_CALLBACK_ENUM_FIELD_ALTITUDE;
        KswordArkCallbackEnumCopyWide(entry->altitude, RTL_NUMBER_OF(entry->altitude), Altitude);
    }
    KswordArkCallbackEnumCopyWide(
        entry->detail,
        RTL_NUMBER_OF(entry->detail),
        L"当前 fltMgr.sys 无可用 PDB 偏移，且有界扫描未发现通过完整结构与模块范围校验的 Operations 数组。");
}

static VOID
KswordArkMinifilterAddFilter(
    _Inout_ KSWORD_ARK_CALLBACK_ENUM_BUILDER* Builder,
    _Inout_ KSWORD_ARK_CALLBACK_MODULE_CACHE* ModuleCache,
    _In_ PFLT_FILTER FilterObject
    )
/*++

Routine Description:

    Add one public filter parent and all real Pre/Post callback children.

--*/
{
    FILTER_AGGREGATE_STANDARD_INFORMATION* filterInfo = NULL;
    KSWORD_ARK_MINIFILTER_OPERATION_LAYOUT layout;
    WCHAR filterName[KSWORD_ARK_CALLBACK_ENUM_NAME_CHARS];
    WCHAR altitude[KSWORD_ARK_CALLBACK_ENUM_ALTITUDE_CHARS];
    NTSTATUS filterInfoStatus = STATUS_SUCCESS;
    BOOLEAN layoutFound = FALSE;
    ULONG operationIndex = 0UL;

    RtlZeroMemory(&layout, sizeof(layout));
    RtlZeroMemory(filterName, sizeof(filterName));
    RtlZeroMemory(altitude, sizeof(altitude));

    filterInfoStatus = KswordArkMinifilterQueryFilterInfo(FilterObject, &filterInfo);
    if (NT_SUCCESS(filterInfoStatus) && filterInfo != NULL) {
        KswordArkMinifilterCopyPublicText(
            filterInfo,
            filterName,
            RTL_NUMBER_OF(filterName),
            altitude,
            RTL_NUMBER_OF(altitude));
    }
    if (filterName[0] == L'\0') {
        KswordArkCallbackEnumCopyWide(
            filterName,
            RTL_NUMBER_OF(filterName),
            L"<unnamed minifilter>");
    }

    layoutFound = KswordArkMinifilterLocateOperations(ModuleCache, FilterObject, &layout);
    (VOID)KswordArkMinifilterAddParentRow(
        Builder,
        FilterObject,
        filterInfo,
        filterInfoStatus,
        layoutFound ? &layout : NULL,
        filterName,
        altitude);

    if (!layoutFound) {
        KswordArkMinifilterAddUnavailableChild(Builder, FilterObject, altitude);
    }
    else {
        for (operationIndex = 0UL; operationIndex < layout.OperationCount; ++operationIndex) {
            FLT_OPERATION_REGISTRATION operation;

            RtlZeroMemory(&operation, sizeof(operation));
            if (!KswordArkCallbackEnumReadMemory(
                    &layout.Operations[operationIndex],
                    &operation,
                    sizeof(operation))) {
                Builder->LastStatus = STATUS_PARTIAL_COPY;
                break;
            }
            KswordArkMinifilterAddCallbackRow(
                Builder,
                ModuleCache,
                FilterObject,
                &layout,
                &operation,
                operationIndex,
                TRUE,
                filterName,
                altitude);
            KswordArkMinifilterAddCallbackRow(
                Builder,
                ModuleCache,
                FilterObject,
                &layout,
                &operation,
                operationIndex,
                FALSE,
                filterName,
                altitude);
        }
    }

    if (filterInfo != NULL) {
        ExFreePool(filterInfo);
    }
}

NTSTATUS
KswordArkMinifilterQueryFirstCallbackOwner(
    _In_ PFLT_FILTER FilterObject,
    _Out_writes_(ModulePathChars) PWCHAR ModulePath,
    _In_ ULONG ModulePathChars,
    _Out_opt_ ULONG64* ModuleBaseOut,
    _Out_opt_ ULONG* ModuleSizeOut
    )
/*++

Routine Description:

    Resolve the module that owns the first validated Pre/Post callback for one
    filter. This provides a compact owner hint to the inventory protocol while
    the full callback IOCTL returns every operation row.

Return Value:

    STATUS_SUCCESS when an owner module is resolved; otherwise the layout,
    validation, or module-resolution status.

--*/
{
    KSWORD_ARK_CALLBACK_MODULE_CACHE moduleCache;
    KSWORD_ARK_MINIFILTER_OPERATION_LAYOUT layout;
    ULONG operationIndex = 0UL;
    NTSTATUS status = STATUS_NOT_SUPPORTED;

    if (FilterObject == NULL || ModulePath == NULL || ModulePathChars == 0UL) {
        return STATUS_INVALID_PARAMETER;
    }
    ModulePath[0] = L'\0';
    if (ModuleBaseOut != NULL) {
        *ModuleBaseOut = 0ULL;
    }
    if (ModuleSizeOut != NULL) {
        *ModuleSizeOut = 0UL;
    }
    RtlZeroMemory(&layout, sizeof(layout));
    KswordArkCallbackEnumInitModuleCache(&moduleCache);

    status = KswordArkCallbackEnumEnsureModuleCache(&moduleCache);
    if (!NT_SUCCESS(status) ||
        !KswordArkMinifilterLocateOperations(&moduleCache, FilterObject, &layout)) {
        KswordArkCallbackEnumFreeModuleCache(&moduleCache);
        return NT_SUCCESS(status) ? STATUS_NOT_SUPPORTED : status;
    }

    for (operationIndex = 0UL; operationIndex < layout.OperationCount; ++operationIndex) {
        FLT_OPERATION_REGISTRATION operation;
        ULONG64 callbackAddress = 0ULL;

        RtlZeroMemory(&operation, sizeof(operation));
        if (!KswordArkCallbackEnumReadMemory(
                &layout.Operations[operationIndex],
                &operation,
                sizeof(operation))) {
            status = STATUS_PARTIAL_COPY;
            break;
        }
        callbackAddress = operation.PreOperation != NULL
            ? (ULONG64)(ULONG_PTR)operation.PreOperation
            : (ULONG64)(ULONG_PTR)operation.PostOperation;
        if (callbackAddress == 0ULL) {
            continue;
        }

        status = KswordArkCallbackEnumResolveModuleByAddressCached(
            &moduleCache,
            callbackAddress,
            ModulePath,
            ModulePathChars,
            ModuleBaseOut,
            ModuleSizeOut);
        break;
    }

    KswordArkCallbackEnumFreeModuleCache(&moduleCache);
    return status;
}

VOID
KswordArkCallbackEnumAddMinifilters(
    _Inout_ KSWORD_ARK_CALLBACK_ENUM_BUILDER* Builder
    )
/*++

Routine Description:

    Enumerate all referenced Filter Manager filters, add stable parent rows, and
    recover each registered Pre/Post callback with module ownership.

--*/
{
    KSWORD_ARK_CALLBACK_MODULE_CACHE moduleCache;
    NTSTATUS status = STATUS_SUCCESS;
    ULONG filterCount = 0UL;
    ULONG filterIndex = 0UL;
    PFLT_FILTER* filterList = NULL;
    SIZE_T allocationBytes = 0U;

    if (Builder == NULL) {
        return;
    }
    KswordArkCallbackEnumInitModuleCache(&moduleCache);

    status = FltEnumerateFilters(NULL, 0UL, &filterCount);
    if (status != STATUS_BUFFER_TOO_SMALL && status != STATUS_SUCCESS) {
        Builder->LastStatus = status;
        KswordArkCallbackEnumAddUnsupportedRow(
            Builder,
            KSWORD_ARK_CALLBACK_ENUM_CLASS_MINIFILTER,
            L"Minifilter enumeration failed",
            L"FltEnumerateFilters 长度探测失败，无法枚举 minifilter。");
        return;
    }
    if (filterCount == 0UL) {
        KswordArkCallbackEnumAddUnsupportedRow(
            Builder,
            KSWORD_ARK_CALLBACK_ENUM_CLASS_MINIFILTER,
            L"Minifilter",
            L"FltEnumerateFilters 返回 0 个 minifilter。");
        return;
    }

    allocationBytes = (SIZE_T)filterCount * sizeof(PFLT_FILTER);
    filterList = (PFLT_FILTER*)KswordArkAllocateNonPaged(
        allocationBytes,
        KSWORD_ARK_MINIFILTER_ENUM_TAG);
    if (filterList == NULL) {
        Builder->LastStatus = STATUS_INSUFFICIENT_RESOURCES;
        return;
    }
    RtlZeroMemory(filterList, allocationBytes);

    status = FltEnumerateFilters(filterList, filterCount, &filterCount);
    if (!NT_SUCCESS(status)) {
        Builder->LastStatus = status;
        ExFreePool(filterList);
        KswordArkCallbackEnumAddUnsupportedRow(
            Builder,
            KSWORD_ARK_CALLBACK_ENUM_CLASS_MINIFILTER,
            L"Minifilter enumeration failed",
            L"FltEnumerateFilters 返回错误，当前无法展示 minifilter 列表。");
        return;
    }

    (VOID)KswordArkCallbackEnumEnsureModuleCache(&moduleCache);
    for (filterIndex = 0UL; filterIndex < filterCount; ++filterIndex) {
        if (filterList[filterIndex] != NULL) {
            KswordArkMinifilterAddFilter(Builder, &moduleCache, filterList[filterIndex]);
            FltObjectDereference(filterList[filterIndex]);
        }
    }

    KswordArkCallbackEnumFreeModuleCache(&moduleCache);
    ExFreePool(filterList);
}
