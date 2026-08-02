/*++

Module Name:

    handle_query.c

Abstract:

    Phase-4 direct EPROCESS.ObjectTable handle enumeration.

Environment:

    Kernel-mode Driver Framework

--*/

#include "ark/ark_handle.h"

#include "ark/ark_dyndata.h"
#include "handle_support.h"
#include "../kernel/object_header_fallback.h"
#include "../../platform/pool_compat.h"

#define KSWORD_ARK_HANDLE_ENUM_RESPONSE_HEADER_SIZE \
    (sizeof(KSWORD_ARK_ENUM_PROCESS_HANDLES_RESPONSE) - sizeof(KSWORD_ARK_HANDLE_ENTRY))

#define KSWORD_ARK_OBJECT_GRANTED_ACCESS_MASK 0x01ffffffUL
#define KSWORD_ARK_HANDLE_SNAPSHOT_POOL_TAG    'sHsK'
#define KSWORD_ARK_HANDLE_SNAPSHOT_INFO_CLASS  64UL
#define KSWORD_ARK_HANDLE_SNAPSHOT_MAX_BYTES   (64UL * 1024UL * 1024UL)

#ifndef STATUS_INFO_LENGTH_MISMATCH
#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS)0xC0000004L)
#endif

typedef struct _KSW_SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX
{
    PVOID Object;
    ULONG_PTR UniqueProcessId;
    ULONG_PTR HandleValue;
    ULONG GrantedAccess;
    USHORT CreatorBackTraceIndex;
    USHORT ObjectTypeIndex;
    ULONG HandleAttributes;
    ULONG Reserved;
} KSW_SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX, *PKSW_SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX;

typedef struct _KSW_SYSTEM_HANDLE_INFORMATION_EX
{
    ULONG_PTR NumberOfHandles;
    ULONG_PTR Reserved;
    KSW_SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX Handles[1];
} KSW_SYSTEM_HANDLE_INFORMATION_EX, *PKSW_SYSTEM_HANDLE_INFORMATION_EX;

typedef struct _HANDLE_TABLE HANDLE_TABLE, *PHANDLE_TABLE;

typedef struct _HANDLE_TABLE_ENTRY
{
    union _KSW_HANDLE_TABLE_ENTRY_LOW
    {
        PVOID Object;
        ULONG ObAttributes;
        ULONG_PTR Value;
    } Low;
    union _KSW_HANDLE_TABLE_ENTRY_HIGH
    {
        ACCESS_MASK GrantedAccess;
        LONG NextFreeTableEntry;
    } High;
} HANDLE_TABLE_ENTRY, *PHANDLE_TABLE_ENTRY;

typedef
_Function_class_(EX_ENUM_HANDLE_CALLBACK)
_Must_inspect_result_
BOOLEAN
NTAPI
KSWORD_EX_ENUM_HANDLE_CALLBACK(
    _In_ PHANDLE_TABLE HandleTable,
    _Inout_ PHANDLE_TABLE_ENTRY HandleTableEntry,
    _In_ HANDLE Handle,
    _In_opt_ PVOID Context
    );

typedef KSWORD_EX_ENUM_HANDLE_CALLBACK* PKSWORD_EX_ENUM_HANDLE_CALLBACK;

NTKERNELAPI
BOOLEAN
NTAPI
ExEnumHandleTable(
    _In_ PHANDLE_TABLE HandleTable,
    _In_ PKSWORD_EX_ENUM_HANDLE_CALLBACK EnumHandleProcedure,
    _Inout_ PVOID Context,
    _Out_opt_ PHANDLE Handle
    );

typedef struct _EX_PUSH_LOCK_WAIT_BLOCK* PEX_PUSH_LOCK_WAIT_BLOCK;

NTKERNELAPI
VOID
FASTCALL
ExfUnblockPushLock(
    _Inout_ PEX_PUSH_LOCK PushLock,
    _Inout_opt_ PEX_PUSH_LOCK_WAIT_BLOCK WaitBlock
    );

NTKERNELAPI
NTSTATUS
NTAPI
PsAcquireProcessExitSynchronization(
    _In_ PEPROCESS Process
    );

NTKERNELAPI
VOID
NTAPI
PsReleaseProcessExitSynchronization(
    _In_ PEPROCESS Process
    );

NTSYSAPI
NTSTATUS
NTAPI
PsLookupProcessByProcessId(
    _In_ HANDLE ProcessId,
    _Outptr_ PEPROCESS* Process
    );

NTSYSAPI
NTSTATUS
NTAPI
ZwQuerySystemInformation(
    _In_ ULONG SystemInformationClass,
    _Out_writes_bytes_opt_(SystemInformationLength) PVOID SystemInformation,
    _In_ ULONG SystemInformationLength,
    _Out_opt_ PULONG ReturnLength
    );

NTKERNELAPI
VOID
KeStackAttachProcess(
    _Inout_ PVOID Process,
    _Out_ PVOID ApcState
    );

NTKERNELAPI
VOID
KeUnstackDetachProcess(
    _In_ PVOID ApcState
    );

NTKERNELAPI
POBJECT_TYPE
NTAPI
ObGetObjectType(
    _In_ PVOID Object
    );

typedef struct _KSWORD_ARK_HANDLE_ENUM_CONTEXT
{
    KSWORD_ARK_ENUM_PROCESS_HANDLES_RESPONSE* Response;
    size_t EntryCapacity;
    ULONG ProcessId;
    ULONG RequestFlags;
    KSW_DYN_STATE DynState;
    NTSTATUS LastStatus;
} KSWORD_ARK_HANDLE_ENUM_CONTEXT, *PKSWORD_ARK_HANDLE_ENUM_CONTEXT;

static BOOLEAN
KswordARKHandleHasRequiredDynData(
    _In_ const KSW_DYN_STATE* DynState
    )
/*++

Routine Description:

    Check every Phase-4 dependency, including HtHandleContentionEvent. 中文说明：
    capability 当前把 HtHandleContentionEvent 标为 optional；但直接调用
    ExEnumHandleTable 后必须解锁 entry，因此本功能把它作为强依赖处理。

Arguments:

    DynState - Snapshot captured at IOCTL time.

Return Value:

    TRUE when all required offsets/shifts are present.

--*/
{
    if (DynState == NULL) {
        return FALSE;
    }

    return
        KswordARKHandleIsOffsetPresent(DynState->Kernel.EpObjectTable) &&
        KswordARKHandleIsOffsetPresent(DynState->Kernel.HtHandleContentionEvent) &&
        KswordARKHandleIsOffsetPresent(DynState->Kernel.ObDecodeShift) &&
        KswordARKHandleIsOffsetPresent(DynState->Kernel.ObAttributesShift) &&
        KswordARKHandleIsOffsetPresent(DynState->Kernel.OtName) &&
        KswordARKHandleIsOffsetPresent(DynState->Kernel.OtIndex);
}

static VOID
KswordARKHandlePrepareEntryDynData(
    _Inout_ KSWORD_ARK_HANDLE_ENTRY* Entry,
    _In_ const KSW_DYN_STATE* DynState
    )
/*++

Routine Description:

    Copy DynData diagnostics into one response entry. 中文说明：这些字段仅用于
    展示“本次解码使用了哪些偏移/shift”，不允许 R3 用它们作为对象凭据。

Arguments:

    Entry - Mutable response row.
    DynState - Active DynData snapshot.

Return Value:

    None.

--*/
{
    if (Entry == NULL || DynState == NULL) {
        return;
    }

    Entry->dynDataCapabilityMask = DynState->CapabilityMask;
    Entry->epObjectTableOffset = KswordARKHandleNormalizeOffset(DynState->Kernel.EpObjectTable);
    Entry->htHandleContentionEventOffset = KswordARKHandleNormalizeOffset(DynState->Kernel.HtHandleContentionEvent);
    Entry->obDecodeShift = KswordARKHandleNormalizeOffset(DynState->Kernel.ObDecodeShift);
    Entry->obAttributesShift = KswordARKHandleNormalizeOffset(DynState->Kernel.ObAttributesShift);
    Entry->otNameOffset = KswordARKHandleNormalizeOffset(DynState->Kernel.OtName);
    Entry->otIndexOffset = KswordARKHandleNormalizeOffset(DynState->Kernel.OtIndex);
}

static PVOID
KswordARKHandleDecodeObjectHeader(
    _In_ const KSW_DYN_STATE* DynState,
    _In_ PHANDLE_TABLE_ENTRY HandleTableEntry
    )
/*++

Routine Description:

    Decode the encoded object header pointer stored in HANDLE_TABLE_ENTRY.
    中文说明：逻辑直接对齐 System Informer 的 KphObpDecodeObject；LA57 的差异
    由 ObDecodeShift 动态数据吸收，这里不猜测系统版本。

Arguments:

    DynState - Active DynData snapshot containing ObDecodeShift.
    HandleTableEntry - Current handle table entry supplied by ExEnumHandleTable.

Return Value:

    Decoded OBJECT_HEADER pointer, or NULL when decoding is unavailable/failed.

--*/
{
#if defined(_M_X64) || defined(_M_ARM64)
    LONG_PTR objectValue = 0;

    if (DynState == NULL || HandleTableEntry == NULL) {
        return NULL;
    }
    if (!KswordARKHandleIsOffsetPresent(DynState->Kernel.ObDecodeShift)) {
        return NULL;
    }

    __try {
        objectValue = (LONG_PTR)HandleTableEntry->Low.Object;
        objectValue >>= DynState->Kernel.ObDecodeShift;
        objectValue <<= 4;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return NULL;
    }
    return (PVOID)objectValue;
#else
    UNREFERENCED_PARAMETER(DynState);
    if (HandleTableEntry == NULL) {
        return NULL;
    }
    __try {
        return (PVOID)((ULONG_PTR)HandleTableEntry->Low.Object & ~0x7UL);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return NULL;
    }
#endif
}

static ULONG
KswordARKHandleDecodeAttributes(
    _In_ const KSW_DYN_STATE* DynState,
    _In_ PHANDLE_TABLE_ENTRY HandleTableEntry
    )
/*++

Routine Description:

    Decode HANDLE_TABLE_ENTRY attributes. 中文说明：x64/ARM64 新格式把属性位
    编在 Value 高位，ObAttributesShift 来自 DynData，避免硬编码。

Arguments:

    DynState - Active DynData snapshot containing ObAttributesShift.
    HandleTableEntry - Current handle table entry.

Return Value:

    Low attribute bits used by UI (PROTECT/INHERIT/AUDIT subset).

--*/
{
#if defined(_M_X64) || defined(_M_ARM64)
    if (DynState == NULL || HandleTableEntry == NULL) {
        return 0UL;
    }
    if (!KswordARKHandleIsOffsetPresent(DynState->Kernel.ObAttributesShift)) {
        return 0UL;
    }

    return (ULONG)((HandleTableEntry->Low.Value >> DynState->Kernel.ObAttributesShift) & 0x3UL);
#else
    UNREFERENCED_PARAMETER(DynState);
    if (HandleTableEntry == NULL) {
        return 0UL;
    }
    return (ULONG)(HandleTableEntry->Low.ObAttributes & 0x7UL);
#endif
}

static VOID
KswordARKHandleUnlockEntry(
    _In_ const KSW_DYN_STATE* DynState,
    _In_ PHANDLE_TABLE HandleTable,
    _Inout_ PHANDLE_TABLE_ENTRY HandleTableEntry
    )
/*++

Routine Description:

    Release one entry lock held by ExEnumHandleTable. 中文说明：此处照搬
    System Informer 的解锁模型，先设置 unlocked bit，再唤醒等待者。

Arguments:

    DynState - Active DynData snapshot containing HtHandleContentionEvent.
    HandleTable - Owning handle table.
    HandleTableEntry - Entry to unlock.

Return Value:

    None.

--*/
{
    PEX_PUSH_LOCK handleContentionEvent = NULL;

    if (DynState == NULL || HandleTable == NULL || HandleTableEntry == NULL) {
        return;
    }
    if (!KswordARKHandleIsOffsetPresent(DynState->Kernel.HtHandleContentionEvent)) {
        return;
    }

    #if defined(_WIN64)
    InterlockedExchangeAdd64((volatile LONG64*)&HandleTableEntry->Low.Value, 1);
#else
    InterlockedExchangeAdd((volatile LONG*)&HandleTableEntry->Low.Value, 1);
#endif
    handleContentionEvent = (PEX_PUSH_LOCK)((PUCHAR)HandleTable + DynState->Kernel.HtHandleContentionEvent);
    if (*(PULONG_PTR)handleContentionEvent != 0UL) {
        ExfUnblockPushLock(handleContentionEvent, NULL);
    }
}

static VOID
KswordARKHandleFillEntryFromTable(
    _Inout_ KSWORD_ARK_HANDLE_ENTRY* Entry,
    _In_ PHANDLE_TABLE_ENTRY HandleTableEntry,
    _In_ HANDLE Handle,
    _In_ PKSWORD_ARK_HANDLE_ENUM_CONTEXT Context
    )
/*++

Routine Description:

    Decode one handle table row into the shared response entry. 中文说明：失败不会
    丢弃该行，DecodeStatus 会记录保守状态，方便 UI 做差异分析。

Arguments:

    Entry - Mutable response entry.
    HandleTableEntry - Raw kernel handle table entry.
    Handle - Numeric handle value supplied by ExEnumHandleTable.
    Context - Enumeration context with DynData snapshot and request flags.

Return Value:

    None.

--*/
{
    PVOID objectHeader = NULL;
    PVOID objectBody = NULL;
    POBJECT_TYPE objectType = NULL;

    if (Entry == NULL || HandleTableEntry == NULL || Context == NULL) {
        return;
    }

    Entry->processId = Context->ProcessId;
    Entry->handleValue = HandleToULong(Handle);
    Entry->decodeStatus = KSWORD_ARK_HANDLE_DECODE_STATUS_OK;
    Entry->grantedAccessDecodeStatus = KSWORD_ARK_HANDLE_DECODE_STATUS_UNAVAILABLE;
    Entry->grantedAccessReadStatus = STATUS_UNSUCCESSFUL;
    KswordARKHandlePrepareEntryDynData(Entry, &Context->DynState);

    __try {
        Entry->grantedAccess = ((ULONG)HandleTableEntry->High.GrantedAccess) & KSWORD_ARK_OBJECT_GRANTED_ACCESS_MASK;
        Entry->attributes = KswordARKHandleDecodeAttributes(&Context->DynState, HandleTableEntry);
        Entry->grantedAccessDecodeStatus = KSWORD_ARK_HANDLE_DECODE_STATUS_OK;
        Entry->grantedAccessReadStatus = STATUS_SUCCESS;
        Entry->fieldFlags |= KSWORD_ARK_HANDLE_FIELD_GRANTED_ACCESS_PRESENT;
        Entry->fieldFlags |= KSWORD_ARK_HANDLE_FIELD_ATTRIBUTES_PRESENT;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        Context->LastStatus = GetExceptionCode();
        Entry->decodeStatus = KSWORD_ARK_HANDLE_DECODE_STATUS_PARTIAL;
        Entry->grantedAccessDecodeStatus = KSWORD_ARK_HANDLE_DECODE_STATUS_ACCESS_DECODE_FAILED;
        Entry->grantedAccessReadStatus = Context->LastStatus;
    }

    if ((Context->RequestFlags & KSWORD_ARK_ENUM_HANDLE_FLAG_INCLUDE_OBJECT) != 0UL) {
        objectHeader = KswordARKHandleDecodeObjectHeader(&Context->DynState, HandleTableEntry);
        if (objectHeader != NULL) {
            objectBody = KswordARKHandleGetObjectBodyFromHeader(objectHeader);
            Entry->objectAddress = (ULONG64)(ULONG_PTR)objectBody;
            Entry->fieldFlags |= KSWORD_ARK_HANDLE_FIELD_OBJECT_PRESENT;
        }
        else {
            Entry->decodeStatus = KSWORD_ARK_HANDLE_DECODE_STATUS_OBJECT_DECODE_FAILED;
        }
    }

    if ((Context->RequestFlags & KSWORD_ARK_ENUM_HANDLE_FLAG_INCLUDE_TYPE_INDEX) != 0UL) {
        if (objectBody == NULL) {
            Entry->decodeStatus = KSWORD_ARK_HANDLE_DECODE_STATUS_OBJECT_DECODE_FAILED;
            return;
        }

        __try {
            objectType = ObGetObjectType(objectBody);
            if (NT_SUCCESS(KswordARKHandleReadObjectTypeIndex(objectType, &Context->DynState, &Entry->objectTypeIndex))) {
                Entry->fieldFlags |= KSWORD_ARK_HANDLE_FIELD_TYPE_INDEX_PRESENT;
            }
            else if (Entry->decodeStatus == KSWORD_ARK_HANDLE_DECODE_STATUS_OK) {
                Entry->decodeStatus = KSWORD_ARK_HANDLE_DECODE_STATUS_TYPE_DECODE_FAILED;
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            Context->LastStatus = GetExceptionCode();
            if (Entry->decodeStatus == KSWORD_ARK_HANDLE_DECODE_STATUS_OK) {
                Entry->decodeStatus = KSWORD_ARK_HANDLE_DECODE_STATUS_TYPE_DECODE_FAILED;
            }
        }
    }

    if (objectHeader != NULL || objectBody != NULL) {
        KswordARKHandleFillEntryObjectHeaderAudit(
            Entry,
            objectHeader,
            objectBody,
            objectType,
            &Context->DynState);
        if (Entry->objectHeaderDecodeStatus != KSWORD_ARK_HANDLE_DECODE_STATUS_OK &&
            Entry->decodeStatus == KSWORD_ARK_HANDLE_DECODE_STATUS_OK) {
            Entry->decodeStatus = KSWORD_ARK_HANDLE_DECODE_STATUS_PARTIAL;
        }
    }

    if (Entry->objectTypeIndexSource == KSWORD_ARK_OBJECT_TYPE_SOURCE_NONE) {
        Entry->objectTypeIndexSource = KswordARKHandleMergeTypeIndexSource(
            ((Entry->fieldFlags & KSWORD_ARK_HANDLE_FIELD_TYPE_INDEX_PRESENT) != 0UL) ? TRUE : FALSE,
            Entry->objectTypeIndex,
            ((Entry->fieldFlags & KSWORD_ARK_HANDLE_FIELD_HEADER_TYPE_INDEX_PRESENT) != 0UL) ? TRUE : FALSE,
            Entry->objectHeaderTypeIndex);
    }

    if (Entry->decodeStatus == KSWORD_ARK_HANDLE_DECODE_STATUS_OK &&
        (Entry->fieldFlags & KSWORD_ARK_HANDLE_FIELD_TYPE_INDEX_PRESENT) == 0UL &&
        (Context->RequestFlags & KSWORD_ARK_ENUM_HANDLE_FLAG_INCLUDE_TYPE_INDEX) != 0UL) {
        Entry->decodeStatus = KSWORD_ARK_HANDLE_DECODE_STATUS_PARTIAL;
    }
}

static BOOLEAN NTAPI
KswordARKHandleEnumCallback(
    _In_ PHANDLE_TABLE HandleTable,
    _Inout_ PHANDLE_TABLE_ENTRY HandleTableEntry,
    _In_ HANDLE Handle,
    _In_opt_ PVOID Context
    )
/*++

Routine Description:

    ExEnumHandleTable callback. 中文说明：即使输出缓冲不足也继续统计 totalCount，
    每个 entry 回调结束前必须解锁当前 HandleTableEntry。

Arguments:

    HandleTable - Owning handle table.
    HandleTableEntry - Current entry locked by ExEnumHandleTable.
    Handle - Numeric handle value.
    Context - KSWORD_ARK_HANDLE_ENUM_CONTEXT pointer.

Return Value:

    FALSE to continue enumeration.

--*/
{
    PKSWORD_ARK_HANDLE_ENUM_CONTEXT enumContext = (PKSWORD_ARK_HANDLE_ENUM_CONTEXT)Context;
    KSWORD_ARK_HANDLE_ENTRY* entry = NULL;

    if (enumContext == NULL || enumContext->Response == NULL) {
        return FALSE;
    }

    if (enumContext->Response->totalCount != MAXULONG) {
        enumContext->Response->totalCount += 1UL;
    }

    if ((size_t)enumContext->Response->returnedCount < enumContext->EntryCapacity) {
        entry = &enumContext->Response->entries[enumContext->Response->returnedCount];
        RtlZeroMemory(entry, sizeof(*entry));
        KswordARKHandleFillEntryFromTable(entry, HandleTableEntry, Handle, enumContext);
        enumContext->Response->returnedCount += 1UL;
    }

    KswordARKHandleUnlockEntry(&enumContext->DynState, HandleTable, HandleTableEntry);
    return FALSE;
}

static NTSTATUS
KswordARKHandleReadProcessHandleTable(
    _In_ PEPROCESS ProcessObject,
    _In_ const KSW_DYN_STATE* DynState,
    _Outptr_result_nullonfailure_ PHANDLE_TABLE* HandleTableOut
    )
/*++

Routine Description:

    Acquire process-exit synchronization and read EPROCESS.ObjectTable. 中文说明：
    成功返回后调用方必须 PsReleaseProcessExitSynchronization。

Arguments:

    ProcessObject - Referenced target EPROCESS.
    DynState - Active DynData snapshot containing EpObjectTable.
    HandleTableOut - Receives the raw handle table pointer.

Return Value:

    STATUS_SUCCESS with the process exit lock held, or failure status.

--*/
{
    NTSTATUS status = STATUS_SUCCESS;
    PHANDLE_TABLE handleTable = NULL;

    if (ProcessObject == NULL || DynState == NULL || HandleTableOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *HandleTableOut = NULL;

    if (!KswordARKHandleIsOffsetPresent(DynState->Kernel.EpObjectTable)) {
        return STATUS_NOT_SUPPORTED;
    }

    status = PsAcquireProcessExitSynchronization(ProcessObject);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    __try {
        RtlCopyMemory(&handleTable, (PUCHAR)ProcessObject + DynState->Kernel.EpObjectTable, sizeof(handleTable));
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();
    }

    if (!NT_SUCCESS(status) || handleTable == NULL) {
        PsReleaseProcessExitSynchronization(ProcessObject);
        return NT_SUCCESS(status) ? STATUS_NOT_FOUND : status;
    }

    *HandleTableOut = handleTable;
    return STATUS_SUCCESS;
}

static NTSTATUS
KswordARKHandleCaptureSystemSnapshot(
    _Outptr_result_bytebuffer_(*SnapshotBytesOut) KSW_SYSTEM_HANDLE_INFORMATION_EX** SnapshotOut,
    _Out_ ULONG* SnapshotBytesOut
    )
/*++

Routine Description:

    Capture the documented system-wide extended handle projection used as the
    no-profile fallback.  The buffer is size-bounded and re-queried at most
    three times so handle churn cannot cause an unbounded allocation loop.

--*/
{
    KSW_SYSTEM_HANDLE_INFORMATION_EX* snapshot = NULL;
    ULONG requiredBytes = 0UL;
    ULONG allocationBytes = 0UL;
    ULONG attempt = 0UL;
    NTSTATUS status = STATUS_SUCCESS;

    if (SnapshotOut == NULL || SnapshotBytesOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *SnapshotOut = NULL;
    *SnapshotBytesOut = 0UL;

    status = ZwQuerySystemInformation(
        KSWORD_ARK_HANDLE_SNAPSHOT_INFO_CLASS,
        NULL,
        0UL,
        &requiredBytes);
    if (status != STATUS_INFO_LENGTH_MISMATCH && !NT_SUCCESS(status)) {
        return status;
    }
    if (requiredBytes < sizeof(KSW_SYSTEM_HANDLE_INFORMATION_EX)) {
        requiredBytes = 64UL * 1024UL;
    }

    for (attempt = 0UL; attempt < 3UL; ++attempt) {
        if (requiredBytes > KSWORD_ARK_HANDLE_SNAPSHOT_MAX_BYTES - (64UL * 1024UL)) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        allocationBytes = requiredBytes + (64UL * 1024UL);
        snapshot = (KSW_SYSTEM_HANDLE_INFORMATION_EX*)KswordARKAllocateNonPagedPool(
            allocationBytes,
            KSWORD_ARK_HANDLE_SNAPSHOT_POOL_TAG);
        if (snapshot == NULL) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        RtlZeroMemory(snapshot, allocationBytes);
        status = ZwQuerySystemInformation(
            KSWORD_ARK_HANDLE_SNAPSHOT_INFO_CLASS,
            snapshot,
            allocationBytes,
            &requiredBytes);
        if (NT_SUCCESS(status)) {
            *SnapshotOut = snapshot;
            *SnapshotBytesOut = allocationBytes;
            return STATUS_SUCCESS;
        }
        ExFreePoolWithTag(snapshot, KSWORD_ARK_HANDLE_SNAPSHOT_POOL_TAG);
        snapshot = NULL;
        if (status != STATUS_INFO_LENGTH_MISMATCH ||
            requiredBytes > KSWORD_ARK_HANDLE_SNAPSHOT_MAX_BYTES) {
            return status;
        }
    }

    return STATUS_INFO_LENGTH_MISMATCH;
}

static VOID
KswordARKHandlePopulateSnapshotHeaderAudit(
    _Inout_ KSWORD_ARK_HANDLE_ENTRY* Entry,
    _In_ PVOID Object
    )
/*++

Routine Description:

    Add only the OBJECT_HEADER fields independently proved by the runtime
    signature resolver.  TypeIndex/InfoMask are intentionally left absent;
    they must never be inferred from the legacy compile-time header layout.

--*/
{
    KSW_OBJECT_HEADER_FALLBACK_RESULT result;
    NTSTATUS status = STATUS_SUCCESS;

    if (Entry == NULL || Object == NULL) {
        return;
    }
    RtlZeroMemory(&result, sizeof(result));
    status = KswordARKObjectHeaderQueryFallback(Object, &result);
    Entry->objectHeaderReadStatus = status;
    if (!NT_SUCCESS(status) || (ULONG_PTR)Object < result.BodyOffset) {
        Entry->objectHeaderDecodeStatus =
            KSWORD_ARK_HANDLE_DECODE_STATUS_HEADER_DYNDATA_MISSING;
        return;
    }

    Entry->objectHeaderAddress = (ULONG64)((ULONG_PTR)Object - result.BodyOffset);
    Entry->pointerCount = (LONG64)result.PointerCount;
    Entry->objectHeaderDecodeStatus = KSWORD_ARK_HANDLE_DECODE_STATUS_PARTIAL;
    Entry->fieldFlags |=
        KSWORD_ARK_HANDLE_FIELD_OBJECT_HEADER_PRESENT |
        KSWORD_ARK_HANDLE_FIELD_OBJECT_HEADER_BODY_PRESENT |
        KSWORD_ARK_HANDLE_FIELD_POINTER_COUNT_PRESENT;
    if ((result.ValidFields &
            KSW_OBJECT_HEADER_FALLBACK_FIELD_HANDLE_COUNT) != 0UL) {
        Entry->handleCount = (ULONG64)result.HandleCount;
        Entry->fieldFlags |= KSWORD_ARK_HANDLE_FIELD_HANDLE_COUNT_PRESENT;
    }
}

static NTSTATUS
KswordARKHandleEnumerateSystemSnapshot(
    _Inout_ KSWORD_ARK_ENUM_PROCESS_HANDLES_RESPONSE* Response,
    _In_ size_t OutputBufferLength,
    _In_ const KSWORD_ARK_ENUM_PROCESS_HANDLES_REQUEST* Request,
    _In_ const KSW_DYN_STATE* DynState,
    _Out_ size_t* BytesWrittenOut
    )
/*++

Routine Description:

    Enumerate handles without EPROCESS/HANDLE_TABLE private offsets.  The
    system snapshot supplies handle/access/type metadata; emitted rows are
    optionally re-referenced in the target process before runtime header
    counters are read.  This is the fail-safe fallback when the direct
    handle-table profile is absent.

--*/
{
    KSW_SYSTEM_HANDLE_INFORMATION_EX* snapshot = NULL;
    PEPROCESS processObject = NULL;
    ULONG snapshotBytes = 0UL;
    ULONG_PTR snapshotCapacity = 0U;
    ULONG_PTR snapshotCount = 0U;
    ULONG_PTR index = 0U;
    ULONG requestFlags = 0UL;
    size_t entryCapacity = 0U;
    DECLSPEC_ALIGN(16) UCHAR attachState[128];
    BOOLEAN attached = FALSE;
    NTSTATUS status = STATUS_SUCCESS;

    if (Response == NULL || Request == NULL || DynState == NULL ||
        BytesWrittenOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    requestFlags = (Request->flags == 0UL) ?
        KSWORD_ARK_ENUM_HANDLE_FLAG_INCLUDE_ALL : Request->flags;
    entryCapacity = (OutputBufferLength - KSWORD_ARK_HANDLE_ENUM_RESPONSE_HEADER_SIZE) /
        sizeof(KSWORD_ARK_HANDLE_ENTRY);

    status = PsLookupProcessByProcessId(
        ULongToHandle(Request->processId),
        &processObject);
    if (!NT_SUCCESS(status)) {
        Response->overallStatus = KSWORD_ARK_HANDLE_DECODE_STATUS_PROCESS_LOOKUP_FAILED;
        Response->lastStatus = status;
        *BytesWrittenOut = KSWORD_ARK_HANDLE_ENUM_RESPONSE_HEADER_SIZE;
        return status;
    }
    status = KswordARKHandleCaptureSystemSnapshot(&snapshot, &snapshotBytes);
    if (!NT_SUCCESS(status)) {
        Response->overallStatus = KSWORD_ARK_HANDLE_DECODE_STATUS_READ_FAILED;
        Response->lastStatus = status;
        ObDereferenceObject(processObject);
        *BytesWrittenOut = KSWORD_ARK_HANDLE_ENUM_RESPONSE_HEADER_SIZE;
        return status;
    }

    snapshotCapacity = (snapshotBytes - FIELD_OFFSET(
        KSW_SYSTEM_HANDLE_INFORMATION_EX,
        Handles)) / sizeof(snapshot->Handles[0]);
    snapshotCount = snapshot->NumberOfHandles;
    if (snapshotCount > snapshotCapacity) {
        snapshotCount = snapshotCapacity;
        Response->lastStatus = STATUS_DATA_ERROR;
    }

    RtlZeroMemory(attachState, sizeof(attachState));
    __try {
        KeStackAttachProcess((PVOID)processObject, attachState);
        attached = TRUE;
        for (index = 0U; index < snapshotCount; ++index) {
            const KSW_SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX* source =
                &snapshot->Handles[index];
            KSWORD_ARK_HANDLE_ENTRY* entry = NULL;
            PVOID referencedObject = NULL;
            OBJECT_HANDLE_INFORMATION handleInformation;
            NTSTATUS referenceStatus = STATUS_SUCCESS;

            if (source->UniqueProcessId != (ULONG_PTR)Request->processId) {
                continue;
            }
            if (Response->totalCount != MAXULONG) {
                Response->totalCount += 1UL;
            }
            if ((size_t)Response->returnedCount >= entryCapacity) {
                continue;
            }

            entry = &Response->entries[Response->returnedCount++];
            RtlZeroMemory(entry, sizeof(*entry));
            entry->processId = Request->processId;
            entry->handleValue = (ULONG)source->HandleValue;
            entry->grantedAccess = source->GrantedAccess;
            entry->attributes = source->HandleAttributes;
            entry->decodeStatus = KSWORD_ARK_HANDLE_DECODE_STATUS_OK;
            entry->grantedAccessDecodeStatus = KSWORD_ARK_HANDLE_DECODE_STATUS_OK;
            entry->grantedAccessReadStatus = STATUS_SUCCESS;
            entry->objectHeaderDecodeStatus = KSWORD_ARK_HANDLE_DECODE_STATUS_UNAVAILABLE;
            entry->objectHeaderReadStatus = STATUS_NOT_SUPPORTED;
            entry->fieldFlags |=
                KSWORD_ARK_HANDLE_FIELD_GRANTED_ACCESS_PRESENT |
                KSWORD_ARK_HANDLE_FIELD_ATTRIBUTES_PRESENT;
            KswordARKHandlePrepareEntryDynData(entry, DynState);

            if ((requestFlags & KSWORD_ARK_ENUM_HANDLE_FLAG_INCLUDE_OBJECT) != 0UL &&
                source->Object != NULL) {
                entry->objectAddress = (ULONG64)(ULONG_PTR)source->Object;
                entry->fieldFlags |= KSWORD_ARK_HANDLE_FIELD_OBJECT_PRESENT;
            }
            if ((requestFlags & KSWORD_ARK_ENUM_HANDLE_FLAG_INCLUDE_TYPE_INDEX) != 0UL &&
                source->ObjectTypeIndex != 0U) {
                entry->objectTypeIndex = source->ObjectTypeIndex;
                entry->objectTypeIndexSource =
                    KSWORD_ARK_OBJECT_TYPE_SOURCE_SYSTEM_SNAPSHOT;
                entry->fieldFlags |= KSWORD_ARK_HANDLE_FIELD_TYPE_INDEX_PRESENT;
            }

            RtlZeroMemory(&handleInformation, sizeof(handleInformation));
            referenceStatus = ObReferenceObjectByHandle(
                (HANDLE)source->HandleValue,
                0,
                NULL,
                UserMode,
                &referencedObject,
                &handleInformation);
            if (NT_SUCCESS(referenceStatus) && referencedObject != NULL) {
                if ((requestFlags & KSWORD_ARK_ENUM_HANDLE_FLAG_INCLUDE_OBJECT) != 0UL) {
                    entry->objectAddress = (ULONG64)(ULONG_PTR)referencedObject;
                    entry->fieldFlags |= KSWORD_ARK_HANDLE_FIELD_OBJECT_PRESENT;
                }
                KswordARKHandlePopulateSnapshotHeaderAudit(entry, referencedObject);
                ObDereferenceObject(referencedObject);
            }
            else {
                entry->objectHeaderReadStatus = referenceStatus;
            }
        }
        KeUnstackDetachProcess(attachState);
        attached = FALSE;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();
        if (attached) {
            KeUnstackDetachProcess(attachState);
            attached = FALSE;
        }
    }

    ExFreePoolWithTag(snapshot, KSWORD_ARK_HANDLE_SNAPSHOT_POOL_TAG);
    ObDereferenceObject(processObject);
    if (!NT_SUCCESS(status)) {
        Response->overallStatus = KSWORD_ARK_HANDLE_DECODE_STATUS_READ_FAILED;
        Response->lastStatus = status;
    }
    else {
        Response->overallStatus = (Response->returnedCount < Response->totalCount) ?
            KSWORD_ARK_HANDLE_DECODE_STATUS_BUFFER_TOO_SMALL :
            KSWORD_ARK_HANDLE_DECODE_STATUS_OK;
        if (NT_SUCCESS(Response->lastStatus)) {
            Response->lastStatus = STATUS_SUCCESS;
        }
    }
    *BytesWrittenOut = KSWORD_ARK_HANDLE_ENUM_RESPONSE_HEADER_SIZE +
        ((size_t)Response->returnedCount * sizeof(KSWORD_ARK_HANDLE_ENTRY));
    return status;
}

static KSWORD_ARK_ENUM_PROCESS_HANDLES_RESPONSE*
KswordARKHandlePrepareEnumerationResponse(
    _Out_writes_bytes_(OutputBufferLength) PVOID OutputBuffer,
    _In_ size_t OutputBufferLength,
    _In_ ULONG ProcessId
    )
/*++

Routine Description:

    Reset the common response header before either the private-table path or a
    retry through the system handle snapshot fallback.

--*/
{
    KSWORD_ARK_ENUM_PROCESS_HANDLES_RESPONSE* response = NULL;

    if (OutputBuffer == NULL ||
        OutputBufferLength < KSWORD_ARK_HANDLE_ENUM_RESPONSE_HEADER_SIZE) {
        return NULL;
    }
    RtlZeroMemory(OutputBuffer, OutputBufferLength);
    response = (KSWORD_ARK_ENUM_PROCESS_HANDLES_RESPONSE*)OutputBuffer;
    response->version = KSWORD_ARK_HANDLE_PROTOCOL_VERSION;
    response->entrySize = sizeof(KSWORD_ARK_HANDLE_ENTRY);
    response->processId = ProcessId;
    response->overallStatus = KSWORD_ARK_HANDLE_DECODE_STATUS_UNAVAILABLE;
    response->lastStatus = STATUS_SUCCESS;
    return response;
}

NTSTATUS
KswordARKDriverEnumerateProcessHandles(
    _Out_writes_bytes_to_(OutputBufferLength, *BytesWrittenOut) PVOID OutputBuffer,
    _In_ size_t OutputBufferLength,
    _In_ const KSWORD_ARK_ENUM_PROCESS_HANDLES_REQUEST* Request,
    _Out_ size_t* BytesWrittenOut
    )
/*++

Routine Description:

    Enumerate a target process HandleTable directly from kernel mode. 中文说明：
    本函数只返回显示/差异分析字段；对象地址是诊断值，不是后续 IOCTL 的凭据。

Arguments:

    OutputBuffer - Caller output packet.
    OutputBufferLength - Output packet capacity.
    Request - Required request containing a non-zero PID.
    BytesWrittenOut - Receives actual bytes written.

Return Value:

    STATUS_SUCCESS when the response header is valid; private-field or lookup
    failures are reflected in response->overallStatus and may also be returned.

--*/
{
    KSWORD_ARK_ENUM_PROCESS_HANDLES_RESPONSE* response = NULL;
    KSWORD_ARK_HANDLE_ENUM_CONTEXT enumContext;
    PEPROCESS processObject = NULL;
    PHANDLE_TABLE handleTable = NULL;
    size_t entryCapacity = 0U;
    size_t totalBytesWritten = 0U;
    NTSTATUS status = STATUS_SUCCESS;

    if (OutputBuffer == NULL || BytesWrittenOut == NULL || Request == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *BytesWrittenOut = 0U;
    if (OutputBufferLength < KSWORD_ARK_HANDLE_ENUM_RESPONSE_HEADER_SIZE) {
        return STATUS_BUFFER_TOO_SMALL;
    }
    if (Request->processId == 0UL) {
        return STATUS_INVALID_PARAMETER;
    }

    response = KswordARKHandlePrepareEnumerationResponse(
        OutputBuffer,
        OutputBufferLength,
        Request->processId);
    if (response == NULL) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    RtlZeroMemory(&enumContext, sizeof(enumContext));
    enumContext.Response = response;
    enumContext.ProcessId = Request->processId;
    enumContext.RequestFlags = (Request->flags == 0UL) ? KSWORD_ARK_ENUM_HANDLE_FLAG_INCLUDE_ALL : Request->flags;
    enumContext.LastStatus = STATUS_SUCCESS;
    KswordARKDynDataSnapshot(&enumContext.DynState);

    if (!KswordARKHandleHasRequiredDynData(&enumContext.DynState)) {
        return KswordARKHandleEnumerateSystemSnapshot(
            response,
            OutputBufferLength,
            Request,
            &enumContext.DynState,
            BytesWrittenOut);
    }

    status = PsLookupProcessByProcessId(ULongToHandle(Request->processId), &processObject);
    if (!NT_SUCCESS(status)) {
        response->overallStatus = KSWORD_ARK_HANDLE_DECODE_STATUS_PROCESS_LOOKUP_FAILED;
        response->lastStatus = status;
        totalBytesWritten = KSWORD_ARK_HANDLE_ENUM_RESPONSE_HEADER_SIZE;
        *BytesWrittenOut = totalBytesWritten;
        return status;
    }

    status = KswordARKHandleReadProcessHandleTable(processObject, &enumContext.DynState, &handleTable);
    if (!NT_SUCCESS(status)) {
        response->overallStatus = (status == STATUS_NOT_FOUND) ?
            KSWORD_ARK_HANDLE_DECODE_STATUS_HANDLE_TABLE_MISSING :
            KSWORD_ARK_HANDLE_DECODE_STATUS_PROCESS_EXITING;
        response->lastStatus = status;
        ObDereferenceObject(processObject);
        response = KswordARKHandlePrepareEnumerationResponse(
            OutputBuffer,
            OutputBufferLength,
            Request->processId);
        return KswordARKHandleEnumerateSystemSnapshot(
            response,
            OutputBufferLength,
            Request,
            &enumContext.DynState,
            BytesWrittenOut);
    }

    entryCapacity = (OutputBufferLength - KSWORD_ARK_HANDLE_ENUM_RESPONSE_HEADER_SIZE) / sizeof(KSWORD_ARK_HANDLE_ENTRY);
    enumContext.EntryCapacity = entryCapacity;

    __try {
        (VOID)ExEnumHandleTable(handleTable, KswordARKHandleEnumCallback, &enumContext, NULL);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();
        enumContext.LastStatus = status;
    }

    PsReleaseProcessExitSynchronization(processObject);
    ObDereferenceObject(processObject);

    if (!NT_SUCCESS(status)) {
        response = KswordARKHandlePrepareEnumerationResponse(
            OutputBuffer,
            OutputBufferLength,
            Request->processId);
        return KswordARKHandleEnumerateSystemSnapshot(
            response,
            OutputBufferLength,
            Request,
            &enumContext.DynState,
            BytesWrittenOut);
    }

    response->overallStatus = (response->returnedCount < response->totalCount) ?
        KSWORD_ARK_HANDLE_DECODE_STATUS_BUFFER_TOO_SMALL :
        KSWORD_ARK_HANDLE_DECODE_STATUS_OK;
    response->lastStatus = enumContext.LastStatus;
    totalBytesWritten = KSWORD_ARK_HANDLE_ENUM_RESPONSE_HEADER_SIZE +
        ((size_t)response->returnedCount * sizeof(KSWORD_ARK_HANDLE_ENTRY));
    *BytesWrittenOut = totalBytesWritten;

    return STATUS_SUCCESS;
}
