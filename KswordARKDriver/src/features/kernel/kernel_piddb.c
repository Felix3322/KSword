/*++

Module Name:

    kernel_piddb.c

Abstract:

    Exact PDB-layout-gated PiDDB cache enumeration and identity-bound removal.

Environment:

    Kernel mode, PASSIVE_LEVEL.

--*/

#include "kernel_piddb.h"
#include "ark/ark_dyndata.h"
#include "../../platform/kernel_object_probe.h"
#include "../../platform/pool_compat.h"

#define KSW_PIDDB_POOL_TAG 'bDiP'
#define KSW_PIDDB_MAX_ENTRY_BYTES 4096UL
#define KSW_PIDDB_HARD_WALK_LIMIT 4096UL

typedef struct _KSW_PIDDB_LAYOUT
{
    PRTL_AVL_TABLE Table;
    PERESOURCE Lock;
    ULONG DriverNameOffset;
    ULONG TimeDateStampOffset;
    ULONG LoadStatusOffset;
    ULONG EntrySize;
} KSW_PIDDB_LAYOUT, *PKSW_PIDDB_LAYOUT;

static BOOLEAN
KswordARKPiDdbSourceIsTrusted(
    _In_ ULONG Source
    )
{
    return Source == KSW_DYN_FIELD_SOURCE_PDB_PROFILE ||
        Source == KSW_DYN_FIELD_SOURCE_RUNTIME_PATTERN;
}

static SIZE_T
KswordARKPiDdbBoundedWideLength(
    _In_reads_(Capacity) const WCHAR* Text,
    _In_ SIZE_T Capacity
    )
{
    SIZE_T index = 0U;

    /* Walk only the fixed protocol array and never depend on kernel CRT helpers. */
    if (Text == NULL) {
        return Capacity;
    }
    for (index = 0U; index < Capacity; ++index) {
        if (Text[index] == L'\0') {
            return index;
        }
    }
    return Capacity;
}

static BOOLEAN
KswordARKPiDdbRvaToAddress(
    _In_ const KSW_DYN_STATE* State,
    _In_ ULONG Rva,
    _In_ SIZE_T RequiredBytes,
    _Out_ ULONGLONG* AddressOut
    )
{
    ULONGLONG imageBase = 0ULL;
    ULONG imageSize = 0UL;

    /* Reject absent state, unavailable sentinels, and missing image identity. */
    if (State == NULL || AddressOut == NULL ||
        Rva == 0UL || Rva == KSW_DYN_OFFSET_UNAVAILABLE) {
        return FALSE;
    }
    imageBase = State->Ntoskrnl.imageBase;
    imageSize = State->Ntoskrnl.sizeOfImage;
    if (imageBase == 0ULL || imageSize == 0UL ||
        Rva >= imageSize || RequiredBytes > imageSize - Rva) {
        return FALSE;
    }

    /* Derive the live address only from the identity-matched ntoskrnl base. */
    *AddressOut = imageBase + Rva;
    return TRUE;
}

static BOOLEAN
KswordARKPiDdbResolveLayout(
    _Out_ KSW_PIDDB_LAYOUT* Layout
    )
{
    KSW_DYN_STATE state;
    ULONGLONG tableAddress = 0ULL;
    ULONGLONG lockAddress = 0ULL;

    /* Snapshot DynData so no consumer retains pointers into mutable state. */
    if (Layout == NULL) {
        return FALSE;
    }
    RtlZeroMemory(Layout, sizeof(*Layout));
    RtlZeroMemory(&state, sizeof(state));
    KswordARKDynDataSnapshot(&state);

    /*
     * Prefer the exact PDB profile, but also accept the runtime resolver only
     * after its unique export-anchored candidate and live AVL/resource checks.
     */
    if (!state.NtosActive ||
        !KswordARKPiDdbSourceIsTrusted(
            state.KernelSources.PiDdbDriverName) ||
        !KswordARKPiDdbSourceIsTrusted(
            state.KernelSources.PiDdbTimeDateStamp) ||
        !KswordARKPiDdbSourceIsTrusted(
            state.KernelSources.PiDdbLoadStatus) ||
        !KswordARKPiDdbSourceIsTrusted(
            state.KernelSources.PiDdbTypeSize) ||
        !KswordARKPiDdbSourceIsTrusted(
            state.KernelGlobalSources.PiDDBCacheTable) ||
        !KswordARKPiDdbSourceIsTrusted(
            state.KernelGlobalSources.PiDDBLock) ||
        state.Kernel.PiDdbDriverName == KSW_DYN_OFFSET_UNAVAILABLE ||
        state.Kernel.PiDdbTimeDateStamp == KSW_DYN_OFFSET_UNAVAILABLE ||
        state.Kernel.PiDdbLoadStatus == KSW_DYN_OFFSET_UNAVAILABLE ||
        state.Kernel.PiDdbTypeSize == KSW_DYN_OFFSET_UNAVAILABLE ||
        state.Kernel.PiDdbTypeSize < sizeof(UNICODE_STRING) ||
        state.Kernel.PiDdbTypeSize > KSW_PIDDB_MAX_ENTRY_BYTES) {
        return FALSE;
    }

    /* Bound every member inside the exact or runtime-validated entry size. */
    if (state.Kernel.PiDdbDriverName >
            state.Kernel.PiDdbTypeSize - sizeof(UNICODE_STRING) ||
        state.Kernel.PiDdbTimeDateStamp >
            state.Kernel.PiDdbTypeSize - sizeof(ULONG) ||
        state.Kernel.PiDdbLoadStatus >
            state.Kernel.PiDdbTypeSize - sizeof(NTSTATUS)) {
        return FALSE;
    }

    /* Both the AVL table and its ERESOURCE must come from validated RVAs. */
    if (!KswordARKPiDdbRvaToAddress(
            &state,
            state.KernelGlobals.PiDDBCacheTable,
            sizeof(RTL_AVL_TABLE),
            &tableAddress) ||
        !KswordARKPiDdbRvaToAddress(
            &state,
            state.KernelGlobals.PiDDBLock,
            sizeof(ERESOURCE),
            &lockAddress)) {
        return FALSE;
    }

    /*
     * PiDdb sources include the runtime resolver, whose lock RVA comes from a
     * heuristic scan.  Both callers acquire this resource and block, so prove
     * the object is on the global resource list before publishing it.
     */
    if (!KswordARKKernelProbeResourceIsSystemResource((ULONG_PTR)lockAddress)) {
        return FALSE;
    }

    /* Publish only a fully validated scalar layout. */
    Layout->Table = (PRTL_AVL_TABLE)(ULONG_PTR)tableAddress;
    Layout->Lock = (PERESOURCE)(ULONG_PTR)lockAddress;
    Layout->DriverNameOffset = state.Kernel.PiDdbDriverName;
    Layout->TimeDateStampOffset = state.Kernel.PiDdbTimeDateStamp;
    Layout->LoadStatusOffset = state.Kernel.PiDdbLoadStatus;
    Layout->EntrySize = state.Kernel.PiDdbTypeSize;
    return TRUE;
}

static BOOLEAN
KswordARKPiDdbReadEntry(
    _In_ const KSW_PIDDB_LAYOUT* Layout,
    _In_ PVOID Entry,
    _Out_ KSWORD_ARK_PIDDB_ROW* Row
    )
{
    UNICODE_STRING driverName;
    ULONG copyBytes = 0UL;

    /* Reject null pointers before guarded reads from the AVL element. */
    if (Layout == NULL || Entry == NULL || Row == NULL) {
        return FALSE;
    }
    RtlZeroMemory(Row, sizeof(*Row));
    RtlZeroMemory(&driverName, sizeof(driverName));

    /* Read only PDB-bounded fields and the separately allocated name buffer. */
    __try {
        RtlCopyMemory(
            &driverName,
            (const UCHAR*)Entry + Layout->DriverNameOffset,
            sizeof(driverName));
        RtlCopyMemory(
            &Row->timeDateStamp,
            (const UCHAR*)Entry + Layout->TimeDateStampOffset,
            sizeof(Row->timeDateStamp));
        RtlCopyMemory(
            &Row->loadStatus,
            (const UCHAR*)Entry + Layout->LoadStatusOffset,
            sizeof(Row->loadStatus));
        if (driverName.Length == 0U ||
            driverName.Buffer == NULL ||
            driverName.Length > driverName.MaximumLength ||
            (driverName.Length & (sizeof(WCHAR) - 1U)) != 0U) {
            return FALSE;
        }
        copyBytes = min(
            (ULONG)driverName.Length,
            (ULONG)((KSWORD_ARK_PIDDB_NAME_CHARS - 1U) * sizeof(WCHAR)));
        RtlCopyMemory(Row->driverName, driverName.Buffer, copyBytes);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        RtlZeroMemory(Row, sizeof(*Row));
        return FALSE;
    }

    /* Record the exact element identity and explicit copied name length. */
    Row->entryAddress = (ULONGLONG)(ULONG_PTR)Entry;
    Row->nameLengthBytes = copyBytes;
    Row->driverName[copyBytes / sizeof(WCHAR)] = L'\0';
    return TRUE;
}

static BOOLEAN
KswordARKPiDdbRowMatchesRequest(
    _In_ const KSWORD_ARK_PIDDB_ROW* Row,
    _In_ const KSWORD_ARK_DELETE_PIDDB_REQUEST* Request
    )
{
    UNICODE_STRING rowName;
    UNICODE_STRING requestedName;
    SIZE_T requestedChars = 0U;

    /* Bind removal to the exact address, timestamp, load status, and name. */
    if (Row == NULL || Request == NULL ||
        Row->entryAddress != Request->expectedEntryAddress ||
        Row->timeDateStamp != Request->expectedTimeDateStamp ||
        Row->loadStatus != Request->expectedLoadStatus) {
        return FALSE;
    }
    requestedChars = KswordARKPiDdbBoundedWideLength(
        Request->driverName,
        KSWORD_ARK_PIDDB_NAME_CHARS);
    if (requestedChars == 0U ||
        requestedChars >= KSWORD_ARK_PIDDB_NAME_CHARS) {
        return FALSE;
    }
    RtlInitUnicodeString(&rowName, Row->driverName);
    RtlInitUnicodeString(&requestedName, Request->driverName);
    return RtlEqualUnicodeString(&rowName, &requestedName, TRUE);
}

NTSTATUS
KswordARKPiDdbQuery(
    _In_ const KSWORD_ARK_QUERY_PIDDB_REQUEST* Request,
    _Out_writes_bytes_to_(OutputBufferLength, *BytesWritten)
        KSWORD_ARK_QUERY_PIDDB_RESPONSE* Response,
    _In_ SIZE_T OutputBufferLength,
    _Out_ SIZE_T* BytesWritten
    )
{
    KSW_PIDDB_LAYOUT layout;
    ULONG maxRows = 0UL;
    ULONG rowCapacity = 0UL;
    PVOID entry = NULL;
    PVOID restartKey = NULL;
    ULONG walkedRows = 0UL;

    /* Validate the fixed header contract before writing variable rows. */
    if (Request == NULL || Response == NULL || BytesWritten == NULL ||
        OutputBufferLength < KSWORD_ARK_QUERY_PIDDB_RESPONSE_HEADER_SIZE) {
        return STATUS_INVALID_PARAMETER;
    }
    *BytesWritten = 0U;
    RtlZeroMemory(Response, OutputBufferLength);
    Response->version = KSWORD_ARK_PIDDB_PROTOCOL_VERSION;
    Response->size = KSWORD_ARK_QUERY_PIDDB_RESPONSE_HEADER_SIZE;
    Response->rowSize = sizeof(KSWORD_ARK_PIDDB_ROW);
    Response->queryStatus = KSWORD_ARK_PIDDB_QUERY_STATUS_INVALID_LAYOUT;
    if (Request->version != KSWORD_ARK_PIDDB_PROTOCOL_VERSION ||
        Request->size != sizeof(*Request)) {
        Response->lastStatus = STATUS_INVALID_PARAMETER;
        *BytesWritten = KSWORD_ARK_QUERY_PIDDB_RESPONSE_HEADER_SIZE;
        return STATUS_SUCCESS;
    }

    /* Bound output rows by both the request and the actual WDF buffer. */
    maxRows = Request->maxRows == 0UL
        ? KSWORD_ARK_PIDDB_DEFAULT_ROWS
        : min(Request->maxRows, KSWORD_ARK_PIDDB_MAX_ROWS);
    rowCapacity = (ULONG)(
        (OutputBufferLength - KSWORD_ARK_QUERY_PIDDB_RESPONSE_HEADER_SIZE) /
        sizeof(KSWORD_ARK_PIDDB_ROW));
    maxRows = min(maxRows, rowCapacity);
    if (!KswordARKPiDdbResolveLayout(&layout)) {
        Response->queryStatus = KSWORD_ARK_PIDDB_QUERY_STATUS_DYNDATA_MISSING;
        Response->lastStatus = STATUS_NOT_SUPPORTED;
        *BytesWritten = KSWORD_ARK_QUERY_PIDDB_RESPONSE_HEADER_SIZE;
        return STATUS_SUCCESS;
    }

    /*
     * Hold the exact internal resource while traversing the AVL table.  The
     * walk must not mutate it: RtlEnumerateGenericTableAvl writes RestartKey
     * and WhichOrderedElement into the table, and this resource is held only
     * shared, so concurrent readers would corrupt each other's traversal.  The
     * WithoutSplaying variant keeps its cursor in the caller's restartKey.
     */
    KeEnterCriticalRegion();
    if (!ExAcquireResourceSharedLite(layout.Lock, TRUE)) {
        KeLeaveCriticalRegion();
        Response->queryStatus = KSWORD_ARK_PIDDB_QUERY_STATUS_READ_FAILED;
        Response->lastStatus = STATUS_LOCK_NOT_GRANTED;
        *BytesWritten = KSWORD_ARK_QUERY_PIDDB_RESPONSE_HEADER_SIZE;
        return STATUS_SUCCESS;
    }
    __try {
        Response->totalRows = RtlNumberGenericTableElementsAvl(layout.Table);
        while ((entry = RtlEnumerateGenericTableWithoutSplayingAvl(
                    layout.Table,
                    &restartKey)) != NULL) {
            KSWORD_ARK_PIDDB_ROW row;

            /* Damaged AVL metadata must not turn a read-only query endless. */
            if (walkedRows >= KSW_PIDDB_HARD_WALK_LIMIT) {
                Response->responseFlags |=
                    KSWORD_ARK_PIDDB_RESPONSE_FLAG_TRUNCATED;
                break;
            }
            walkedRows += 1UL;
            if (!KswordARKPiDdbReadEntry(&layout, entry, &row)) {
                Response->queryStatus = KSWORD_ARK_PIDDB_QUERY_STATUS_PARTIAL;
                Response->lastStatus = STATUS_DATA_ERROR;
                continue;
            }
            if (Response->returnedRows >= maxRows) {
                Response->responseFlags |=
                    KSWORD_ARK_PIDDB_RESPONSE_FLAG_TRUNCATED;
                break;
            }
            Response->rows[Response->returnedRows] = row;
            Response->returnedRows += 1UL;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        Response->queryStatus = KSWORD_ARK_PIDDB_QUERY_STATUS_PARTIAL;
        Response->lastStatus = GetExceptionCode();
    }
    ExReleaseResourceLite(layout.Lock);
    KeLeaveCriticalRegion();

    /* Preserve a partial status; otherwise report a complete bounded snapshot. */
    if (Response->queryStatus != KSWORD_ARK_PIDDB_QUERY_STATUS_PARTIAL) {
        Response->queryStatus =
            (Response->responseFlags &
                KSWORD_ARK_PIDDB_RESPONSE_FLAG_TRUNCATED) != 0UL
            ? KSWORD_ARK_PIDDB_QUERY_STATUS_PARTIAL
            : KSWORD_ARK_PIDDB_QUERY_STATUS_OK;
        Response->lastStatus = STATUS_SUCCESS;
    }
    *BytesWritten = KSWORD_ARK_QUERY_PIDDB_RESPONSE_HEADER_SIZE +
        ((SIZE_T)Response->returnedRows *
            sizeof(KSWORD_ARK_PIDDB_ROW));
    Response->size = (ULONG)*BytesWritten;
    return STATUS_SUCCESS;
}

NTSTATUS
KswordARKPiDdbDelete(
    _In_ const KSWORD_ARK_DELETE_PIDDB_REQUEST* Request,
    _Out_ KSWORD_ARK_DELETE_PIDDB_RESPONSE* Response
    )
{
    KSW_PIDDB_LAYOUT layout;
    PVOID entry = NULL;
    PVOID matchedEntry = NULL;
    PVOID entryCopy = NULL;
    PVOID restartKey = NULL;
    ULONG walkedRows = 0UL;
    KSWORD_ARK_PIDDB_ROW row = { 0 };
    BOOLEAN deleted = FALSE;
    BOOLEAN stillPresent = FALSE;

    /* Initialize a semantic response before validating the mutation identity. */
    if (Request == NULL || Response == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    RtlZeroMemory(Response, sizeof(*Response));
    Response->version = KSWORD_ARK_PIDDB_PROTOCOL_VERSION;
    Response->size = sizeof(*Response);
    Response->status = KSWORD_ARK_PIDDB_DELETE_STATUS_INVALID_REQUEST;
    if (Request->version != KSWORD_ARK_PIDDB_PROTOCOL_VERSION ||
        Request->size != sizeof(*Request) ||
        Request->confirmationToken !=
            KSWORD_ARK_PIDDB_DELETE_CONFIRMATION_TOKEN ||
        Request->expectedEntryAddress == 0ULL ||
        KswordARKPiDdbBoundedWideLength(
            Request->driverName,
            KSWORD_ARK_PIDDB_NAME_CHARS) >=
            KSWORD_ARK_PIDDB_NAME_CHARS) {
        Response->lastStatus = STATUS_INVALID_PARAMETER;
        return STATUS_SUCCESS;
    }
    if (!KswordARKPiDdbResolveLayout(&layout)) {
        Response->status =
            KSWORD_ARK_PIDDB_DELETE_STATUS_DYNDATA_MISSING;
        Response->lastStatus = STATUS_NOT_SUPPORTED;
        return STATUS_SUCCESS;
    }

    /* Serialize identity lookup and deletion under the real PiDDB resource. */
    KeEnterCriticalRegion();
    if (!ExAcquireResourceExclusiveLite(layout.Lock, TRUE)) {
        KeLeaveCriticalRegion();
        Response->status =
            KSWORD_ARK_PIDDB_DELETE_STATUS_DELETE_FAILED;
        Response->lastStatus = STATUS_LOCK_NOT_GRANTED;
        return STATUS_SUCCESS;
    }
    __try {
        while ((entry = RtlEnumerateGenericTableWithoutSplayingAvl(
                    layout.Table,
                    &restartKey)) != NULL) {
            if (walkedRows >= KSW_PIDDB_HARD_WALK_LIMIT) {
                break;
            }
            walkedRows += 1UL;
            if (!KswordARKPiDdbReadEntry(&layout, entry, &row)) {
                continue;
            }
            if (KswordARKPiDdbRowMatchesRequest(&row, Request)) {
                matchedEntry = entry;
                break;
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        Response->lastStatus = GetExceptionCode();
    }
    if (matchedEntry == NULL) {
        Response->status = KSWORD_ARK_PIDDB_DELETE_STATUS_NOT_FOUND;
        if (Response->lastStatus == STATUS_SUCCESS) {
            Response->lastStatus = STATUS_NOT_FOUND;
        }
        ExReleaseResourceLite(layout.Lock);
        KeLeaveCriticalRegion();
        return STATUS_SUCCESS;
    }

    /* Copy matched identity into the response before any table-owned memory frees. */
    Response->matchedEntryAddress = row.entryAddress;
    Response->matchedTimeDateStamp = row.timeDateStamp;
    Response->matchedLoadStatus = row.loadStatus;
    RtlCopyMemory(
        Response->matchedDriverName,
        row.driverName,
        sizeof(Response->matchedDriverName));

    /* A non-force call is a read-only preflight against the current AVL state. */
    if ((Request->flags & KSWORD_ARK_PIDDB_DELETE_FLAG_FORCE) == 0UL) {
        Response->status =
            KSWORD_ARK_PIDDB_DELETE_STATUS_FORCE_REQUIRED;
        Response->lastStatus = STATUS_REQUEST_NOT_ACCEPTED;
        Response->remainingRows =
            RtlNumberGenericTableElementsAvl(layout.Table);
        ExReleaseResourceLite(layout.Lock);
        KeLeaveCriticalRegion();
        return STATUS_SUCCESS;
    }

    /* Delete using a byte-for-byte key copy while the source entry is locked. */
    entryCopy = KswordARKAllocateNonPagedPool(
        layout.EntrySize,
        KSW_PIDDB_POOL_TAG);
    if (entryCopy == NULL) {
        Response->status =
            KSWORD_ARK_PIDDB_DELETE_STATUS_DELETE_FAILED;
        Response->lastStatus = STATUS_INSUFFICIENT_RESOURCES;
        ExReleaseResourceLite(layout.Lock);
        KeLeaveCriticalRegion();
        return STATUS_SUCCESS;
    }
    __try {
        RtlCopyMemory(entryCopy, matchedEntry, layout.EntrySize);
        deleted = RtlDeleteElementGenericTableAvl(
            layout.Table,
            entryCopy);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        Response->lastStatus = GetExceptionCode();
        deleted = FALSE;
    }
    ExFreePoolWithTag(entryCopy, KSW_PIDDB_POOL_TAG);
    entryCopy = NULL;
    if (!deleted) {
        Response->status =
            KSWORD_ARK_PIDDB_DELETE_STATUS_DELETE_FAILED;
        if (Response->lastStatus == STATUS_SUCCESS) {
            Response->lastStatus = STATUS_UNSUCCESSFUL;
        }
        ExReleaseResourceLite(layout.Lock);
        KeLeaveCriticalRegion();
        return STATUS_SUCCESS;
    }

    /* Re-enumerate and require the exact identity to be absent before success. */
    restartKey = NULL;
    walkedRows = 0UL;
    __try {
        while ((entry = RtlEnumerateGenericTableWithoutSplayingAvl(
                    layout.Table,
                    &restartKey)) != NULL) {
            /* A truncated re-scan cannot prove absence, so it must not pass. */
            if (walkedRows >= KSW_PIDDB_HARD_WALK_LIMIT) {
                stillPresent = TRUE;
                break;
            }
            walkedRows += 1UL;
            if (KswordARKPiDdbReadEntry(&layout, entry, &row) &&
                KswordARKPiDdbRowMatchesRequest(&row, Request)) {
                stillPresent = TRUE;
                break;
            }
        }
        Response->remainingRows =
            RtlNumberGenericTableElementsAvl(layout.Table);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        Response->lastStatus = GetExceptionCode();
        stillPresent = TRUE;
    }
    Response->status = stillPresent
        ? KSWORD_ARK_PIDDB_DELETE_STATUS_VERIFY_FAILED
        : KSWORD_ARK_PIDDB_DELETE_STATUS_OK;
    if (!stillPresent) {
        Response->lastStatus = STATUS_SUCCESS;
    }
    ExReleaseResourceLite(layout.Lock);
    KeLeaveCriticalRegion();
    return STATUS_SUCCESS;
}
