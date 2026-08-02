/*++

Module Name:

    kernel_object_type_table.c

Abstract:

    Enumerates the live ObTypeIndexTable as read-only R0 evidence. The table is
    recovered from bounded references rooted at Object Manager exports and is
    accepted only when several exported POBJECT_TYPE identities agree with the
    table slots. Optional DynData offsets add name and index cross-validation.

Environment:

    Kernel-mode Driver Framework, PASSIVE_LEVEL read-only query path.

--*/

#include "kernel_object_type_table.h"
#include "ark/ark_dyndata.h"
#include "../../dispatch/ioctl_validation.h"
#include "../../platform/pool_compat.h"
#include "../../platform/runtime_signature_scan.h"

#define KSW_OBJECT_TYPE_RESPONSE_HEADER_SIZE \
    (sizeof(KSWORD_ARK_ENUM_OBJECT_TYPE_TABLE_RESPONSE) - \
        sizeof(KSWORD_ARK_OBJECT_TYPE_TABLE_ENTRY))
#define KSW_OBJECT_TYPE_MAX_REFERENCES 96UL
#define KSW_OBJECT_TYPE_SCAN_BYTES 0x500UL
#define KSW_OBJECT_TYPE_MAX_CALL_DEPTH 2UL
#define KSW_OBJECT_TYPE_MAX_STRUCT_OFFSET 0x1000UL
#define KSW_OBJECT_TYPE_FNV_OFFSET_BASIS 1469598103934665603ULL
#define KSW_OBJECT_TYPE_FNV_PRIME 1099511628211ULL
#define KSW_OBJECT_TYPE_NAME_POOL_TAG 'nTsK'

#ifndef STATUS_INFO_LENGTH_MISMATCH
#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS)0xC0000004L)
#endif

extern POBJECT_TYPE* PsProcessType;
extern POBJECT_TYPE* PsThreadType;
extern POBJECT_TYPE* IoDriverObjectType;
extern POBJECT_TYPE* IoFileObjectType;

NTKERNELAPI
NTSTATUS
ObQueryNameString(
    _In_ PVOID Object,
    _Out_writes_bytes_opt_(Length) POBJECT_NAME_INFORMATION ObjectNameInfo,
    _In_ ULONG Length,
    _Out_ PULONG ReturnLength
    );

typedef struct _KSW_OBJECT_TYPE_TABLE_CANDIDATE
{
    ULONG_PTR Address;
    ULONG KnownMatchCount;
    ULONG NonNullCount;
    BOOLEAN Valid;
} KSW_OBJECT_TYPE_TABLE_CANDIDATE, *PKSW_OBJECT_TYPE_TABLE_CANDIDATE;

static BOOLEAN
KswordARKObjectTypeIsKernelPointer(
    _In_ ULONG_PTR Address
    )
/*++

Routine Description:

    Validates one aligned canonical kernel pointer.

Return Value:

    TRUE only for system-range aligned addresses.

--*/
{
#if defined(_M_AMD64) || defined(_M_X64)
    return Address >= (ULONG_PTR)MmSystemRangeStart &&
        (Address >> 48U) == 0xFFFFU &&
        (Address & (sizeof(PVOID) - 1U)) == 0U;
#else
    return Address >= (ULONG_PTR)MmSystemRangeStart &&
        (Address & (sizeof(PVOID) - 1U)) == 0U;
#endif
}

static BOOLEAN
KswordARKObjectTypeOffsetPresent(
    _In_ ULONG Offset
    )
/*++

Routine Description:

    Rejects missing or implausibly large private structure offsets.

Return Value:

    TRUE for a bounded non-sentinel offset.

--*/
{
    return Offset != 0UL && Offset != 0xFFFFFFFFUL &&
        Offset < KSW_OBJECT_TYPE_MAX_STRUCT_OFFSET;
}

static ULONG64
KswordARKObjectTypeHashBytes(
    _In_ ULONG64 Hash,
    _In_reads_bytes_(ByteCount) const VOID* Data,
    _In_ SIZE_T ByteCount
    )
/*++

Routine Description:

    Extends a deterministic FNV-1a snapshot or row identity.

Return Value:

    Updated 64-bit hash.

--*/
{
    const UCHAR* bytes = (const UCHAR*)Data;
    SIZE_T index = 0U;

    for (index = 0U; index < ByteCount; ++index) {
        Hash ^= bytes[index];
        Hash *= KSW_OBJECT_TYPE_FNV_PRIME;
    }
    return Hash;
}

static BOOLEAN
KswordARKObjectTypeReadPointerSlot(
    _In_ ULONG_PTR TableAddress,
    _In_ ULONG SlotIndex,
    _Out_ ULONG_PTR* ObjectTypeAddressOut
    )
/*++

Routine Description:

    Reads one fixed ObTypeIndexTable pointer without dereferencing the object.

Return Value:

    TRUE when the slot was readable.

--*/
{
    if (ObjectTypeAddressOut == NULL ||
        SlotIndex >= KSWORD_ARK_OBJECT_TYPE_TABLE_MAX_SLOTS) {
        return FALSE;
    }
    *ObjectTypeAddressOut = 0U;
    return KswordARKRuntimeReadMemory(
        (const VOID*)(TableAddress + ((ULONG_PTR)SlotIndex * sizeof(PVOID))),
        ObjectTypeAddressOut,
        sizeof(*ObjectTypeAddressOut));
}

static ULONG
KswordARKObjectTypeKnownPointers(
    _Out_writes_(Capacity) ULONG_PTR* Pointers,
    _In_ ULONG Capacity
    )
/*++

Routine Description:

    Captures exported Object Manager type identities used only to authenticate
    a candidate table.

Return Value:

    Number of distinct non-null known POBJECT_TYPE values.

--*/
{
    POBJECT_TYPE* sources[] = {
        PsProcessType,
        PsThreadType,
        IoDriverObjectType,
        IoFileObjectType
    };
    ULONG sourceIndex = 0UL;
    ULONG count = 0UL;

    if (Pointers == NULL || Capacity == 0UL) {
        return 0UL;
    }
    for (sourceIndex = 0UL; sourceIndex < RTL_NUMBER_OF(sources); ++sourceIndex) {
        ULONG_PTR value = 0U;
        ULONG existingIndex = 0UL;
        BOOLEAN duplicate = FALSE;

        if (sources[sourceIndex] == NULL ||
            !KswordARKRuntimeReadMemory(
                sources[sourceIndex],
                &value,
                sizeof(value)) ||
            !KswordARKObjectTypeIsKernelPointer(value)) {
            continue;
        }
        for (existingIndex = 0UL; existingIndex < count; ++existingIndex) {
            if (Pointers[existingIndex] == value) {
                duplicate = TRUE;
                break;
            }
        }
        if (!duplicate && count < Capacity) {
            Pointers[count] = value;
            count += 1UL;
        }
    }
    return count;
}

static BOOLEAN
KswordARKObjectTypeValidateCandidate(
    _In_ const KSW_RUNTIME_IMAGE_VIEW* NtosView,
    _In_ ULONG_PTR CandidateAddress,
    _In_reads_(KnownCount) const ULONG_PTR* KnownPointers,
    _In_ ULONG KnownCount,
    _Out_ KSW_OBJECT_TYPE_TABLE_CANDIDATE* CandidateOut
    )
/*++

Routine Description:

    Requires a complete writable 256-slot array, canonical non-null entries,
    and at least three exported type identities present in the same table.

Return Value:

    TRUE only for a strongly authenticated table candidate.

--*/
{
    ULONG slot = 0UL;
    ULONG knownIndex = 0UL;
    ULONG knownMatches = 0UL;
    ULONG nonNullCount = 0UL;
    BOOLEAN knownSeen[4];

    if (CandidateOut == NULL || KnownPointers == NULL || KnownCount < 3UL ||
        KnownCount > RTL_NUMBER_OF(knownSeen) ||
        !KswordARKRuntimeAddressIsWritableData(
            NtosView,
            CandidateAddress,
            KSWORD_ARK_OBJECT_TYPE_TABLE_MAX_SLOTS * sizeof(PVOID))) {
        return FALSE;
    }
    RtlZeroMemory(knownSeen, sizeof(knownSeen));
    for (slot = 0UL; slot < KSWORD_ARK_OBJECT_TYPE_TABLE_MAX_SLOTS; ++slot) {
        ULONG_PTR objectTypeAddress = 0U;

        if (!KswordARKObjectTypeReadPointerSlot(
                CandidateAddress,
                slot,
                &objectTypeAddress)) {
            return FALSE;
        }
        if (objectTypeAddress == 0U) {
            continue;
        }
        if (!KswordARKObjectTypeIsKernelPointer(objectTypeAddress)) {
            return FALSE;
        }
        nonNullCount += 1UL;
        for (knownIndex = 0UL; knownIndex < KnownCount; ++knownIndex) {
            if (!knownSeen[knownIndex] &&
                KnownPointers[knownIndex] == objectTypeAddress) {
                knownSeen[knownIndex] = TRUE;
                knownMatches += 1UL;
            }
        }
    }
    if (knownMatches < 3UL || nonNullCount < knownMatches) {
        return FALSE;
    }
    CandidateOut->Address = CandidateAddress;
    CandidateOut->KnownMatchCount = knownMatches;
    CandidateOut->NonNullCount = nonNullCount;
    CandidateOut->Valid = TRUE;
    return TRUE;
}

static NTSTATUS
KswordARKObjectTypeLocateTable(
    _In_ const KSW_RUNTIME_IMAGE_VIEW* NtosView,
    _Out_ ULONG_PTR* TableAddressOut
    )
/*++

Routine Description:

    Locates ObTypeIndexTable from bounded RIP-relative references rooted at
    Object Manager exports and rejects tied strongest candidates.

Return Value:

    STATUS_SUCCESS for one unique table, STATUS_OBJECT_NAME_COLLISION for an
    ambiguity, or STATUS_NOT_FOUND when no candidate validates.

--*/
{
    static PCSTR const anchors[] = {
        "ObGetObjectType",
        "ObReferenceObjectByHandle",
        "ObOpenObjectByPointer"
    };
    KSW_RUNTIME_DATA_REFERENCE references[KSW_OBJECT_TYPE_MAX_REFERENCES];
    ULONG_PTR knownPointers[4];
    ULONG knownCount = 0UL;
    ULONG referenceCount = 0UL;
    ULONG referenceIndex = 0UL;
    KSW_OBJECT_TYPE_TABLE_CANDIDATE best;
    BOOLEAN ambiguous = FALSE;

    if (NtosView == NULL || TableAddressOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *TableAddressOut = 0U;
    RtlZeroMemory(references, sizeof(references));
    RtlZeroMemory(knownPointers, sizeof(knownPointers));
    RtlZeroMemory(&best, sizeof(best));
    knownCount = KswordARKObjectTypeKnownPointers(
        knownPointers,
        RTL_NUMBER_OF(knownPointers));
    if (knownCount < 3UL) {
        return STATUS_NOT_SUPPORTED;
    }
    referenceCount = KswordARKRuntimeCollectAnchoredDataReferences(
        NtosView,
        anchors,
        RTL_NUMBER_OF(anchors),
        KSW_OBJECT_TYPE_MAX_CALL_DEPTH,
        KSW_OBJECT_TYPE_SCAN_BYTES,
        references,
        RTL_NUMBER_OF(references));
    for (referenceIndex = 0UL; referenceIndex < referenceCount; ++referenceIndex) {
        KSW_OBJECT_TYPE_TABLE_CANDIDATE candidate;

        RtlZeroMemory(&candidate, sizeof(candidate));
        if (!KswordARKObjectTypeValidateCandidate(
                NtosView,
                references[referenceIndex].Address,
                knownPointers,
                knownCount,
                &candidate)) {
            continue;
        }
        if (!best.Valid ||
            candidate.KnownMatchCount > best.KnownMatchCount) {
            best = candidate;
            ambiguous = FALSE;
        }
        else if (candidate.KnownMatchCount == best.KnownMatchCount &&
            candidate.Address != best.Address) {
            ambiguous = TRUE;
        }
    }
    if (!best.Valid) {
        return STATUS_NOT_FOUND;
    }
    if (ambiguous) {
        return STATUS_OBJECT_NAME_COLLISION;
    }
    *TableAddressOut = best.Address;
    return STATUS_SUCCESS;
}

static BOOLEAN
KswordARKObjectTypeReadName(
    _In_ ULONG_PTR ObjectTypeAddress,
    _In_ ULONG NameOffset,
    _Out_writes_(DestinationChars) PWCHAR Destination,
    _In_ ULONG DestinationChars
    )
/*++

Routine Description:

    Copies a DynData-gated _OBJECT_TYPE.Name into a fixed response buffer.

Return Value:

    TRUE only when the UNICODE_STRING and complete bounded payload are valid.

--*/
{
    UNICODE_STRING name;
    USHORT copyBytes = 0U;

    if (Destination == NULL || DestinationChars < 2UL ||
        !KswordARKObjectTypeOffsetPresent(NameOffset)) {
        return FALSE;
    }
    RtlZeroMemory(Destination, (SIZE_T)DestinationChars * sizeof(WCHAR));
    RtlZeroMemory(&name, sizeof(name));
    if (!KswordARKRuntimeReadMemory(
            (const VOID*)(ObjectTypeAddress + NameOffset),
            &name,
            sizeof(name)) ||
        name.Buffer == NULL || name.Length == 0U ||
        name.Length > name.MaximumLength ||
        (name.Length & (sizeof(WCHAR) - 1U)) != 0U ||
        !KswordARKObjectTypeIsKernelPointer((ULONG_PTR)name.Buffer)) {
        return FALSE;
    }
    copyBytes = (USHORT)min(
        name.Length,
        (USHORT)((DestinationChars - 1UL) * sizeof(WCHAR)));
    if (!KswordARKRuntimeReadMemory(name.Buffer, Destination, copyBytes)) {
        RtlZeroMemory(Destination, (SIZE_T)DestinationChars * sizeof(WCHAR));
        return FALSE;
    }
    Destination[copyBytes / sizeof(WCHAR)] = L'\0';
    return TRUE;
}

static BOOLEAN
KswordARKObjectTypeReadNamespaceName(
    _In_ ULONG_PTR ObjectTypeAddress,
    _Out_writes_(DestinationChars) PWCHAR Destination,
    _In_ ULONG DestinationChars
    )
/*++

Routine Description:

    Query the Object Manager name of an OBJECT_TYPE object and retain the last
    path component (for example, "Process" from "\ObjectTypes\Process").
    This provides names without the private _OBJECT_TYPE.Name member offset.

Return Value:

    TRUE only when a complete bounded name was copied.

--*/
{
    POBJECT_NAME_INFORMATION nameInfo = NULL;
    ULONG requiredBytes = 0UL;
    ULONG allocationBytes = 0UL;
    ULONG sourceChars = 0UL;
    ULONG startChar = 0UL;
    ULONG copyChars = 0UL;
    ULONG index = 0UL;
    NTSTATUS status = STATUS_SUCCESS;

    if (ObjectTypeAddress == 0U || Destination == NULL ||
        DestinationChars < 2UL) {
        return FALSE;
    }
    RtlZeroMemory(Destination, (SIZE_T)DestinationChars * sizeof(WCHAR));
    status = ObQueryNameString(
        (PVOID)ObjectTypeAddress,
        NULL,
        0UL,
        &requiredBytes);
    if (status != STATUS_INFO_LENGTH_MISMATCH &&
        status != STATUS_BUFFER_TOO_SMALL &&
        status != STATUS_BUFFER_OVERFLOW) {
        return FALSE;
    }
    allocationBytes = max(
        requiredBytes,
        (ULONG)(sizeof(OBJECT_NAME_INFORMATION) + sizeof(WCHAR)));
    if (allocationBytes > 64UL * 1024UL) {
        return FALSE;
    }
    nameInfo = (POBJECT_NAME_INFORMATION)KswordARKAllocateNonPagedPool(
        allocationBytes,
        KSW_OBJECT_TYPE_NAME_POOL_TAG);
    if (nameInfo == NULL) {
        return FALSE;
    }
    RtlZeroMemory(nameInfo, allocationBytes);
    status = ObQueryNameString(
        (PVOID)ObjectTypeAddress,
        nameInfo,
        allocationBytes,
        &requiredBytes);
    if (NT_SUCCESS(status) && nameInfo->Name.Buffer != NULL &&
        nameInfo->Name.Length != 0U &&
        nameInfo->Name.Length <= nameInfo->Name.MaximumLength &&
        (nameInfo->Name.Length & (sizeof(WCHAR) - 1U)) == 0U) {
        sourceChars = nameInfo->Name.Length / sizeof(WCHAR);
        for (index = 0UL; index < sourceChars; ++index) {
            if (nameInfo->Name.Buffer[index] == L'\\') {
                startChar = index + 1UL;
            }
        }
        if (startChar < sourceChars) {
            copyChars = min(sourceChars - startChar, DestinationChars - 1UL);
            RtlCopyMemory(
                Destination,
                &nameInfo->Name.Buffer[startChar],
                (SIZE_T)copyChars * sizeof(WCHAR));
            Destination[copyChars] = L'\0';
        }
    }
    ExFreePoolWithTag(nameInfo, KSW_OBJECT_TYPE_NAME_POOL_TAG);
    return copyChars != 0UL;
}

static BOOLEAN
KswordARKObjectTypeReadIndex(
    _In_ ULONG_PTR ObjectTypeAddress,
    _In_ ULONG IndexOffset,
    _Out_ UCHAR* TypeIndexOut
    )
/*++

Routine Description:

    Reads the DynData-gated _OBJECT_TYPE.Index byte.

Return Value:

    TRUE when the member is available and readable.

--*/
{
    if (TypeIndexOut == NULL ||
        !KswordARKObjectTypeOffsetPresent(IndexOffset)) {
        return FALSE;
    }
    *TypeIndexOut = 0U;
    return KswordARKRuntimeReadMemory(
        (const VOID*)(ObjectTypeAddress + IndexOffset),
        TypeIndexOut,
        sizeof(*TypeIndexOut));
}

static BOOLEAN
KswordARKObjectTypeIsKnown(
    _In_ ULONG_PTR ObjectTypeAddress
    )
/*++

Routine Description:

    Compares one row against exported process/thread/driver/file type objects.

Return Value:

    TRUE for an exported known identity.

--*/
{
    ULONG_PTR knownPointers[4];
    ULONG knownCount = 0UL;
    ULONG index = 0UL;

    RtlZeroMemory(knownPointers, sizeof(knownPointers));
    knownCount = KswordARKObjectTypeKnownPointers(
        knownPointers,
        RTL_NUMBER_OF(knownPointers));
    for (index = 0UL; index < knownCount; ++index) {
        if (knownPointers[index] == ObjectTypeAddress) {
            return TRUE;
        }
    }
    return FALSE;
}

static NTSTATUS
KswordARKObjectTypeBuildResponse(
    _Out_writes_bytes_to_(OutputBufferLength, *BytesWrittenOut) PVOID OutputBuffer,
    _In_ size_t OutputBufferLength,
    _In_ const KSWORD_ARK_ENUM_OBJECT_TYPE_TABLE_REQUEST* Request,
    _Out_ size_t* BytesWrittenOut
    )
/*++

Routine Description:

    Builds one paged, read-only Object Type Table response.

Return Value:

    STATUS_SUCCESS for a semantic response; malformed buffers return an error.

--*/
{
    KSWORD_ARK_ENUM_OBJECT_TYPE_TABLE_RESPONSE* response =
        (KSWORD_ARK_ENUM_OBJECT_TYPE_TABLE_RESPONSE*)OutputBuffer;
    KSWORD_ARK_OBJECT_TYPE_TABLE_ENTRY* rows = NULL;
    KSW_DYN_STATE dynState;
    KSW_RUNTIME_IMAGE_VIEW ntosView;
    ULONG_PTR tableAddress = 0U;
    NTSTATUS locateStatus = STATUS_SUCCESS;
    ULONG capacity = 0UL;
    ULONG requestedMax = 0UL;
    ULONG startIndex = 0UL;
    ULONG slot = 0UL;
    ULONG nextIndex = KSWORD_ARK_OBJECT_TYPE_TABLE_MAX_SLOTS;
    BOOLEAN dynName = FALSE;
    BOOLEAN dynIndex = FALSE;
    BOOLEAN partial = FALSE;
    ULONG64 snapshotHash = KSW_OBJECT_TYPE_FNV_OFFSET_BASIS;

    if (OutputBuffer == NULL || Request == NULL || BytesWrittenOut == NULL ||
        OutputBufferLength < KSW_OBJECT_TYPE_RESPONSE_HEADER_SIZE) {
        return STATUS_BUFFER_TOO_SMALL;
    }
    *BytesWrittenOut = 0U;
    RtlZeroMemory(OutputBuffer, OutputBufferLength);
    RtlZeroMemory(&dynState, sizeof(dynState));
    RtlZeroMemory(&ntosView, sizeof(ntosView));
    response->version = KSWORD_ARK_KERNEL_OBJECT_PROTOCOL_VERSION;
    response->entrySize = sizeof(KSWORD_ARK_OBJECT_TYPE_TABLE_ENTRY);
    response->status = KSWORD_ARK_OBJECT_TYPE_TABLE_STATUS_UNAVAILABLE;
    response->nextIndex = KSWORD_ARK_OBJECT_TYPE_TABLE_MAX_SLOTS;
    capacity = (ULONG)((OutputBufferLength - KSW_OBJECT_TYPE_RESPONSE_HEADER_SIZE) /
        sizeof(KSWORD_ARK_OBJECT_TYPE_TABLE_ENTRY));
    requestedMax = Request->maxEntries == 0UL
        ? KSWORD_ARK_OBJECT_TYPE_TABLE_MAX_SLOTS
        : min(Request->maxEntries, KSWORD_ARK_OBJECT_TYPE_TABLE_MAX_SLOTS);
    capacity = min(capacity, requestedMax);
    startIndex = min(Request->startIndex, KSWORD_ARK_OBJECT_TYPE_TABLE_MAX_SLOTS);
    rows = response->entries;

    KswordARKDynDataSnapshot(&dynState);
    response->dynDataCapabilityMask = dynState.CapabilityMask;
    response->otNameOffset = dynState.Kernel.OtName;
    response->otIndexOffset = dynState.Kernel.OtIndex;
    dynName = KswordARKObjectTypeOffsetPresent(dynState.Kernel.OtName);
    dynIndex = KswordARKObjectTypeOffsetPresent(dynState.Kernel.OtIndex);
    if (dynName || dynIndex) {
        response->flags |=
            KSWORD_ARK_OBJECT_TYPE_TABLE_RESPONSE_FLAG_DYNDATA_ACTIVE;
    }
    if (dynState.Ntoskrnl.present == 0UL ||
        !KswordARKRuntimeInitializeImageView(
            (PVOID)(ULONG_PTR)dynState.Ntoskrnl.imageBase,
            dynState.Ntoskrnl.sizeOfImage,
            &ntosView)) {
        response->status = KSWORD_ARK_OBJECT_TYPE_TABLE_STATUS_TABLE_NOT_FOUND;
        response->lastStatus = STATUS_NOT_SUPPORTED;
        *BytesWrittenOut = KSW_OBJECT_TYPE_RESPONSE_HEADER_SIZE;
        return STATUS_SUCCESS;
    }
    locateStatus = KswordARKObjectTypeLocateTable(&ntosView, &tableAddress);
    if (!NT_SUCCESS(locateStatus)) {
        response->status = (locateStatus == STATUS_OBJECT_NAME_COLLISION)
            ? KSWORD_ARK_OBJECT_TYPE_TABLE_STATUS_TABLE_AMBIGUOUS
            : KSWORD_ARK_OBJECT_TYPE_TABLE_STATUS_TABLE_NOT_FOUND;
        response->lastStatus = locateStatus;
        *BytesWrittenOut = KSW_OBJECT_TYPE_RESPONSE_HEADER_SIZE;
        return STATUS_SUCCESS;
    }
    response->tableAddress = (ULONG64)tableAddress;
    response->flags |=
        KSWORD_ARK_OBJECT_TYPE_TABLE_RESPONSE_FLAG_TABLE_VALIDATED;

    for (slot = 0UL; slot < KSWORD_ARK_OBJECT_TYPE_TABLE_MAX_SLOTS; ++slot) {
        ULONG_PTR objectTypeAddress = 0U;

        if (!KswordARKObjectTypeReadPointerSlot(
                tableAddress,
                slot,
                &objectTypeAddress)) {
            partial = TRUE;
            continue;
        }
        if (objectTypeAddress == 0U) {
            continue;
        }
        response->totalCount += 1UL;
        snapshotHash = KswordARKObjectTypeHashBytes(
            snapshotHash,
            &slot,
            sizeof(slot));
        snapshotHash = KswordARKObjectTypeHashBytes(
            snapshotHash,
            &objectTypeAddress,
            sizeof(objectTypeAddress));
        if (slot < startIndex || response->returnedCount >= capacity) {
            if (slot >= startIndex && nextIndex == KSWORD_ARK_OBJECT_TYPE_TABLE_MAX_SLOTS) {
                nextIndex = slot;
            }
            continue;
        }
        {
            KSWORD_ARK_OBJECT_TYPE_TABLE_ENTRY* entry =
                &rows[response->returnedCount];
            UCHAR observedIndex = 0U;
            BOOLEAN nameRead = FALSE;
            BOOLEAN indexRead = FALSE;

            entry->size = sizeof(*entry);
            entry->typeIndex = slot;
            entry->status = KSWORD_ARK_OBJECT_TYPE_ENTRY_STATUS_OK;
            entry->fieldFlags = KSWORD_ARK_OBJECT_TYPE_ENTRY_FIELD_ADDRESS;
            entry->objectTypeAddress = (ULONG64)objectTypeAddress;
            if (KswordARKObjectTypeIsKnown(objectTypeAddress)) {
                entry->fieldFlags |=
                    KSWORD_ARK_OBJECT_TYPE_ENTRY_FIELD_KNOWN_TYPE;
            }
            if ((Request->flags &
                    KSWORD_ARK_OBJECT_TYPE_TABLE_FLAG_INCLUDE_NAMES) != 0UL &&
                dynName) {
                nameRead = KswordARKObjectTypeReadName(
                    objectTypeAddress,
                    dynState.Kernel.OtName,
                    entry->typeName,
                    RTL_NUMBER_OF(entry->typeName));
                if (nameRead) {
                    entry->fieldFlags |=
                        KSWORD_ARK_OBJECT_TYPE_ENTRY_FIELD_NAME;
                }
            }
            if ((Request->flags &
                    KSWORD_ARK_OBJECT_TYPE_TABLE_FLAG_INCLUDE_NAMES) != 0UL &&
                !nameRead) {
                nameRead = KswordARKObjectTypeReadNamespaceName(
                    objectTypeAddress,
                    entry->typeName,
                    RTL_NUMBER_OF(entry->typeName));
                if (nameRead) {
                    entry->fieldFlags |=
                        KSWORD_ARK_OBJECT_TYPE_ENTRY_FIELD_NAME;
                    response->flags |=
                        KSWORD_ARK_OBJECT_TYPE_TABLE_RESPONSE_FLAG_NAMESPACE_NAMES;
                }
            }
            if ((Request->flags &
                    KSWORD_ARK_OBJECT_TYPE_TABLE_FLAG_VALIDATE_INDEX) != 0UL &&
                dynIndex) {
                indexRead = KswordARKObjectTypeReadIndex(
                    objectTypeAddress,
                    dynState.Kernel.OtIndex,
                    &observedIndex);
                if (indexRead) {
                    entry->fieldFlags |=
                        KSWORD_ARK_OBJECT_TYPE_ENTRY_FIELD_INDEX;
                    if ((ULONG)observedIndex == slot) {
                        entry->fieldFlags |=
                            KSWORD_ARK_OBJECT_TYPE_ENTRY_FIELD_INDEX_MATCH;
                    }
                    else {
                        entry->status =
                            KSWORD_ARK_OBJECT_TYPE_ENTRY_STATUS_INDEX_MISMATCH;
                        entry->lastStatus = STATUS_DATA_ERROR;
                        partial = TRUE;
                    }
                }
            }
            if (((Request->flags &
                    KSWORD_ARK_OBJECT_TYPE_TABLE_FLAG_INCLUDE_NAMES) != 0UL &&
                    !nameRead) ||
                ((Request->flags &
                    KSWORD_ARK_OBJECT_TYPE_TABLE_FLAG_VALIDATE_INDEX) != 0UL &&
                    !indexRead)) {
                if (entry->status == KSWORD_ARK_OBJECT_TYPE_ENTRY_STATUS_OK) {
                    entry->status = KSWORD_ARK_OBJECT_TYPE_ENTRY_STATUS_PARTIAL;
                }
                partial = TRUE;
            }
            entry->identityHash = KswordARKObjectTypeHashBytes(
                KSW_OBJECT_TYPE_FNV_OFFSET_BASIS,
                &entry->typeIndex,
                sizeof(entry->typeIndex));
            entry->identityHash = KswordARKObjectTypeHashBytes(
                entry->identityHash,
                &entry->objectTypeAddress,
                sizeof(entry->objectTypeAddress));
            entry->fieldFlags |=
                KSWORD_ARK_OBJECT_TYPE_ENTRY_FIELD_IDENTITY_HASH;
            response->returnedCount += 1UL;
        }
    }
    response->snapshotHash = snapshotHash;
    response->flags |=
        KSWORD_ARK_OBJECT_TYPE_TABLE_RESPONSE_FLAG_SNAPSHOT_HASH_VALID;
    response->nextIndex = nextIndex;
    if (nextIndex < KSWORD_ARK_OBJECT_TYPE_TABLE_MAX_SLOTS) {
        response->flags |=
            KSWORD_ARK_OBJECT_TYPE_TABLE_RESPONSE_FLAG_TRUNCATED;
        response->status =
            KSWORD_ARK_OBJECT_TYPE_TABLE_STATUS_BUFFER_TRUNCATED;
        response->lastStatus = STATUS_BUFFER_OVERFLOW;
    }
    else if (partial ||
        (((Request->flags &
            KSWORD_ARK_OBJECT_TYPE_TABLE_FLAG_VALIDATE_INDEX) != 0UL) &&
            !dynIndex)) {
        response->status = KSWORD_ARK_OBJECT_TYPE_TABLE_STATUS_PARTIAL;
        response->lastStatus = partial ? STATUS_PARTIAL_COPY : STATUS_NOT_SUPPORTED;
    }
    else {
        response->status = KSWORD_ARK_OBJECT_TYPE_TABLE_STATUS_OK;
        response->lastStatus = STATUS_SUCCESS;
    }
    *BytesWrittenOut = KSW_OBJECT_TYPE_RESPONSE_HEADER_SIZE +
        ((size_t)response->returnedCount *
            sizeof(KSWORD_ARK_OBJECT_TYPE_TABLE_ENTRY));
    return STATUS_SUCCESS;
}

NTSTATUS
KswordARKKernelObjectIoctlEnumTypeTable(
    _In_ WDFDEVICE Device,
    _In_ WDFREQUEST Request,
    _In_ size_t InputBufferLength,
    _In_ size_t OutputBufferLength,
    _Out_ size_t* BytesReturned
    )
/*++

Routine Description:

    Validates and dispatches IOCTL_KSWORD_ARK_ENUM_OBJECT_TYPE_TABLE.

Return Value:

    WDF buffer validation or response-builder status.

--*/
{
    KSWORD_ARK_ENUM_OBJECT_TYPE_TABLE_REQUEST* queryRequest = NULL;
    PVOID outputBuffer = NULL;
    size_t actualInputLength = 0U;
    size_t actualOutputLength = 0U;
    NTSTATUS status = STATUS_SUCCESS;

    UNREFERENCED_PARAMETER(Device);
    if (BytesReturned == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *BytesReturned = 0U;
    if (InputBufferLength < sizeof(*queryRequest) ||
        OutputBufferLength < KSW_OBJECT_TYPE_RESPONSE_HEADER_SIZE) {
        return STATUS_BUFFER_TOO_SMALL;
    }
    status = WdfRequestRetrieveInputBuffer(
        Request,
        sizeof(*queryRequest),
        (PVOID*)&queryRequest,
        &actualInputLength);
    if (!NT_SUCCESS(status) || actualInputLength < sizeof(*queryRequest)) {
        return NT_SUCCESS(status) ? STATUS_BUFFER_TOO_SMALL : status;
    }
    if (queryRequest->version != KSWORD_ARK_KERNEL_OBJECT_PROTOCOL_VERSION ||
        (queryRequest->flags &
            (~KSWORD_ARK_OBJECT_TYPE_TABLE_FLAG_INCLUDE_ALL)) != 0UL) {
        return STATUS_INVALID_PARAMETER;
    }
    status = KswordARKRetrieveRequiredOutputBuffer(
        Request,
        KSW_OBJECT_TYPE_RESPONSE_HEADER_SIZE,
        &outputBuffer,
        &actualOutputLength);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    return KswordARKObjectTypeBuildResponse(
        outputBuffer,
        actualOutputLength,
        queryRequest,
        BytesReturned);
}
