/*++

Module Name:

    dyndata_fallback_resolver.c

Abstract:

    This file recovers kernel layouts that previously required an exact PDB
    profile. It starts from public WDK layouts or an ntoskrnl export and then
    validates every private KLDR offset against the live KSword driver entry.

Environment:

    Kernel-mode Driver Framework

--*/

#include <ntifs.h>
#include "dyndata_fallback_resolver.h"
#include "kernel_cache_fallback.h"
#include "../features/kernel/ssdt_fallback.h"

#define KSW_RUNTIME_KLDR_SCAN_BYTES 0x0100U
#define KSW_RUNTIME_KLDR_WALK_BUDGET 0x1000U
#define KSW_RUNTIME_KLDR_NAME_CHARS 0x0200U

NTSYSAPI
PVOID
NTAPI
RtlFindExportedRoutineByName(
    _In_ PVOID ImageBase,
    _In_ PCCH RoutineName
    );

static VOID
KswordARKDriverInitializeKernelFallbackLayout(
    _Out_ PKSW_RUNTIME_KERNEL_LAYOUT Layout
    )
/*++

Routine Description:

    Initialize every signed fallback result to the unavailable sentinel.

Arguments:

    Layout - Output scalar layout.

Return Value:

    None.

--*/
{
    LONG* field = NULL;
    SIZE_T index = 0U;

    if (Layout == NULL) {
        return;
    }
    field = (LONG*)Layout;
    for (index = 0U; index < sizeof(*Layout) / sizeof(*field); ++index) {
        field[index] = -1;
    }
}

static BOOLEAN
KswordARKDriverFallbackReadMemory(
    _In_ const VOID* Address,
    _Out_writes_bytes_(Size) VOID* Buffer,
    _In_ SIZE_T Size
    )
/*++

Routine Description:

    Copy a small kernel-memory scalar or structure through an exception boundary.

Arguments:

    Address - Candidate source address.
    Buffer - Caller-owned output buffer.
    Size - Exact bounded byte count.

Return Value:

    TRUE when the complete read succeeded; otherwise FALSE.

--*/
{
    if (Address == NULL || Buffer == NULL || Size == 0U) {
        return FALSE;
    }
    __try {
        RtlCopyMemory(Buffer, Address, Size);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return FALSE;
    }
    return TRUE;
}

static BOOLEAN
KswordARKDriverFallbackAddressInImage(
    _In_ ULONG_PTR Address,
    _In_ const KSW_DYN_MODULE_IDENTITY_PACKET* Identity,
    _In_ SIZE_T RequiredBytes
    )
/*++

Routine Description:

    Check that an address range is contained by the identity-matched ntoskrnl image.

Arguments:

    Address - Candidate virtual address.
    Identity - Current loaded ntoskrnl identity.
    RequiredBytes - Minimum contained byte count.

Return Value:

    TRUE when the full range is inside the non-wrapping image interval.

--*/
{
    ULONG_PTR imageBase = 0U;
    ULONG_PTR imageEnd = 0U;

    if (Identity == NULL || Identity->present == 0UL ||
        Identity->imageBase == 0ULL || Identity->sizeOfImage == 0UL) {
        return FALSE;
    }
    imageBase = (ULONG_PTR)Identity->imageBase;
    if (imageBase > MAXULONG_PTR - Identity->sizeOfImage) {
        return FALSE;
    }
    imageEnd = imageBase + Identity->sizeOfImage;
    if (Address < imageBase || Address >= imageEnd || RequiredBytes > imageEnd - Address) {
        return FALSE;
    }
    return TRUE;
}

static PLIST_ENTRY
KswordARKDriverResolveLoadedModuleListExport(
    _In_ const KSW_DYN_MODULE_IDENTITY_PACKET* Identity,
    _Out_ LONG* RvaOut
    )
/*++

Routine Description:

    Resolve the exported PsLoadedModuleList data address and validate its
    reciprocal list-head links. The export identity is stronger than a broad
    image signature and remains fully offline.

Arguments:

    Identity - Current loaded ntoskrnl identity.
    RvaOut - Receives the non-negative image RVA when validated.

Return Value:

    Validated list-head address or NULL.

--*/
{
    PLIST_ENTRY listHead = NULL;
    LIST_ENTRY headSnapshot;
    LIST_ENTRY firstSnapshot;
    LIST_ENTRY lastSnapshot;
    ULONG_PTR imageBase = 0U;
    ULONG_PTR address = 0U;

    if (RvaOut == NULL) {
        return NULL;
    }
    *RvaOut = -1;
    if (Identity == NULL || Identity->imageBase == 0ULL) {
        return NULL;
    }
    imageBase = (ULONG_PTR)Identity->imageBase;
    listHead = (PLIST_ENTRY)RtlFindExportedRoutineByName(
        (PVOID)imageBase,
        "PsLoadedModuleList");
    address = (ULONG_PTR)listHead;
    if (listHead == NULL ||
        !KswordARKDriverFallbackAddressInImage(address, Identity, sizeof(*listHead)) ||
        !KswordARKDriverFallbackReadMemory(listHead, &headSnapshot, sizeof(headSnapshot)) ||
        headSnapshot.Flink == NULL || headSnapshot.Blink == NULL ||
        !KswordARKDriverFallbackReadMemory(headSnapshot.Flink, &firstSnapshot, sizeof(firstSnapshot)) ||
        !KswordARKDriverFallbackReadMemory(headSnapshot.Blink, &lastSnapshot, sizeof(lastSnapshot)) ||
        firstSnapshot.Blink != listHead || lastSnapshot.Flink != listHead ||
        address - imageBase > MAXLONG) {
        return NULL;
    }
    *RvaOut = (LONG)(address - imageBase);
    return listHead;
}

static BOOLEAN
KswordARKDriverValidateKldrListOffset(
    _In_ const UCHAR* DriverSection,
    _In_ ULONG CandidateOffset,
    _In_ const LIST_ENTRY* LoadedModuleListHead
    )
/*++

Routine Description:

    Walk a candidate KLDR list entry until it reaches PsLoadedModuleList.
    Reciprocal links are checked at every step and the walk is strictly bounded.

Arguments:

    DriverSection - Live KLDR entry stored in DRIVER_OBJECT.DriverSection.
    CandidateOffset - Candidate embedded LIST_ENTRY offset.
    LoadedModuleListHead - Validated exported list head.

Return Value:

    TRUE when the candidate belongs to the exported loaded-module list.

--*/
{
    ULONG_PTR currentAddress = (ULONG_PTR)DriverSection + CandidateOffset;
    LIST_ENTRY currentEntry;
    ULONG step = 0UL;

    if (DriverSection == NULL || LoadedModuleListHead == NULL ||
        !KswordARKDriverFallbackReadMemory(
            (const VOID*)currentAddress,
            &currentEntry,
            sizeof(currentEntry))) {
        return FALSE;
    }

    for (step = 0UL; step < KSW_RUNTIME_KLDR_WALK_BUDGET; ++step) {
        ULONG_PTR nextAddress = (ULONG_PTR)currentEntry.Flink;
        LIST_ENTRY nextEntry;

        if (nextAddress == (ULONG_PTR)LoadedModuleListHead) {
            if (!KswordARKDriverFallbackReadMemory(
                    LoadedModuleListHead,
                    &nextEntry,
                    sizeof(nextEntry)) ||
                (ULONG_PTR)nextEntry.Blink != currentAddress) {
                return FALSE;
            }
            return TRUE;
        }
        if (nextAddress == 0U ||
            !KswordARKDriverFallbackReadMemory(
                (const VOID*)nextAddress,
                &nextEntry,
                sizeof(nextEntry)) ||
            (ULONG_PTR)nextEntry.Blink != currentAddress) {
            return FALSE;
        }
        currentAddress = nextAddress;
        currentEntry = nextEntry;
    }
    return FALSE;
}

static LONG
KswordARKDriverResolveUniqueKldrListOffset(
    _In_ const UCHAR* DriverSection,
    _In_ const LIST_ENTRY* LoadedModuleListHead
    )
/*++

Routine Description:

    Find the unique embedded KLDR list entry that reaches PsLoadedModuleList.

Arguments:

    DriverSection - Live validation entry.
    LoadedModuleListHead - Validated exported list head.

Return Value:

    Non-negative unique offset or -1.

--*/
{
    ULONG offset = 0UL;
    LONG foundOffset = -1;

    for (offset = 0UL;
         offset + sizeof(LIST_ENTRY) <= KSW_RUNTIME_KLDR_SCAN_BYTES;
         offset += (ULONG)sizeof(PVOID)) {
        if (!KswordARKDriverValidateKldrListOffset(
                DriverSection,
                offset,
                LoadedModuleListHead)) {
            continue;
        }
        if (foundOffset >= 0) {
            return -1;
        }
        foundOffset = (LONG)offset;
    }
    return foundOffset;
}

static LONG
KswordARKDriverResolveUniquePointerField(
    _In_reads_bytes_(KSW_RUNTIME_KLDR_SCAN_BYTES) const UCHAR* Object,
    _In_ ULONG_PTR ExpectedValue
    )
/*++

Routine Description:

    Find one unique pointer-sized field equal to a trusted live value.

Arguments:

    Object - Bounded object body.
    ExpectedValue - Trusted pointer value expected in the object.

Return Value:

    Non-negative unique offset or -1.

--*/
{
    ULONG offset = 0UL;
    LONG foundOffset = -1;

    if (Object == NULL || ExpectedValue == 0U) {
        return -1;
    }
    for (offset = 0UL;
         offset + sizeof(ULONG_PTR) <= KSW_RUNTIME_KLDR_SCAN_BYTES;
         offset += (ULONG)sizeof(PVOID)) {
        ULONG_PTR value = 0U;

        if (!KswordARKDriverFallbackReadMemory(Object + offset, &value, sizeof(value)) ||
            value != ExpectedValue) {
            continue;
        }
        if (foundOffset >= 0) {
            return -1;
        }
        foundOffset = (LONG)offset;
    }
    return foundOffset;
}

static LONG
KswordARKDriverResolveKldrSizeField(
    _In_reads_bytes_(KSW_RUNTIME_KLDR_SCAN_BYTES) const UCHAR* DriverSection,
    _In_ LONG DllBaseOffset,
    _In_ ULONG ExpectedSize
    )
/*++

Routine Description:

    Find the unique image-size scalar immediately following the validated DllBase field.

Arguments:

    DriverSection - Live KLDR entry.
    DllBaseOffset - Previously validated DllBase field offset.
    ExpectedSize - DRIVER_OBJECT.DriverSize value.

Return Value:

    Non-negative unique offset or -1.

--*/
{
    ULONG startOffset = 0UL;
    ULONG endOffset = 0UL;
    ULONG offset = 0UL;
    LONG foundOffset = -1;

    if (DriverSection == NULL || DllBaseOffset < 0 || ExpectedSize == 0UL) {
        return -1;
    }
    startOffset = (ULONG)DllBaseOffset + (ULONG)sizeof(PVOID);
    endOffset = startOffset + 0x20UL;
    if (endOffset > KSW_RUNTIME_KLDR_SCAN_BYTES - sizeof(ULONG)) {
        endOffset = KSW_RUNTIME_KLDR_SCAN_BYTES - sizeof(ULONG);
    }
    for (offset = startOffset; offset <= endOffset; offset += sizeof(ULONG)) {
        ULONG value = 0UL;

        if (!KswordARKDriverFallbackReadMemory(DriverSection + offset, &value, sizeof(value)) ||
            value != ExpectedSize) {
            continue;
        }
        if (foundOffset >= 0) {
            return -1;
        }
        foundOffset = (LONG)offset;
    }
    return foundOffset;
}

static BOOLEAN
KswordARKDriverReadKldrUnicodeString(
    _In_ const UCHAR* DriverSection,
    _In_ ULONG Offset,
    _Out_ UNICODE_STRING* StringOut
    )
/*++

Routine Description:

    Read and bound one candidate KLDR UNICODE_STRING descriptor.

Arguments:

    DriverSection - Live KLDR entry.
    Offset - Candidate descriptor offset.
    StringOut - Receives the validated descriptor.

Return Value:

    TRUE when lengths and backing storage are readable and bounded.

--*/
{
    WCHAR probe = L'\0';

    if (DriverSection == NULL || StringOut == NULL ||
        Offset + sizeof(*StringOut) > KSW_RUNTIME_KLDR_SCAN_BYTES) {
        return FALSE;
    }
    RtlZeroMemory(StringOut, sizeof(*StringOut));
    if (!KswordARKDriverFallbackReadMemory(
            DriverSection + Offset,
            StringOut,
            sizeof(*StringOut)) ||
        StringOut->Buffer == NULL || StringOut->Length == 0U ||
        (StringOut->Length & 1U) != 0U ||
        StringOut->MaximumLength < StringOut->Length ||
        StringOut->MaximumLength > KSW_RUNTIME_KLDR_NAME_CHARS * sizeof(WCHAR) ||
        !KswordARKDriverFallbackReadMemory(StringOut->Buffer, &probe, sizeof(probe)) ||
        !KswordARKDriverFallbackReadMemory(
            (const UCHAR*)StringOut->Buffer + StringOut->Length - sizeof(WCHAR),
            &probe,
            sizeof(probe))) {
        RtlZeroMemory(StringOut, sizeof(*StringOut));
        return FALSE;
    }
    return TRUE;
}

static BOOLEAN
KswordARKDriverKldrNamesMatch(
    _In_ const UNICODE_STRING* FullName,
    _In_ const UNICODE_STRING* BaseName
    )
/*++

Routine Description:

    Verify that BaseName is a path-free, case-insensitive suffix of FullName.

Arguments:

    FullName - Candidate full module path.
    BaseName - Candidate base module name.

Return Value:

    TRUE when the relationship and both backing buffers validate.

--*/
{
    UNICODE_STRING suffix;
    USHORT index = 0U;
    BOOLEAN fullHasSeparator = FALSE;

    if (FullName == NULL || BaseName == NULL ||
        FullName->Length <= BaseName->Length || BaseName->Length < 4U) {
        return FALSE;
    }
    __try {
        for (index = 0U; index < FullName->Length / sizeof(WCHAR); ++index) {
            if (FullName->Buffer[index] == L'\\' || FullName->Buffer[index] == L'/') {
                fullHasSeparator = TRUE;
                break;
            }
        }
        for (index = 0U; index < BaseName->Length / sizeof(WCHAR); ++index) {
            if (BaseName->Buffer[index] == L'\\' || BaseName->Buffer[index] == L'/') {
                return FALSE;
            }
        }
        suffix.Length = BaseName->Length;
        suffix.MaximumLength = BaseName->Length;
        suffix.Buffer = FullName->Buffer +
            ((FullName->Length - BaseName->Length) / sizeof(WCHAR));
        return (fullHasSeparator && RtlEqualUnicodeString(&suffix, BaseName, TRUE))
            ? TRUE
            : FALSE;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return FALSE;
    }
}

static VOID
KswordARKDriverResolveKldrNameOffsets(
    _In_ const UCHAR* DriverSection,
    _Out_ LONG* FullNameOffsetOut,
    _Out_ LONG* BaseNameOffsetOut
    )
/*++

Routine Description:

    Find a unique full-path/base-name UNICODE_STRING pair in a live KLDR entry.

Arguments:

    DriverSection - Live validation entry.
    FullNameOffsetOut - Receives the full-name descriptor offset.
    BaseNameOffsetOut - Receives the base-name descriptor offset.

Return Value:

    None. Both outputs remain unavailable unless exactly one pair validates.

--*/
{
    ULONG fullOffset = 0UL;
    LONG foundFullOffset = -1;
    LONG foundBaseOffset = -1;

    if (FullNameOffsetOut == NULL || BaseNameOffsetOut == NULL) {
        return;
    }
    *FullNameOffsetOut = -1;
    *BaseNameOffsetOut = -1;

    for (fullOffset = 0UL;
         fullOffset + sizeof(UNICODE_STRING) <= KSW_RUNTIME_KLDR_SCAN_BYTES;
         fullOffset += (ULONG)sizeof(PVOID)) {
        UNICODE_STRING fullName;
        ULONG baseOffset = 0UL;

        if (!KswordARKDriverReadKldrUnicodeString(DriverSection, fullOffset, &fullName)) {
            continue;
        }
        for (baseOffset = 0UL;
             baseOffset + sizeof(UNICODE_STRING) <= KSW_RUNTIME_KLDR_SCAN_BYTES;
             baseOffset += (ULONG)sizeof(PVOID)) {
            UNICODE_STRING baseName;

            if (baseOffset == fullOffset ||
                !KswordARKDriverReadKldrUnicodeString(DriverSection, baseOffset, &baseName) ||
                !KswordARKDriverKldrNamesMatch(&fullName, &baseName)) {
                continue;
            }
            if (foundFullOffset >= 0) {
                return;
            }
            foundFullOffset = (LONG)fullOffset;
            foundBaseOffset = (LONG)baseOffset;
        }
    }

    *FullNameOffsetOut = foundFullOffset;
    *BaseNameOffsetOut = foundBaseOffset;
}

static VOID
KswordARKDriverResolvePublicDriverObjectLayout(
    _In_opt_ PDRIVER_OBJECT ValidationDriverObject,
    _Inout_ PKSW_RUNTIME_KERNEL_LAYOUT Layout
    )
/*++

Routine Description:

    Publish WDK-defined DRIVER_OBJECT member offsets after cross-checking a live object.

Arguments:

    ValidationDriverObject - Live KSword driver object.
    Layout - Mutable fallback result.

Return Value:

    None.

--*/
{
    PVOID driverStart = NULL;
    ULONG driverSize = 0UL;

    if (ValidationDriverObject == NULL || Layout == NULL ||
        !KswordARKDriverFallbackReadMemory(
            &ValidationDriverObject->DriverStart,
            &driverStart,
            sizeof(driverStart)) ||
        !KswordARKDriverFallbackReadMemory(
            &ValidationDriverObject->DriverSize,
            &driverSize,
            sizeof(driverSize)) ||
        driverStart == NULL || driverSize == 0UL) {
        return;
    }

    Layout->DoDriverStart = (LONG)FIELD_OFFSET(DRIVER_OBJECT, DriverStart);
    Layout->DoDriverSize = (LONG)FIELD_OFFSET(DRIVER_OBJECT, DriverSize);
    Layout->DoDriverSection = (LONG)FIELD_OFFSET(DRIVER_OBJECT, DriverSection);
    Layout->DoMajorFunction = (LONG)FIELD_OFFSET(DRIVER_OBJECT, MajorFunction);
    Layout->DoFastIoDispatch = (LONG)FIELD_OFFSET(DRIVER_OBJECT, FastIoDispatch);
    Layout->DoDriverUnload = (LONG)FIELD_OFFSET(DRIVER_OBJECT, DriverUnload);
}

static VOID
KswordARKDriverResolvePublicAvlLayout(
    _Inout_ PKSW_RUNTIME_KERNEL_LAYOUT Layout
    )
/*++

Routine Description:

    Publish WDK-defined RTL_AVL_TABLE offsets and exact public type size.

Arguments:

    Layout - Mutable fallback result.

Return Value:

    None.

--*/
{
    if (Layout == NULL) {
        return;
    }
    Layout->RtlAvlBalancedRoot = (LONG)FIELD_OFFSET(RTL_AVL_TABLE, BalancedRoot);
    Layout->RtlAvlOrderedPointer = (LONG)FIELD_OFFSET(RTL_AVL_TABLE, OrderedPointer);
    Layout->RtlAvlWhichOrderedElement = (LONG)FIELD_OFFSET(RTL_AVL_TABLE, WhichOrderedElement);
    Layout->RtlAvlNumberGenericTableElements =
        (LONG)FIELD_OFFSET(RTL_AVL_TABLE, NumberGenericTableElements);
    Layout->RtlAvlDepthOfTree = (LONG)FIELD_OFFSET(RTL_AVL_TABLE, DepthOfTree);
    Layout->RtlAvlRestartKey = (LONG)FIELD_OFFSET(RTL_AVL_TABLE, RestartKey);
    Layout->RtlAvlDeleteCount = (LONG)FIELD_OFFSET(RTL_AVL_TABLE, DeleteCount);
    Layout->RtlAvlTypeSize = (LONG)sizeof(RTL_AVL_TABLE);
}

VOID
KswordARKDriverResolveKernelFallbackLayout(
    _In_opt_ PDRIVER_OBJECT ValidationDriverObject,
    _In_ const KSW_DYN_MODULE_IDENTITY_PACKET* NtoskrnlIdentity,
    _Out_ PKSW_RUNTIME_KERNEL_LAYOUT LayoutOut
    )
/*++

Routine Description:

    Resolve all currently supported non-PDB kernel layout facts in one pass.
    PDB data remains preferred by the caller; these results fill only missing
    fields and carry runtime-pattern provenance.

Arguments:

    ValidationDriverObject - Live KSword driver object used for structure checks.
    NtoskrnlIdentity - Current loaded ntoskrnl image identity.
    LayoutOut - Receives signed offsets and RVAs.

Return Value:

    None.

--*/
{
    PLIST_ENTRY loadedModuleList = NULL;
    const UCHAR* driverSection = NULL;

    if (LayoutOut == NULL) {
        return;
    }
    KswordARKDriverInitializeKernelFallbackLayout(LayoutOut);
    KswordARKDriverResolvePublicDriverObjectLayout(ValidationDriverObject, LayoutOut);
    KswordARKDriverResolvePublicAvlLayout(LayoutOut);
    KswordARKDriverResolveKernelCacheFallback(NtoskrnlIdentity, LayoutOut);
    LayoutOut->KeServiceDescriptorTableShadowRva =
        KswordARKDriverResolveShadowSsdtRva(NtoskrnlIdentity);

    loadedModuleList = KswordARKDriverResolveLoadedModuleListExport(
        NtoskrnlIdentity,
        &LayoutOut->PsLoadedModuleListRva);
    if (ValidationDriverObject == NULL || loadedModuleList == NULL) {
        return;
    }
    driverSection = (const UCHAR*)ValidationDriverObject->DriverSection;
    if (driverSection == NULL || ValidationDriverObject->DriverStart == NULL ||
        ValidationDriverObject->DriverSize == 0UL) {
        return;
    }

    LayoutOut->KldrInLoadOrderLinks = KswordARKDriverResolveUniqueKldrListOffset(
        driverSection,
        loadedModuleList);
    LayoutOut->KldrDllBase = KswordARKDriverResolveUniquePointerField(
        driverSection,
        (ULONG_PTR)ValidationDriverObject->DriverStart);
    LayoutOut->KldrSizeOfImage = KswordARKDriverResolveKldrSizeField(
        driverSection,
        LayoutOut->KldrDllBase,
        ValidationDriverObject->DriverSize);
    KswordARKDriverResolveKldrNameOffsets(
        driverSection,
        &LayoutOut->KldrFullDllName,
        &LayoutOut->KldrBaseDllName);
}
