/*++

Module Name:

    runtime_signature_scan.c

Abstract:

    Shared x64 runtime-signature support.  The scanner begins at stable PE
    exports, follows a bounded number of direct relative calls or jumps, and
    records only RIP-relative references that resolve into the same loaded
    image.  It deliberately does not publish a candidate: feature-specific
    callers must still require a unique match and validate the live structure.

Environment:

    Kernel mode, PASSIVE_LEVEL initialization or read-only query paths.

--*/

#include "runtime_signature_scan.h"
#include <ntimage.h>

NTSYSAPI
PVOID
NTAPI
RtlFindExportedRoutineByName(
    _In_ PVOID ImageBase,
    _In_ PCCH RoutineName
    );

typedef struct _KSW_RUNTIME_ROUTINE_WORK
{
    ULONG_PTR Address;
    ULONG Depth;
} KSW_RUNTIME_ROUTINE_WORK, *PKSW_RUNTIME_ROUTINE_WORK;

BOOLEAN
KswordARKRuntimeReadMemory(
    _In_ const VOID* Address,
    _Out_writes_bytes_(Size) VOID* Buffer,
    _In_ SIZE_T Size
    )
/*++

Routine Description:

    Copy a bounded kernel-memory range while containing invalid candidates.

Return Value:

    TRUE only when the complete range was readable.

--*/
{
    MM_COPY_ADDRESS sourceAddress;
    SIZE_T bytesTransferred = 0U;
    NTSTATUS status = STATUS_SUCCESS;

    if (Address == NULL || Buffer == NULL || Size == 0U) {
        return FALSE;
    }
    if (KeGetCurrentIrql() > APC_LEVEL) {
        return FALSE;
    }
    RtlZeroMemory(&sourceAddress, sizeof(sourceAddress));
    sourceAddress.VirtualAddress = (PVOID)Address;
    status = MmCopyMemory(
        Buffer,
        sourceAddress,
        Size,
        MM_COPY_MEMORY_VIRTUAL,
        &bytesTransferred);
    return NT_SUCCESS(status) && bytesTransferred == Size;
}

BOOLEAN
KswordARKRuntimeAddressInImage(
    _In_ const KSW_RUNTIME_IMAGE_VIEW* View,
    _In_ ULONG_PTR Address,
    _In_ SIZE_T RequiredBytes
    )
/*++

Routine Description:

    Validate a non-wrapping address range against the loaded image interval.

Return Value:

    TRUE when every requested byte is contained by the image.

--*/
{
    ULONG_PTR imageEnd = 0U;

    if (View == NULL || View->Base == 0U || View->Size == 0UL ||
        RequiredBytes == 0U || View->Base > MAXULONG_PTR - View->Size) {
        return FALSE;
    }
    imageEnd = View->Base + View->Size;
    return Address >= View->Base && Address < imageEnd &&
        RequiredBytes <= imageEnd - Address;
}

static BOOLEAN
KswordARKRuntimeRangeInSection(
    _In_ const KSW_RUNTIME_IMAGE_VIEW* View,
    _In_ ULONG_PTR Address,
    _In_ SIZE_T RequiredBytes,
    _In_ ULONG RequiredCharacteristics,
    _In_ ULONG RejectedCharacteristics
    )
/*++

Routine Description:

    Match one range against a PE section with required and rejected flags.

Return Value:

    TRUE when one complete section range satisfies the policy.

--*/
{
    ULONG index = 0UL;

    if (!KswordARKRuntimeAddressInImage(View, Address, RequiredBytes)) {
        return FALSE;
    }
    for (index = 0UL; index < View->SectionCount; ++index) {
        const KSW_RUNTIME_IMAGE_SECTION* section = &View->Sections[index];

        if ((section->Characteristics & RequiredCharacteristics) !=
                RequiredCharacteristics ||
            (section->Characteristics & RejectedCharacteristics) != 0UL ||
            Address < section->Start || Address >= section->End ||
            RequiredBytes > section->End - Address) {
            continue;
        }
        return TRUE;
    }
    return FALSE;
}

BOOLEAN
KswordARKRuntimeAddressIsExecutable(
    _In_ const KSW_RUNTIME_IMAGE_VIEW* View,
    _In_ ULONG_PTR Address,
    _In_ SIZE_T RequiredBytes
    )
{
    return KswordARKRuntimeRangeInSection(
        View,
        Address,
        RequiredBytes,
        IMAGE_SCN_MEM_EXECUTE,
        0UL);
}

BOOLEAN
KswordARKRuntimeAddressIsWritableData(
    _In_ const KSW_RUNTIME_IMAGE_VIEW* View,
    _In_ ULONG_PTR Address,
    _In_ SIZE_T RequiredBytes
    )
{
    return KswordARKRuntimeRangeInSection(
        View,
        Address,
        RequiredBytes,
        IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE,
        IMAGE_SCN_MEM_EXECUTE);
}

BOOLEAN
KswordARKRuntimeInitializeImageView(
    _In_ PVOID ImageBase,
    _In_ ULONG ImageSize,
    _Out_ PKSW_RUNTIME_IMAGE_VIEW ViewOut
    )
/*++

Routine Description:

    Parse a loaded PE image and retain bounded virtual section intervals.

Return Value:

    TRUE when DOS, NT, optional, and section headers are internally consistent.

--*/
{
    IMAGE_DOS_HEADER dosHeader;
    IMAGE_NT_HEADERS64 ntHeaders;
    ULONG_PTR base = (ULONG_PTR)ImageBase;
    ULONG_PTR ntAddress = 0U;
    ULONG_PTR sectionAddress = 0U;
    ULONG sectionCount = 0UL;
    ULONG index = 0UL;

    if (ViewOut == NULL) {
        return FALSE;
    }
    RtlZeroMemory(ViewOut, sizeof(*ViewOut));
    if (ImageBase == NULL || ImageSize < sizeof(dosHeader) ||
        !KswordARKRuntimeReadMemory(ImageBase, &dosHeader, sizeof(dosHeader)) ||
        dosHeader.e_magic != IMAGE_DOS_SIGNATURE || dosHeader.e_lfanew <= 0 ||
        (ULONG)dosHeader.e_lfanew > ImageSize - sizeof(ntHeaders) ||
        base > MAXULONG_PTR - (ULONG)dosHeader.e_lfanew) {
        return FALSE;
    }

    ntAddress = base + (ULONG)dosHeader.e_lfanew;
    if (!KswordARKRuntimeReadMemory(
            (const VOID*)ntAddress,
            &ntHeaders,
            sizeof(ntHeaders)) ||
        ntHeaders.Signature != IMAGE_NT_SIGNATURE ||
        ntHeaders.OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC ||
        ntHeaders.FileHeader.NumberOfSections == 0U ||
        ntHeaders.FileHeader.NumberOfSections > KSW_RUNTIME_IMAGE_MAX_SECTIONS ||
        ntHeaders.OptionalHeader.SizeOfImage == 0UL ||
        ntHeaders.OptionalHeader.SizeOfImage > ImageSize) {
        return FALSE;
    }

    sectionCount = ntHeaders.FileHeader.NumberOfSections;
    sectionAddress = ntAddress + FIELD_OFFSET(IMAGE_NT_HEADERS64, OptionalHeader) +
        ntHeaders.FileHeader.SizeOfOptionalHeader;
    if (sectionAddress < ntAddress || sectionAddress < base ||
        sectionCount > (ImageSize / sizeof(IMAGE_SECTION_HEADER)) ||
        sectionAddress - base >= ImageSize ||
        (SIZE_T)sectionCount * sizeof(IMAGE_SECTION_HEADER) >
            ImageSize - (sectionAddress - base)) {
        return FALSE;
    }

    ViewOut->Base = base;
    ViewOut->Size = ntHeaders.OptionalHeader.SizeOfImage;
    for (index = 0UL; index < sectionCount; ++index) {
        IMAGE_SECTION_HEADER sectionHeader;
        ULONG virtualBytes = 0UL;
        ULONG_PTR start = 0U;
        ULONG_PTR end = 0U;

        if (!KswordARKRuntimeReadMemory(
                (const VOID*)(sectionAddress +
                    ((ULONG_PTR)index * sizeof(sectionHeader))),
                &sectionHeader,
                sizeof(sectionHeader))) {
            RtlZeroMemory(ViewOut, sizeof(*ViewOut));
            return FALSE;
        }
        virtualBytes = max(sectionHeader.Misc.VirtualSize, sectionHeader.SizeOfRawData);
        if (virtualBytes == 0UL || sectionHeader.VirtualAddress >= ViewOut->Size ||
            virtualBytes > ViewOut->Size - sectionHeader.VirtualAddress ||
            base > MAXULONG_PTR - sectionHeader.VirtualAddress) {
            continue;
        }
        start = base + sectionHeader.VirtualAddress;
        if (start > MAXULONG_PTR - virtualBytes) {
            continue;
        }
        end = start + virtualBytes;
        ViewOut->Sections[ViewOut->SectionCount].Start = start;
        ViewOut->Sections[ViewOut->SectionCount].End = end;
        ViewOut->Sections[ViewOut->SectionCount].Characteristics =
            sectionHeader.Characteristics;
        ViewOut->SectionCount += 1UL;
    }

    if (ViewOut->SectionCount == 0UL) {
        RtlZeroMemory(ViewOut, sizeof(*ViewOut));
        return FALSE;
    }
    return TRUE;
}

PVOID
KswordARKRuntimeFindExport(
    _In_ const KSW_RUNTIME_IMAGE_VIEW* View,
    _In_z_ PCSTR ExportName
    )
/*++

Routine Description:

    Resolve one export and require its address to remain in the supplied image.

Return Value:

    Export address or NULL.

--*/
{
    PVOID address = NULL;

    if (View == NULL || ExportName == NULL || View->Base == 0U) {
        return NULL;
    }
    address = RtlFindExportedRoutineByName((PVOID)View->Base, ExportName);
    return KswordARKRuntimeAddressInImage(View, (ULONG_PTR)address, 1U)
        ? address
        : NULL;
}

static BOOLEAN
KswordARKRuntimeResolveRelativeTarget(
    _In_ ULONG_PTR NextInstruction,
    _In_ LONG Displacement,
    _Out_ ULONG_PTR* TargetOut
    )
{
    ULONG_PTR magnitude = 0U;

    if (TargetOut == NULL) {
        return FALSE;
    }
    if (Displacement >= 0) {
        if (NextInstruction > MAXULONG_PTR - (ULONG)Displacement) {
            return FALSE;
        }
        *TargetOut = NextInstruction + (ULONG)Displacement;
        return TRUE;
    }
    magnitude = (ULONG_PTR)(-(LONGLONG)Displacement);
    if (NextInstruction < magnitude) {
        return FALSE;
    }
    *TargetOut = NextInstruction - magnitude;
    return TRUE;
}

static BOOLEAN
KswordARKRuntimeDecodeRipReference(
    _In_ ULONG_PTR InstructionAddress,
    _Out_ ULONG_PTR* TargetOut,
    _Out_opt_ ULONG* InstructionBytesOut
    )
/*++

Routine Description:

    Decode the small x64 instruction subset used for RIP-relative data access.
    Unsupported encodings are ignored instead of guessed.

Return Value:

    TRUE when a complete supported instruction resolved safely.

--*/
{
#if defined(_M_AMD64) || defined(_M_X64)
    UCHAR bytes[16];
    ULONG cursor = 0UL;
    ULONG modRmOffset = 0UL;
    ULONG displacementOffset = 0UL;
    ULONG instructionBytes = 0UL;
    BOOLEAN supportedOpcode = FALSE;
    LONG displacement = 0L;

    if (TargetOut == NULL ||
        !KswordARKRuntimeReadMemory(
            (const VOID*)InstructionAddress,
            bytes,
            sizeof(bytes))) {
        return FALSE;
    }

    while (cursor < 4UL &&
           (bytes[cursor] == 0x66U || bytes[cursor] == 0xF2U ||
            bytes[cursor] == 0xF3U ||
            (bytes[cursor] >= 0x40U && bytes[cursor] <= 0x4FU))) {
        cursor += 1UL;
    }
    if (cursor >= sizeof(bytes)) {
        return FALSE;
    }

    if (bytes[cursor] == 0x0FU) {
        cursor += 1UL;
        if (cursor >= sizeof(bytes)) {
            return FALSE;
        }
        supportedOpcode = bytes[cursor] == 0xB6U || bytes[cursor] == 0xB7U ||
            bytes[cursor] == 0xBEU || bytes[cursor] == 0xBFU;
    }
    else {
        supportedOpcode = bytes[cursor] == 0x8BU || bytes[cursor] == 0x8DU ||
            bytes[cursor] == 0x89U || bytes[cursor] == 0x39U ||
            bytes[cursor] == 0x3BU || bytes[cursor] == 0x63U ||
            bytes[cursor] == 0x85U || bytes[cursor] == 0xFFU;
    }
    if (!supportedOpcode) {
        return FALSE;
    }

    modRmOffset = cursor + 1UL;
    if (modRmOffset >= sizeof(bytes) || (bytes[modRmOffset] & 0xC7U) != 0x05U) {
        return FALSE;
    }
    displacementOffset = modRmOffset + 1UL;
    instructionBytes = displacementOffset + sizeof(displacement);
    if (instructionBytes > sizeof(bytes)) {
        return FALSE;
    }
    RtlCopyMemory(&displacement, bytes + displacementOffset, sizeof(displacement));
    if (!KswordARKRuntimeResolveRelativeTarget(
            InstructionAddress + instructionBytes,
            displacement,
            TargetOut)) {
        return FALSE;
    }
    if (InstructionBytesOut != NULL) {
        *InstructionBytesOut = instructionBytes;
    }
    return TRUE;
#else
    UNREFERENCED_PARAMETER(InstructionAddress);
    UNREFERENCED_PARAMETER(TargetOut);
    UNREFERENCED_PARAMETER(InstructionBytesOut);
    return FALSE;
#endif
}

static BOOLEAN
KswordARKRuntimeDecodeDirectBranch(
    _In_ ULONG_PTR InstructionAddress,
    _Out_ ULONG_PTR* TargetOut
    )
{
    UCHAR bytes[5];
    LONG displacement = 0L;

    if (TargetOut == NULL ||
        !KswordARKRuntimeReadMemory(
            (const VOID*)InstructionAddress,
            bytes,
            sizeof(bytes)) ||
        (bytes[0] != 0xE8U && bytes[0] != 0xE9U)) {
        return FALSE;
    }
    RtlCopyMemory(&displacement, bytes + 1UL, sizeof(displacement));
    return KswordARKRuntimeResolveRelativeTarget(
        InstructionAddress + sizeof(bytes),
        displacement,
        TargetOut);
}

static BOOLEAN
KswordARKRuntimeAppendReference(
    _Inout_updates_(Capacity) KSW_RUNTIME_DATA_REFERENCE* References,
    _In_ ULONG Capacity,
    _Inout_ ULONG* Count,
    _In_ ULONG_PTR Address,
    _In_ ULONG_PTR RoutineAddress,
    _In_ ULONG_PTR InstructionAddress
    )
{
    ULONG index = 0UL;

    if (References == NULL || Count == NULL || *Count > Capacity) {
        return FALSE;
    }
    for (index = 0UL; index < *Count; ++index) {
        if (References[index].Address == Address &&
            References[index].RoutineAddress == RoutineAddress) {
            return TRUE;
        }
    }
    if (*Count >= Capacity) {
        return FALSE;
    }
    References[*Count].Address = Address;
    References[*Count].RoutineAddress = RoutineAddress;
    References[*Count].InstructionAddress = InstructionAddress;
    *Count += 1UL;
    return TRUE;
}

static ULONG
KswordARKRuntimeScanRoutine(
    _In_ const KSW_RUNTIME_IMAGE_VIEW* View,
    _In_ ULONG_PTR RoutineAddress,
    _In_ ULONG ScanBytes,
    _Inout_updates_(ReferenceCapacity) KSW_RUNTIME_DATA_REFERENCE* References,
    _In_ ULONG ReferenceCapacity,
    _Inout_ ULONG* ReferenceCount,
    _Out_writes_opt_(BranchCapacity) ULONG_PTR* BranchTargets,
    _In_ ULONG BranchCapacity
    )
{
    ULONG offset = 0UL;
    ULONG branchCount = 0UL;

    if (View == NULL || References == NULL || ReferenceCount == NULL ||
        !KswordARKRuntimeAddressIsExecutable(View, RoutineAddress, 1U)) {
        return 0UL;
    }

    for (offset = 0UL; offset < ScanBytes; ++offset) {
        ULONG_PTR instructionAddress = RoutineAddress + offset;
        ULONG_PTR target = 0U;

        if (!KswordARKRuntimeAddressIsExecutable(View, instructionAddress, 1U)) {
            break;
        }
        if (KswordARKRuntimeDecodeRipReference(instructionAddress, &target, NULL) &&
            KswordARKRuntimeAddressInImage(View, target, 1U) &&
            !KswordARKRuntimeAddressIsExecutable(View, target, 1U)) {
            if (!KswordARKRuntimeAppendReference(
                    References,
                    ReferenceCapacity,
                    ReferenceCount,
                    target,
                    RoutineAddress,
                    instructionAddress)) {
                break;
            }
        }
        if (BranchTargets != NULL && branchCount < BranchCapacity &&
            KswordARKRuntimeDecodeDirectBranch(instructionAddress, &target) &&
            KswordARKRuntimeAddressIsExecutable(View, target, 1U)) {
            ULONG branchIndex = 0UL;
            BOOLEAN duplicate = FALSE;

            for (branchIndex = 0UL; branchIndex < branchCount; ++branchIndex) {
                if (BranchTargets[branchIndex] == target) {
                    duplicate = TRUE;
                    break;
                }
            }
            if (!duplicate) {
                BranchTargets[branchCount++] = target;
            }
        }
    }
    return branchCount;
}

ULONG
KswordARKRuntimeCollectAnchoredDataReferences(
    _In_ const KSW_RUNTIME_IMAGE_VIEW* View,
    _In_reads_(AnchorCount) PCSTR const* AnchorNames,
    _In_ ULONG AnchorCount,
    _In_ ULONG MaxCallDepth,
    _In_ ULONG RoutineScanBytes,
    _Out_writes_(ReferenceCapacity) KSW_RUNTIME_DATA_REFERENCE* References,
    _In_ ULONG ReferenceCapacity
    )
/*++

Routine Description:

    Scan stable exports and a bounded direct-call graph for image data references.

Return Value:

    Number of unique address/routine pairs stored in References.

--*/
{
    KSW_RUNTIME_ROUTINE_WORK work[KSW_RUNTIME_SIGNATURE_MAX_ROUTINES];
    ULONG workCount = 0UL;
    ULONG workIndex = 0UL;
    ULONG referenceCount = 0UL;
    ULONG anchorIndex = 0UL;

    if (View == NULL || AnchorNames == NULL || AnchorCount == 0UL ||
        RoutineScanBytes == 0UL || References == NULL || ReferenceCapacity == 0UL) {
        return 0UL;
    }
    RtlZeroMemory(References, (SIZE_T)ReferenceCapacity * sizeof(*References));
    RtlZeroMemory(work, sizeof(work));

    for (anchorIndex = 0UL;
         anchorIndex < AnchorCount && workCount < RTL_NUMBER_OF(work);
         ++anchorIndex) {
        ULONG_PTR address = (ULONG_PTR)KswordARKRuntimeFindExport(
            View,
            AnchorNames[anchorIndex]);
        ULONG index = 0UL;
        BOOLEAN duplicate = FALSE;

        if (address == 0U || !KswordARKRuntimeAddressIsExecutable(View, address, 1U)) {
            continue;
        }
        for (index = 0UL; index < workCount; ++index) {
            if (work[index].Address == address) {
                duplicate = TRUE;
                break;
            }
        }
        if (!duplicate) {
            work[workCount].Address = address;
            work[workCount].Depth = 0UL;
            workCount += 1UL;
        }
    }

    while (workIndex < workCount && referenceCount < ReferenceCapacity) {
        ULONG_PTR branches[KSW_RUNTIME_SIGNATURE_MAX_ROUTINES];
        ULONG branchCount = 0UL;
        ULONG branchIndex = 0UL;

        RtlZeroMemory(branches, sizeof(branches));
        branchCount = KswordARKRuntimeScanRoutine(
            View,
            work[workIndex].Address,
            RoutineScanBytes,
            References,
            ReferenceCapacity,
            &referenceCount,
            branches,
            RTL_NUMBER_OF(branches));
        if (work[workIndex].Depth < MaxCallDepth) {
            for (branchIndex = 0UL;
                 branchIndex < branchCount && workCount < RTL_NUMBER_OF(work);
                 ++branchIndex) {
                ULONG existingIndex = 0UL;
                BOOLEAN duplicate = FALSE;

                for (existingIndex = 0UL; existingIndex < workCount; ++existingIndex) {
                    if (work[existingIndex].Address == branches[branchIndex]) {
                        duplicate = TRUE;
                        break;
                    }
                }
                if (!duplicate) {
                    work[workCount].Address = branches[branchIndex];
                    work[workCount].Depth = work[workIndex].Depth + 1UL;
                    workCount += 1UL;
                }
            }
        }
        workIndex += 1UL;
    }
    return referenceCount;
}

ULONG
KswordARKRuntimeCollectExecutableDataReferences(
    _In_ const KSW_RUNTIME_IMAGE_VIEW* View,
    _In_ ULONG ScanByteBudget,
    _Out_writes_(ReferenceCapacity) KSW_RUNTIME_DATA_REFERENCE* References,
    _In_ ULONG ReferenceCapacity
    )
/*++

Routine Description:

    Scan executable PE sections when a module exposes no stable public anchor.
    The caller supplies a global byte budget and must still perform unique,
    feature-specific live validation before using any reference.

Return Value:

    Number of stored unique address/section-start pairs.

--*/
{
    ULONG referenceCount = 0UL;
    ULONG scannedBytes = 0UL;
    ULONG sectionIndex = 0UL;

    if (View == NULL || ScanByteBudget == 0UL || References == NULL ||
        ReferenceCapacity == 0UL) {
        return 0UL;
    }
    RtlZeroMemory(References, (SIZE_T)ReferenceCapacity * sizeof(*References));
    for (sectionIndex = 0UL;
         sectionIndex < View->SectionCount && scannedBytes < ScanByteBudget &&
             referenceCount < ReferenceCapacity;
         ++sectionIndex) {
        const KSW_RUNTIME_IMAGE_SECTION* section = &View->Sections[sectionIndex];
        ULONG sectionBytes = 0UL;
        ULONG remainingBudget = ScanByteBudget - scannedBytes;

        if ((section->Characteristics & IMAGE_SCN_MEM_EXECUTE) == 0UL ||
            section->End <= section->Start) {
            continue;
        }
        sectionBytes = (ULONG)min(
            section->End - section->Start,
            (ULONG_PTR)remainingBudget);
        (VOID)KswordARKRuntimeScanRoutine(
            View,
            section->Start,
            sectionBytes,
            References,
            ReferenceCapacity,
            &referenceCount,
            NULL,
            0UL);
        scannedBytes += sectionBytes;
    }
    return referenceCount;
}
