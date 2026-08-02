/*++

Module Name:

    ssdt_fallback.c

Abstract:

    Identity-bound runtime fallback for KeServiceDescriptorTableShadow. The
    resolver follows references from the exported KeAddSystemServiceTable
    anchor and accepts only one writable descriptor array whose native and GUI
    service tables both pass live semantic validation.

Environment:

    Kernel-mode Driver Framework

--*/

#include <ntifs.h>
#include <ntimage.h>
#include "ssdt_fallback.h"
#include "../../platform/runtime_signature_scan.h"

#define KSW_SSDT_FALLBACK_REFERENCE_CAPACITY 128UL
#define KSW_SSDT_FALLBACK_ROUTINE_SCAN_BYTES 0x0300UL
#define KSW_SSDT_FALLBACK_MIN_NATIVE_SERVICES 0x0080UL
#define KSW_SSDT_FALLBACK_MAX_NATIVE_SERVICES 0x2000UL
#define KSW_SSDT_FALLBACK_MIN_GUI_SERVICES 0x0080UL
#define KSW_SSDT_FALLBACK_MAX_GUI_SERVICES 0x4000UL
#define KSW_SSDT_FALLBACK_SAMPLE_COUNT 8UL
#define KSW_SSDT_FALLBACK_REQUIRED_NATIVE_SAMPLES 5UL
#define KSW_SSDT_FALLBACK_REQUIRED_GUI_SAMPLES 4UL

#if defined(_M_AMD64)

typedef struct _KSW_SSDT_FALLBACK_DESCRIPTOR
{
    PVOID ServiceTableBase;
    PVOID ServiceCounterTableBase;
    ULONG_PTR NumberOfServices;
    PVOID ParamTableBase;
} KSW_SSDT_FALLBACK_DESCRIPTOR, *PKSW_SSDT_FALLBACK_DESCRIPTOR;

NTSYSAPI
PVOID
NTAPI
RtlPcToFileHeader(
    _In_ PVOID PcValue,
    _Outptr_ PVOID* BaseOfImage
    );

static BOOLEAN
KswordARKDriverSsdtReadImageSize(
    _In_ PVOID ImageBase,
    _Out_ ULONG* ImageSizeOut
    )
{
    IMAGE_DOS_HEADER dosHeader;
    IMAGE_NT_HEADERS64 ntHeaders;
    ULONG_PTR ntHeaderAddress = 0U;

    if (ImageBase == NULL || ImageSizeOut == NULL) {
        return FALSE;
    }
    *ImageSizeOut = 0UL;
    if (!KswordARKRuntimeReadMemory(ImageBase, &dosHeader, sizeof(dosHeader)) ||
        dosHeader.e_magic != IMAGE_DOS_SIGNATURE ||
        dosHeader.e_lfanew <= 0 || dosHeader.e_lfanew > 0x00100000L) {
        return FALSE;
    }
    ntHeaderAddress = (ULONG_PTR)ImageBase + (ULONG)dosHeader.e_lfanew;
    if (ntHeaderAddress < (ULONG_PTR)ImageBase ||
        !KswordARKRuntimeReadMemory(
            (const VOID*)ntHeaderAddress,
            &ntHeaders,
            sizeof(ntHeaders)) ||
        ntHeaders.Signature != IMAGE_NT_SIGNATURE ||
        ntHeaders.OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC ||
        ntHeaders.OptionalHeader.SizeOfImage < 0x1000UL) {
        return FALSE;
    }
    *ImageSizeOut = ntHeaders.OptionalHeader.SizeOfImage;
    return TRUE;
}

static BOOLEAN
KswordARKDriverSsdtAddressIsExecutableImageCode(
    _In_ ULONG_PTR Address,
    _In_opt_ const KSW_RUNTIME_IMAGE_VIEW* RequiredImage
    )
{
    PVOID imageBase = NULL;
    ULONG imageSize = 0UL;
    KSW_RUNTIME_IMAGE_VIEW imageView;

    if (Address < (ULONG_PTR)MmSystemRangeStart ||
        RtlPcToFileHeader((PVOID)Address, &imageBase) == NULL ||
        imageBase == NULL ||
        (RequiredImage != NULL && (ULONG_PTR)imageBase != RequiredImage->Base) ||
        !KswordARKDriverSsdtReadImageSize(imageBase, &imageSize) ||
        !KswordARKRuntimeInitializeImageView(imageBase, imageSize, &imageView)) {
        return FALSE;
    }
    return KswordARKRuntimeAddressIsExecutable(&imageView, Address, 1U);
}

static ULONG_PTR
KswordARKDriverSsdtDecodeRoutine(
    _In_ ULONG_PTR ServiceTableBase,
    _In_ ULONG ServiceIndex
    )
{
    LONG encodedOffset = 0L;
    LONG_PTR signedOffset = 0;

    if (ServiceTableBase < (ULONG_PTR)MmSystemRangeStart ||
        !KswordARKRuntimeReadMemory(
            (const VOID*)(ServiceTableBase + ((ULONG_PTR)ServiceIndex * sizeof(LONG))),
            &encodedOffset,
            sizeof(encodedOffset))) {
        return 0U;
    }
    signedOffset = ((LONG_PTR)encodedOffset) >> 4;
    if (signedOffset > 0 && ServiceTableBase > MAXULONG_PTR - (ULONG_PTR)signedOffset) {
        return 0U;
    }
    if (signedOffset < 0 && ServiceTableBase < (ULONG_PTR)(-signedOffset)) {
        return 0U;
    }
    return (ULONG_PTR)((LONG_PTR)ServiceTableBase + signedOffset);
}

static BOOLEAN
KswordARKDriverSsdtValidateTable(
    _In_ const KSW_SSDT_FALLBACK_DESCRIPTOR* Descriptor,
    _In_ ULONG MinimumServices,
    _In_ ULONG MaximumServices,
    _In_ ULONG RequiredSamples,
    _In_opt_ const KSW_RUNTIME_IMAGE_VIEW* RequiredImage,
    _In_ BOOLEAN RejectRequiredImage
    )
{
    ULONG sampleIndex = 0UL;
    ULONG validSamples = 0UL;
    ULONG serviceCount = 0UL;
    ULONG_PTR tableBase = 0U;

    if (Descriptor == NULL || Descriptor->ServiceTableBase == NULL ||
        Descriptor->NumberOfServices < MinimumServices ||
        Descriptor->NumberOfServices > MaximumServices ||
        Descriptor->NumberOfServices > MAXULONG) {
        return FALSE;
    }
    serviceCount = (ULONG)Descriptor->NumberOfServices;
    tableBase = (ULONG_PTR)Descriptor->ServiceTableBase;
    if (tableBase < (ULONG_PTR)MmSystemRangeStart ||
        (tableBase & (sizeof(LONG) - 1U)) != 0U) {
        return FALSE;
    }

    for (sampleIndex = 0UL; sampleIndex < KSW_SSDT_FALLBACK_SAMPLE_COUNT; ++sampleIndex) {
        const ULONG serviceIndex = (ULONG)(((ULONG64)(serviceCount - 1UL) * sampleIndex) /
            (KSW_SSDT_FALLBACK_SAMPLE_COUNT - 1UL));
        const ULONG_PTR routineAddress = KswordARKDriverSsdtDecodeRoutine(
            tableBase,
            serviceIndex);
        PVOID routineImage = NULL;

        if (routineAddress == 0U ||
            !KswordARKDriverSsdtAddressIsExecutableImageCode(
                routineAddress,
                RejectRequiredImage ? NULL : RequiredImage)) {
            continue;
        }
        if (RejectRequiredImage && RequiredImage != NULL) {
            if (RtlPcToFileHeader((PVOID)routineAddress, &routineImage) == NULL ||
                routineImage == NULL ||
                (ULONG_PTR)routineImage == RequiredImage->Base) {
                continue;
            }
        }
        validSamples += 1UL;
    }
    return validSamples >= RequiredSamples;
}

static BOOLEAN
KswordARKDriverSsdtValidateCandidate(
    _In_ const KSW_RUNTIME_IMAGE_VIEW* NtoskrnlView,
    _In_ ULONG_PTR CandidateAddress
    )
{
    KSW_SSDT_FALLBACK_DESCRIPTOR descriptors[2];

    if (NtoskrnlView == NULL ||
        !KswordARKRuntimeAddressIsWritableData(
            NtoskrnlView,
            CandidateAddress,
            sizeof(descriptors)) ||
        !KswordARKRuntimeReadMemory(
            (const VOID*)CandidateAddress,
            descriptors,
            sizeof(descriptors))) {
        return FALSE;
    }
    if (!KswordARKDriverSsdtValidateTable(
            &descriptors[0],
            KSW_SSDT_FALLBACK_MIN_NATIVE_SERVICES,
            KSW_SSDT_FALLBACK_MAX_NATIVE_SERVICES,
            KSW_SSDT_FALLBACK_REQUIRED_NATIVE_SAMPLES,
            NtoskrnlView,
            FALSE)) {
        return FALSE;
    }
    return KswordARKDriverSsdtValidateTable(
        &descriptors[1],
        KSW_SSDT_FALLBACK_MIN_GUI_SERVICES,
        KSW_SSDT_FALLBACK_MAX_GUI_SERVICES,
        KSW_SSDT_FALLBACK_REQUIRED_GUI_SAMPLES,
        NtoskrnlView,
        TRUE);
}

#endif

LONG
KswordARKDriverResolveShadowSsdtRva(
    _In_ const KSW_DYN_MODULE_IDENTITY_PACKET* NtoskrnlIdentity
    )
/*++

Routine Description:

    Follow the stable KeAddSystemServiceTable export into its bounded call
    graph, validate every referenced writable address as a two-entry service
    descriptor array, and publish only a unique match.

Arguments:

    NtoskrnlIdentity - Current loaded ntoskrnl identity and image bounds.

Return Value:

    Non-negative image RVA for one validated shadow table, or -1 when missing
    or ambiguous.

--*/
{
#if !defined(_M_AMD64)
    UNREFERENCED_PARAMETER(NtoskrnlIdentity);
    return -1;
#else
    static PCSTR const anchors[] = { "KeAddSystemServiceTable" };
    KSW_RUNTIME_IMAGE_VIEW imageView;
    KSW_RUNTIME_DATA_REFERENCE references[KSW_SSDT_FALLBACK_REFERENCE_CAPACITY];
    ULONG referenceCount = 0UL;
    ULONG referenceIndex = 0UL;
    ULONG_PTR uniqueAddress = 0U;

    if (NtoskrnlIdentity == NULL || NtoskrnlIdentity->present == 0UL ||
        NtoskrnlIdentity->imageBase == 0ULL ||
        NtoskrnlIdentity->sizeOfImage == 0UL ||
        !KswordARKRuntimeInitializeImageView(
            (PVOID)(ULONG_PTR)NtoskrnlIdentity->imageBase,
            NtoskrnlIdentity->sizeOfImage,
            &imageView)) {
        return -1;
    }

    RtlZeroMemory(references, sizeof(references));
    referenceCount = KswordARKRuntimeCollectAnchoredDataReferences(
        &imageView,
        anchors,
        RTL_NUMBER_OF(anchors),
        1UL,
        KSW_SSDT_FALLBACK_ROUTINE_SCAN_BYTES,
        references,
        RTL_NUMBER_OF(references));
    for (referenceIndex = 0UL; referenceIndex < referenceCount; ++referenceIndex) {
        const ULONG_PTR candidateAddress = references[referenceIndex].Address;

        if (!KswordARKDriverSsdtValidateCandidate(&imageView, candidateAddress)) {
            continue;
        }
        if (uniqueAddress == 0U) {
            uniqueAddress = candidateAddress;
        }
        else if (uniqueAddress != candidateAddress) {
            return -1;
        }
    }

    if (uniqueAddress == 0U || uniqueAddress < imageView.Base ||
        uniqueAddress - imageView.Base > MAXLONG) {
        return -1;
    }
    return (LONG)(uniqueAddress - imageView.Base);
#endif
}
