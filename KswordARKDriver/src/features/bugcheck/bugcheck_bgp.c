/*++

Module Name:

    bugcheck_bgp.c

Abstract:

    Fail-closed physical-machine BGP resolver and crash-time drawing adapter.
    The private-kernel feature resolver follows the DriverGUI BgpDraw backend.

--*/

#include "bugcheck_bgp.h"
#include "bugcheck_bgp_internal.h"
#include "../../platform/pool_compat.h"

#include <aux_klib.h>
#include <ntimage.h>

#include "Generated/BgpSignatures.h"

#define KSWORD_ARK_BGP_POOL_TAG 'pBgK'
#define KSWORD_ARK_BGP_ALL_PRIVATE_FEATURES \
    (KSWORD_ARK_BGP_FEATURE_CLEAR | KSWORD_ARK_BGP_FEATURE_DRAW | \
     KSWORD_ARK_BGP_FEATURE_ACQUIRE | KSWORD_ARK_BGP_FEATURE_RELEASE | \
     KSWORD_ARK_BGP_FEATURE_RESOLUTION | KSWORD_ARK_BGP_FEATURE_BPP | \
     KSWORD_ARK_BGP_FEATURE_PARSE | KSWORD_ARK_BGP_FEATURE_DESTROY)

KSWORD_ARK_BGP_CONTEXT g_KswordArkBgp;

NTSYSAPI
PIMAGE_NT_HEADERS
NTAPI
RtlImageNtHeader(
    _In_ PVOID Base
    );

VOID
KswordARKBugcheckBgpRecordStage(
    _In_ LONG Stage,
    _In_ NTSTATUS Status
    )
{
    LONG timelineIndex;

    timelineIndex = InterlockedIncrement(&g_KswordArkBgp.TimelineCount) - 1;
    InterlockedExchange(&g_KswordArkBgp.Stage, Stage);
    if (timelineIndex >= 0 &&
        timelineIndex < (LONG)RTL_NUMBER_OF(g_KswordArkBgp.Timeline)) {
        InterlockedExchange(
            &g_KswordArkBgp.Timeline[timelineIndex].Status,
            (LONG)Status);
        InterlockedExchange(
            &g_KswordArkBgp.Timeline[timelineIndex].Stage,
            Stage);
    }
}

static PVOID
KswordARKBugcheckBgpGetExport(
    _In_z_ PCWSTR Name
    )
{
    UNICODE_STRING routineName;

    RtlInitUnicodeString(&routineName, Name);
    return MmGetSystemRoutineAddress(&routineName);
}

static BOOLEAN
KswordARKBugcheckBgpAddressInSection(
    _In_reads_bytes_(ImageSize) PUCHAR ImageBase,
    _In_ ULONG ImageSize,
    _In_opt_ PVOID Address,
    _In_ BOOLEAN AllowPaged
    )
{
    PIMAGE_NT_HEADERS64 ntHeaders;
    PIMAGE_SECTION_HEADER section;
    ULONG sectionIndex;
    ULONG_PTR addressRva;

    if (Address == NULL ||
        (PUCHAR)Address < ImageBase ||
        (PUCHAR)Address >= ImageBase + ImageSize) {
        return FALSE;
    }

    ntHeaders = (PIMAGE_NT_HEADERS64)RtlImageNtHeader(ImageBase);
    if (ntHeaders == NULL || ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
        return FALSE;
    }

    addressRva = (ULONG_PTR)((PUCHAR)Address - ImageBase);
    section = IMAGE_FIRST_SECTION(ntHeaders);
    for (sectionIndex = 0;
         sectionIndex < ntHeaders->FileHeader.NumberOfSections;
         ++sectionIndex, ++section) {
        ULONG sectionSize;

        sectionSize = max(section->Misc.VirtualSize, section->SizeOfRawData);
        if (addressRva < section->VirtualAddress ||
            addressRva >= section->VirtualAddress + sectionSize) {
            continue;
        }
        if ((section->Characteristics & IMAGE_SCN_MEM_EXECUTE) == 0) {
            return FALSE;
        }
        if (!AllowPaged &&
            (section->Characteristics & IMAGE_SCN_MEM_NOT_PAGED) == 0) {
            return FALSE;
        }
        return TRUE;
    }

    return FALSE;
}

static BOOLEAN
KswordARKBugcheckBgpMatches(
    _In_reads_bytes_(Signature->Length) const UCHAR* Address,
    _In_ const BGP_SIGNATURE* Signature
    )
{
    ULONG byteIndex;

    for (byteIndex = 0; byteIndex < Signature->Length; ++byteIndex) {
        if (Signature->Mask[byteIndex] == 'x' &&
            Address[byteIndex] != Signature->Bytes[byteIndex]) {
            return FALSE;
        }
    }

    return TRUE;
}

static BOOLEAN
KswordARKBugcheckBgpSectionNameMatches(
    _In_reads_(IMAGE_SIZEOF_SHORT_NAME) const UCHAR* Actual,
    _In_z_ const CHAR* Expected
    )
{
    ULONG characterIndex;

    for (characterIndex = 0;
         characterIndex < IMAGE_SIZEOF_SHORT_NAME;
         ++characterIndex) {
        if ((CHAR)Actual[characterIndex] != Expected[characterIndex]) {
            return FALSE;
        }
        if (Actual[characterIndex] == '\0') {
            return TRUE;
        }
    }

    return Expected[IMAGE_SIZEOF_SHORT_NAME] == '\0';
}

static PVOID
KswordARKBugcheckBgpDecodeRelativeCallAt(
    _In_reads_bytes_(Length) const UCHAR* Address,
    _In_ ULONG Length,
    _In_ ULONG Offset
    )
{
    LONG displacement;

    if (Offset > Length || Length - Offset < 5UL || Address[Offset] != 0xE8U) {
        return NULL;
    }

    RtlCopyMemory(&displacement, Address + Offset + 1UL, sizeof(displacement));
    return (PVOID)(Address + Offset + 5UL + displacement);
}

static const BGP_SIGNATURE*
KswordARKBugcheckBgpFindSignatureForEntry(
    _In_reads_bytes_(ImageSize) PUCHAR ImageBase,
    _In_ ULONG ImageSize,
    _In_ ULONG Target,
    _In_ PVOID Entry
    )
{
    PIMAGE_NT_HEADERS64 ntHeaders;
    PIMAGE_SECTION_HEADER section;
    ULONG sectionIndex;
    ULONG signatureIndex;
    ULONG_PTR entryRva;

    if (Target >= BgpSignatureCount ||
        (PUCHAR)Entry < ImageBase ||
        (PUCHAR)Entry >= ImageBase + ImageSize) {
        return NULL;
    }

    ntHeaders = (PIMAGE_NT_HEADERS64)RtlImageNtHeader(ImageBase);
    if (ntHeaders == NULL || ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
        return NULL;
    }

    entryRva = (ULONG_PTR)((PUCHAR)Entry - ImageBase);
    section = IMAGE_FIRST_SECTION(ntHeaders);
    for (sectionIndex = 0;
         sectionIndex < ntHeaders->FileHeader.NumberOfSections;
         ++sectionIndex, ++section) {
        ULONG sectionSize;

        sectionSize = min(
            section->Misc.VirtualSize,
            ImageSize - min(section->VirtualAddress, ImageSize));
        if (entryRva < section->VirtualAddress ||
            entryRva >= section->VirtualAddress + sectionSize ||
            (section->Characteristics & IMAGE_SCN_MEM_EXECUTE) == 0) {
            continue;
        }

        for (signatureIndex = 0;
             signatureIndex < BGP_SIGNATURE_TABLE_COUNT;
             ++signatureIndex) {
            const BGP_SIGNATURE* signature;
            ULONG_PTR matchRva;

            signature = &g_BgpSignatures[signatureIndex];
            if (signature->Target != Target ||
                signature->Section == NULL ||
                !KswordARKBugcheckBgpSectionNameMatches(
                    section->Name,
                    signature->Section) ||
                (!signature->AllowPaged &&
                 (section->Characteristics & IMAGE_SCN_MEM_NOT_PAGED) == 0)) {
                continue;
            }

            matchRva = entryRva + signature->EntryOffset;
            if (matchRva < entryRva ||
                matchRva < section->VirtualAddress ||
                matchRva > section->VirtualAddress + sectionSize ||
                signature->Length >
                    section->VirtualAddress + sectionSize - matchRva) {
                continue;
            }

            if (KswordARKBugcheckBgpMatches(ImageBase + matchRva, signature)) {
                return signature;
            }
        }
        break;
    }

    return NULL;
}

static VOID
KswordARKBugcheckBgpAcceptSignatureMatch(
    _In_reads_bytes_(ImageSize) PUCHAR ImageBase,
    _In_ ULONG ImageSize,
    _In_ const BGP_SIGNATURE* Signature,
    _In_ PUCHAR Match,
    _Inout_updates_(BgpSignatureCount) PVOID* Addresses,
    _Inout_updates_(BgpSignatureCount) const BGP_SIGNATURE** MatchedSignatures,
    _Inout_updates_(BgpSignatureCount) BOOLEAN* Ambiguous
    )
{
    PVOID resolvedAddress;
    ULONG targetIndex;

    resolvedAddress = Match - Signature->EntryOffset;
    targetIndex = Signature->Target;
    if (targetIndex >= BgpSignatureCount) {
        return;
    }
    if ((Signature->SemanticFlags & BGP_SEMANTIC_REQUIRE_DIRECT_CALL) != 0 &&
        (Signature->DirectCallOffset == MAXULONG ||
         !KswordARKBugcheckBgpAddressInSection(
             ImageBase,
             ImageSize,
             KswordARKBugcheckBgpDecodeRelativeCallAt(
                 Match,
                 Signature->Length,
                 Signature->DirectCallOffset),
             TRUE))) {
        return;
    }

    if (Addresses[targetIndex] == NULL) {
        Addresses[targetIndex] = resolvedAddress;
        MatchedSignatures[targetIndex] = Signature;
        g_KswordArkBgp.SignatureFamily[targetIndex] = Signature->Family;
    } else if (Addresses[targetIndex] != resolvedAddress) {
        Ambiguous[targetIndex] = TRUE;
    }
}

static NTSTATUS
KswordARKBugcheckBgpScanSignatures(
    _In_reads_bytes_(ImageSize) PUCHAR ImageBase,
    _In_ ULONG ImageSize,
    _Inout_updates_(BgpSignatureCount) PVOID* Addresses,
    _Inout_updates_(BgpSignatureCount) const BGP_SIGNATURE** MatchedSignatures,
    _Inout_updates_(BgpSignatureCount) BOOLEAN* Ambiguous
    )
{
    PIMAGE_NT_HEADERS64 ntHeaders;
    PIMAGE_SECTION_HEADER section;
    ULONG sectionIndex;

    ntHeaders = (PIMAGE_NT_HEADERS64)RtlImageNtHeader(ImageBase);
    if (ntHeaders == NULL || ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
        return STATUS_INVALID_IMAGE_FORMAT;
    }

    section = IMAGE_FIRST_SECTION(ntHeaders);
    for (sectionIndex = 0;
         sectionIndex < ntHeaders->FileHeader.NumberOfSections;
         ++sectionIndex, ++section) {
        ULONG offset;
        ULONG sectionSize;
        PUCHAR sectionBase;

        if ((section->Characteristics & IMAGE_SCN_MEM_EXECUTE) == 0 ||
            section->VirtualAddress >= ImageSize) {
            continue;
        }

        sectionSize = min(
            section->Misc.VirtualSize,
            ImageSize - section->VirtualAddress);
        if (sectionSize < sizeof(ULONG)) {
            continue;
        }

        sectionBase = ImageBase + section->VirtualAddress;
        for (offset = 0;
             offset <= sectionSize - sizeof(ULONG);
             ++offset) {
            ULONG anchor;
            ULONG bucket;
            ULONG signatureIndex;

            RtlCopyMemory(&anchor, sectionBase + offset, sizeof(anchor));
            bucket = anchor & (BGP_SIGNATURE_ANCHOR_BUCKETS - 1UL);
            for (signatureIndex = g_BgpSignatureAnchorBuckets[bucket];
                 signatureIndex < g_BgpSignatureAnchorBuckets[bucket + 1UL];
                 ++signatureIndex) {
                const BGP_SIGNATURE* signature;
                PUCHAR candidate;

                signature = &g_BgpSignatures[signatureIndex];
                if (signature->AnchorValue != anchor ||
                    signature->AnchorOffset > offset ||
                    signature->EntryOffset > offset - signature->AnchorOffset ||
                    signature->Length >
                        sectionSize - (offset - signature->AnchorOffset) ||
                    (!signature->AllowPaged &&
                     (section->Characteristics & IMAGE_SCN_MEM_NOT_PAGED) == 0) ||
                    signature->Section == NULL ||
                    !KswordARKBugcheckBgpSectionNameMatches(
                        section->Name,
                        signature->Section)) {
                    continue;
                }

                candidate = sectionBase + offset - signature->AnchorOffset;
                if (KswordARKBugcheckBgpMatches(candidate, signature)) {
                    KswordARKBugcheckBgpAcceptSignatureMatch(
                        ImageBase,
                        ImageSize,
                        signature,
                        candidate,
                        Addresses,
                        MatchedSignatures,
                        Ambiguous);
                }
            }
        }
    }

    return STATUS_SUCCESS;
}

static NTSTATUS
KswordARKBugcheckBgpGetKernelImage(
    _Out_ PUCHAR* ImageBase,
    _Out_ PULONG ImageSize
    )
{
    PAUX_MODULE_EXTENDED_INFO modules;
    ULONG requiredBytes;
    NTSTATUS status;

    *ImageBase = NULL;
    *ImageSize = 0;
    requiredBytes = 0;

    status = AuxKlibInitialize();
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = AuxKlibQueryModuleInformation(
        &requiredBytes,
        sizeof(AUX_MODULE_EXTENDED_INFO),
        NULL);
    if (!NT_SUCCESS(status) || requiredBytes < sizeof(AUX_MODULE_EXTENDED_INFO)) {
        return NT_SUCCESS(status) ? STATUS_NOT_FOUND : status;
    }

    modules = (PAUX_MODULE_EXTENDED_INFO)KswordARKAllocateNonPagedPool(
        requiredBytes,
        KSWORD_ARK_BGP_POOL_TAG);
    if (modules == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    status = AuxKlibQueryModuleInformation(
        &requiredBytes,
        sizeof(AUX_MODULE_EXTENDED_INFO),
        modules);
    if (NT_SUCCESS(status)) {
        *ImageBase = (PUCHAR)modules[0].BasicInfo.ImageBase;
        *ImageSize = modules[0].ImageSize;
    }

    ExFreePoolWithTag(modules, KSWORD_ARK_BGP_POOL_TAG);
    return status;
}

static BOOLEAN
KswordARKBugcheckBgpCrashTargetsAreNonPaged(
    _In_reads_bytes_(ImageSize) PUCHAR ImageBase,
    _In_ ULONG ImageSize,
    _In_reads_(BgpSignatureCount) PVOID* Addresses
    )
{
    const ULONG crashTargets[] = {
        BgpSignatureClear,
        BgpSignatureDraw,
        BgpSignatureAcquire,
        BgpSignatureRelease,
        BgpSignatureResolution,
        BgpSignatureBpp
    };
    ULONG targetIndex;

    for (targetIndex = 0;
         targetIndex < RTL_NUMBER_OF(crashTargets);
         ++targetIndex) {
        ULONG signatureTarget;

        signatureTarget = crashTargets[targetIndex];
        if (!KswordARKBugcheckBgpAddressInSection(
                ImageBase,
                ImageSize,
                Addresses[signatureTarget],
                FALSE)) {
            return FALSE;
        }
    }

    return TRUE;
}

NTSTATUS
KswordARKBugcheckBgpResolveFunctions(
    VOID
    )
{
    PUCHAR imageBase;
    ULONG imageSize;
    PVOID addresses[BgpSignatureCount] = { NULL };
    const BGP_SIGNATURE* matchedSignatures[BgpSignatureCount] = { NULL };
    BOOLEAN ambiguous[BgpSignatureCount] = { FALSE };
    PVOID semanticBpp;
    NTSTATUS status;
    ULONG targetIndex;

    imageBase = NULL;
    imageSize = 0;
    semanticBpp = NULL;
    status = KswordARKBugcheckBgpGetKernelImage(&imageBase, &imageSize);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = KswordARKBugcheckBgpScanSignatures(
        imageBase,
        imageSize,
        addresses,
        matchedSignatures,
        ambiguous);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    if (!ambiguous[BgpSignatureClear] &&
        !ambiguous[BgpSignatureDraw] &&
        addresses[BgpSignatureClear] != NULL &&
        addresses[BgpSignatureDraw] != NULL &&
        matchedSignatures[BgpSignatureClear] != NULL &&
        matchedSignatures[BgpSignatureDraw] != NULL) {
        PVOID clearBpp;
        PVOID drawBpp;

        clearBpp = KswordARKBugcheckBgpDecodeRelativeCallAt(
            (PUCHAR)addresses[BgpSignatureClear] +
                matchedSignatures[BgpSignatureClear]->EntryOffset,
            matchedSignatures[BgpSignatureClear]->Length,
            matchedSignatures[BgpSignatureClear]->DirectCallOffset);
        drawBpp = KswordARKBugcheckBgpDecodeRelativeCallAt(
            (PUCHAR)addresses[BgpSignatureDraw] +
                matchedSignatures[BgpSignatureDraw]->EntryOffset,
            matchedSignatures[BgpSignatureDraw]->Length,
            matchedSignatures[BgpSignatureDraw]->DirectCallOffset);
        if (clearBpp != NULL &&
            clearBpp == drawBpp &&
            KswordARKBugcheckBgpAddressInSection(
                imageBase,
                imageSize,
                clearBpp,
                FALSE)) {
            semanticBpp = clearBpp;
        }
    }

    for (targetIndex = 0;
         targetIndex < RTL_NUMBER_OF(addresses);
         ++targetIndex) {
        if (ambiguous[targetIndex]) {
            addresses[targetIndex] = NULL;
            matchedSignatures[targetIndex] = NULL;
            g_KswordArkBgp.SignatureFamily[targetIndex] = 0;
        }
    }

    if (semanticBpp != NULL) {
        const BGP_SIGNATURE* bppSignature;

        bppSignature = KswordARKBugcheckBgpFindSignatureForEntry(
            imageBase,
            imageSize,
            BgpSignatureBpp,
            semanticBpp);
        addresses[BgpSignatureBpp] = semanticBpp;
        matchedSignatures[BgpSignatureBpp] = bppSignature;
        ambiguous[BgpSignatureBpp] = FALSE;
        g_KswordArkBgp.SignatureFamily[BgpSignatureBpp] =
            bppSignature == NULL ? 0UL : bppSignature->Family;
    }

    if (addresses[BgpSignatureBpp] != NULL) {
        ULONG callerTarget;

        for (callerTarget = BgpSignatureClear;
             callerTarget <= BgpSignatureDraw;
             ++callerTarget) {
            const BGP_SIGNATURE* matchedSignature;

            matchedSignature = matchedSignatures[callerTarget];
            if (addresses[callerTarget] == NULL) {
                continue;
            }
            if (matchedSignature == NULL ||
                matchedSignature->DirectCallOffset == MAXULONG ||
                KswordARKBugcheckBgpDecodeRelativeCallAt(
                    (PUCHAR)addresses[callerTarget] +
                        matchedSignature->EntryOffset,
                    matchedSignature->Length,
                    matchedSignature->DirectCallOffset) !=
                    addresses[BgpSignatureBpp]) {
                addresses[callerTarget] = NULL;
                g_KswordArkBgp.SignatureFamily[callerTarget] = 0;
            }
        }
    }

    if (!KswordARKBugcheckBgpCrashTargetsAreNonPaged(
            imageBase,
            imageSize,
            addresses) ||
        !KswordARKBugcheckBgpAddressInSection(
            imageBase,
            imageSize,
            addresses[BgpSignatureParse],
            TRUE) ||
        !KswordARKBugcheckBgpAddressInSection(
            imageBase,
            imageSize,
            addresses[BgpSignatureDestroy],
            TRUE)) {
        return STATUS_PROCEDURE_NOT_FOUND;
    }

    g_KswordArkBgp.Clear =
        (PKSWORD_ARK_BGP_CLEAR_SCREEN)addresses[BgpSignatureClear];
    g_KswordArkBgp.Draw =
        (PKSWORD_ARK_BGP_DRAW_RECTANGLE)addresses[BgpSignatureDraw];
    g_KswordArkBgp.Acquire =
        (PKSWORD_ARK_BGP_LOCK)addresses[BgpSignatureAcquire];
    g_KswordArkBgp.Release =
        (PKSWORD_ARK_BGP_LOCK)addresses[BgpSignatureRelease];
    g_KswordArkBgp.GetResolution =
        (PKSWORD_ARK_BGP_GET_RESOLUTION)addresses[BgpSignatureResolution];
    g_KswordArkBgp.GetBpp =
        (PKSWORD_ARK_BGP_GET_BPP)addresses[BgpSignatureBpp];
    g_KswordArkBgp.ParseBitmap =
        (PKSWORD_ARK_BGP_PARSE_BITMAP)addresses[BgpSignatureParse];
    g_KswordArkBgp.DestroyRectangle =
        (PKSWORD_ARK_BGP_DESTROY_RECTANGLE)addresses[BgpSignatureDestroy];
    g_KswordArkBgp.AcquireOwnership =
        (PKSWORD_ARK_INBV_ACQUIRE_DISPLAY_OWNERSHIP)
            KswordARKBugcheckBgpGetExport(L"InbvAcquireDisplayOwnership");

    g_KswordArkBgp.FeatureMask = KSWORD_ARK_BGP_ALL_PRIVATE_FEATURES;
    if (g_KswordArkBgp.AcquireOwnership != NULL &&
        KswordARKBugcheckBgpAddressInSection(
            imageBase,
            imageSize,
            (PVOID)(ULONG_PTR)g_KswordArkBgp.AcquireOwnership,
            FALSE)) {
        g_KswordArkBgp.FeatureMask |= KSWORD_ARK_BGP_FEATURE_INBV;
    } else {
        g_KswordArkBgp.AcquireOwnership = NULL;
    }

    if ((g_KswordArkBgp.FeatureMask &
         (KSWORD_ARK_BGP_ALL_PRIVATE_FEATURES |
          KSWORD_ARK_BGP_FEATURE_INBV)) !=
        (KSWORD_ARK_BGP_ALL_PRIVATE_FEATURES |
         KSWORD_ARK_BGP_FEATURE_INBV)) {
        return STATUS_PROCEDURE_NOT_FOUND;
    }

    return STATUS_SUCCESS;
}

NTSTATUS
KswordARKBugcheckBgpReadScreen(
    _Out_ PKSWORD_ARK_BGP_SCREEN_INFO Screen
    )
{
    ULONG resolution[3];
    ULONG bitsPerPixel;

    RtlZeroMemory(resolution, sizeof(resolution));
    RtlZeroMemory(Screen, sizeof(*Screen));
    if (g_KswordArkBgp.GetResolution == NULL ||
        g_KswordArkBgp.GetBpp == NULL) {
        return STATUS_PROCEDURE_NOT_FOUND;
    }

    if (g_KswordArkBgp.GetResolution(resolution) == NULL) {
        return STATUS_UNSUCCESSFUL;
    }

    bitsPerPixel = g_KswordArkBgp.GetBpp();
    if (resolution[0] == 0 ||
        resolution[1] == 0 ||
        (bitsPerPixel != 24UL && bitsPerPixel != 32UL)) {
        return STATUS_NOT_SUPPORTED;
    }

    Screen->Width = resolution[0];
    Screen->Height = resolution[1];
    Screen->BitsPerPixel = bitsPerPixel;
    return STATUS_SUCCESS;
}

NTSTATUS
KswordARKBugcheckBgpValidateBitmap(
    _In_reads_bytes_(BitmapLength) const VOID* Bitmap,
    _In_ ULONG BitmapLength
    )
{
    const KSWORD_ARK_BGP_BITMAP_FILE_HEADER* fileHeader;
    const KSWORD_ARK_BGP_BITMAP_INFO_HEADER* infoHeader;
    ULONG64 rowBytes;
    ULONG64 requiredBytes;

    if (Bitmap == NULL ||
        BitmapLength <
            sizeof(KSWORD_ARK_BGP_BITMAP_FILE_HEADER) +
            sizeof(KSWORD_ARK_BGP_BITMAP_INFO_HEADER)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    fileHeader = (const KSWORD_ARK_BGP_BITMAP_FILE_HEADER*)Bitmap;
    infoHeader = (const KSWORD_ARK_BGP_BITMAP_INFO_HEADER*)(
        (const UCHAR*)Bitmap + sizeof(*fileHeader));
    if (fileHeader->Type != 0x4D42U ||
        fileHeader->Size > BitmapLength ||
        fileHeader->Size < fileHeader->PixelOffset ||
        fileHeader->PixelOffset < sizeof(*fileHeader) + sizeof(*infoHeader) ||
        infoHeader->Size != sizeof(*infoHeader) ||
        infoHeader->Width <= 0 ||
        infoHeader->Height <= 0 ||
        infoHeader->Planes != 1U ||
        infoHeader->Compression != 0UL ||
        (infoHeader->BitsPerPixel != 24U &&
         infoHeader->BitsPerPixel != 32U)) {
        return STATUS_INVALID_IMAGE_FORMAT;
    }

    if (g_KswordArkBgp.Screen.Width == 0 ||
        g_KswordArkBgp.Screen.Height == 0 ||
        g_KswordArkBgp.Screen.BitsPerPixel != infoHeader->BitsPerPixel ||
        (ULONG)infoHeader->Width > g_KswordArkBgp.Screen.Width ||
        (ULONG)infoHeader->Height > g_KswordArkBgp.Screen.Height) {
        return STATUS_NOT_SUPPORTED;
    }

    rowBytes =
        (((ULONG64)(ULONG)infoHeader->Width *
          infoHeader->BitsPerPixel + 31ULL) / 32ULL) * 4ULL;
    requiredBytes =
        (ULONG64)fileHeader->PixelOffset +
        rowBytes * (ULONG)infoHeader->Height;
    if (rowBytes > MAXULONG ||
        requiredBytes > BitmapLength ||
        requiredBytes > fileHeader->Size) {
        return STATUS_INVALID_IMAGE_FORMAT;
    }

    return STATUS_SUCCESS;
}

NTSTATUS
KswordARKBugcheckBgpBeginDraw(
    VOID
    )
{
    KSWORD_ARK_BGP_SCREEN_INFO crashScreen;
    NTSTATUS status;

    if (InterlockedCompareExchange(&g_KswordArkBgp.DrawStarted, 1, 0) != 0) {
        return STATUS_DEVICE_BUSY;
    }

    KswordARKBugcheckBgpRecordStage(
        KswordArkBgpStageCallbackEntered,
        STATUS_SUCCESS);
    if (InterlockedCompareExchange(
            &g_KswordArkBgp.State,
            0,
            0) != KswordArkBgpStateArmed ||
        g_KswordArkBgp.AcquireOwnership == NULL ||
        g_KswordArkBgp.Acquire == NULL ||
        g_KswordArkBgp.Release == NULL) {
        status = STATUS_DEVICE_NOT_READY;
        InterlockedExchange(&g_KswordArkBgp.LastStatus, (LONG)status);
        KswordARKBugcheckBgpRecordStage(
            (LONG)(KswordArkBgpStageRejected | 1UL),
            status);
        return status;
    }

    KswordARKBugcheckBgpRecordStage(
        KswordArkBgpStageOwnershipBefore,
        STATUS_PENDING);
    g_KswordArkBgp.AcquireOwnership();
    KswordARKBugcheckBgpRecordStage(
        KswordArkBgpStageOwnershipAfter,
        STATUS_SUCCESS);

    KswordARKBugcheckBgpRecordStage(
        KswordArkBgpStageAcquireBefore,
        STATUS_PENDING);
    g_KswordArkBgp.Acquire();
    InterlockedExchange(&g_KswordArkBgp.LockHeld, 1);
    KswordARKBugcheckBgpRecordStage(
        KswordArkBgpStageAcquireAfter,
        STATUS_SUCCESS);

    KswordARKBugcheckBgpRecordStage(
        KswordArkBgpStageScreenBefore,
        STATUS_PENDING);
    status = KswordARKBugcheckBgpReadScreen(&crashScreen);
    InterlockedExchange(&g_KswordArkBgp.LastStatus, (LONG)status);
    KswordARKBugcheckBgpRecordStage(
        KswordArkBgpStageScreenAfter,
        status);
    if (!NT_SUCCESS(status) ||
        crashScreen.Width != g_KswordArkBgp.Screen.Width ||
        crashScreen.Height != g_KswordArkBgp.Screen.Height ||
        crashScreen.BitsPerPixel != g_KswordArkBgp.Screen.BitsPerPixel ||
        g_KswordArkBgp.RequiredWidth > crashScreen.Width ||
        g_KswordArkBgp.RequiredHeight > crashScreen.Height) {
        status = NT_SUCCESS(status) ? STATUS_NOT_SUPPORTED : status;
        InterlockedExchange(&g_KswordArkBgp.LastStatus, (LONG)status);
        InterlockedExchange(
            &g_KswordArkBgp.State,
            KswordArkBgpStateRejected);
        KswordARKBugcheckBgpRecordStage(
            (LONG)(KswordArkBgpStageRejected | 2UL),
            status);
        KswordARKBugcheckBgpRecordStage(
            KswordArkBgpStageReleaseBefore,
            STATUS_PENDING);
        g_KswordArkBgp.Release();
        InterlockedExchange(&g_KswordArkBgp.LockHeld, 0);
        KswordARKBugcheckBgpRecordStage(
            KswordArkBgpStageReleaseAfter,
            STATUS_SUCCESS);
        return status;
    }

    return STATUS_SUCCESS;
}

NTSTATUS
KswordARKBugcheckBgpClearScreen(
    _In_ ULONG ArgbColor
    )
{
    NTSTATUS status;

    if (InterlockedCompareExchange(&g_KswordArkBgp.LockHeld, 0, 0) == 0 ||
        g_KswordArkBgp.Clear == NULL) {
        return STATUS_DEVICE_NOT_READY;
    }

    KswordARKBugcheckBgpRecordStage(
        KswordArkBgpStageClearBefore,
        STATUS_PENDING);
    status = g_KswordArkBgp.Clear(ArgbColor);
    InterlockedExchange(&g_KswordArkBgp.ClearStatus, (LONG)status);
    InterlockedExchange(&g_KswordArkBgp.LastStatus, (LONG)status);
    KswordARKBugcheckBgpRecordStage(
        KswordArkBgpStageClearAfter,
        status);
    return status;
}

NTSTATUS
KswordARKBugcheckBgpDrawRectangle(
    _In_ PVOID Rectangle,
    _In_ LONG X,
    _In_ LONG Y
    )
{
    KSWORD_ARK_BGP_POSITION position;
    NTSTATUS status;

    if (Rectangle == NULL ||
        InterlockedCompareExchange(&g_KswordArkBgp.LockHeld, 0, 0) == 0 ||
        g_KswordArkBgp.Draw == NULL) {
        return STATUS_DEVICE_NOT_READY;
    }

    if (InterlockedCompareExchange(
            &g_KswordArkBgp.DrawStageStarted,
            1,
            0) == 0) {
        KswordARKBugcheckBgpRecordStage(
            KswordArkBgpStageDrawBefore,
            STATUS_PENDING);
    }

    position.X = X;
    position.Y = Y;
    status = g_KswordArkBgp.Draw(Rectangle, &position);
    InterlockedExchange(&g_KswordArkBgp.DrawStatus, (LONG)status);
    InterlockedExchange(&g_KswordArkBgp.LastStatus, (LONG)status);
    return status;
}

VOID
KswordARKBugcheckBgpFinishDraw(
    _In_ NTSTATUS DrawStatus
    )
{
    if (InterlockedCompareExchange(
            &g_KswordArkBgp.DrawStageStarted,
            1,
            0) == 0) {
        KswordARKBugcheckBgpRecordStage(
            KswordArkBgpStageDrawBefore,
            DrawStatus);
    }
    InterlockedExchange(&g_KswordArkBgp.DrawStatus, (LONG)DrawStatus);
    InterlockedExchange(&g_KswordArkBgp.LastStatus, (LONG)DrawStatus);
    KswordARKBugcheckBgpRecordStage(
        KswordArkBgpStageDrawAfter,
        DrawStatus);

    if (InterlockedExchange(&g_KswordArkBgp.LockHeld, 0) != 0 &&
        g_KswordArkBgp.Release != NULL) {
        KswordARKBugcheckBgpRecordStage(
            KswordArkBgpStageReleaseBefore,
            STATUS_PENDING);
        g_KswordArkBgp.Release();
        KswordARKBugcheckBgpRecordStage(
            KswordArkBgpStageReleaseAfter,
            STATUS_SUCCESS);
    }

    InterlockedIncrement64(&g_KswordArkBgp.DrawCount);
    InterlockedExchange(
        &g_KswordArkBgp.State,
        NT_SUCCESS(DrawStatus)
            ? KswordArkBgpStateDrawn
            : KswordArkBgpStateRejected);
    KswordARKBugcheckBgpRecordStage(
        KswordArkBgpStageComplete,
        DrawStatus);
}
