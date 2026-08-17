/*++

Module Name:

    bugcheck_panel.c

Abstract:

    PASSIVE_LEVEL preparation and crash-time rendering for the physical BGP
    diagnostic panel. The callback path uses only fixed nonpaged buffers and
    rectangles created before the bugcheck occurs.

--*/

#include "bugcheck_internal.h"
#include "bugcheck_bgp.h"
#include "bugcheck_layout.h"
#include "bugcheck_panel.h"
#include "../../platform/pool_compat.h"

#include "Generated/AsciiFont8x12.h"
#include "Generated/MainLogoBitmap.h"

#define KSWORD_ARK_PANEL_POOL_TAG 'lPgK'
#define KSWORD_ARK_PANEL_BACKGROUND_ARGB 0xFF050F21UL
#define KSWORD_ARK_PANEL_GLYPH_ADVANCE 9L
#define KSWORD_ARK_PANEL_GLYPH_BORDER 1UL
#define KSWORD_ARK_PANEL_GLYPH_BITMAP_WIDTH \
    (DRIVERGUI_FONT_WIDTH + (KSWORD_ARK_PANEL_GLYPH_BORDER * 2UL))
#define KSWORD_ARK_PANEL_GLYPH_BITMAP_HEIGHT \
    (DRIVERGUI_FONT_HEIGHT + (KSWORD_ARK_PANEL_GLYPH_BORDER * 2UL))
#define KSWORD_ARK_PANEL_COLOR_COUNT \
    ((ULONG)KswordArkBugcheckLayoutColorCount)
#define KSWORD_ARK_PANEL_BPP24_INDEX 0UL
#define KSWORD_ARK_PANEL_BPP32_INDEX 1UL
#define KSWORD_ARK_PANEL_BPP_VARIANT_COUNT 2UL
#define KSWORD_ARK_PANEL_VERDICT_SET_COUNT 2UL

#pragma pack(push, 1)
typedef struct _KSWORD_ARK_PANEL_BITMAP_FILE_HEADER
{
    USHORT Type;
    ULONG Size;
    USHORT Reserved1;
    USHORT Reserved2;
    ULONG PixelOffset;
} KSWORD_ARK_PANEL_BITMAP_FILE_HEADER, *PKSWORD_ARK_PANEL_BITMAP_FILE_HEADER;

typedef struct _KSWORD_ARK_PANEL_BITMAP_INFO_HEADER
{
    ULONG Size;
    LONG Width;
    LONG Height;
    USHORT Planes;
    USHORT BitsPerPixel;
    ULONG Compression;
    ULONG ImageSize;
    LONG XPelsPerMeter;
    LONG YPelsPerMeter;
    ULONG ColorsUsed;
    ULONG ColorsImportant;
} KSWORD_ARK_PANEL_BITMAP_INFO_HEADER, *PKSWORD_ARK_PANEL_BITMAP_INFO_HEADER;
#pragma pack(pop)

typedef struct _KSWORD_ARK_PANEL_VARIANT
{
    ULONG BitsPerPixel;
    PVOID LogoRectangle;
    PVOID GlyphRectangles[KSWORD_ARK_PANEL_COLOR_COUNT][DRIVERGUI_FONT_COUNT];
    PVOID FrameHorizontalRectangles[KswordArkBugcheckLayoutFrameCount];
    PVOID FrameVerticalRectangles[KswordArkBugcheckLayoutFrameCount];
    // Keep the source BMPs resident for the lifetime of the parsed glyphs.
    // BgpGxParseBitmap is private and its ownership contract is not documented.
    // A persistent nonpaged backing buffer prevents a small-rectangle parser
    // from retaining a reused preparation stack buffer.
    PUCHAR GlyphBitmaps[KSWORD_ARK_PANEL_COLOR_COUNT][DRIVERGUI_FONT_COUNT];
    PUCHAR FrameHorizontalBitmaps[KswordArkBugcheckLayoutFrameCount];
    PUCHAR FrameVerticalBitmaps[KswordArkBugcheckLayoutFrameCount];
} KSWORD_ARK_PANEL_VARIANT, *PKSWORD_ARK_PANEL_VARIANT;

typedef struct _KSWORD_ARK_PANEL_VERDICT_ITEM
{
    PVOID Rectangle;
    PUCHAR BackingBitmap;
    ULONG Width;
    ULONG Height;
} KSWORD_ARK_PANEL_VERDICT_ITEM, *PKSWORD_ARK_PANEL_VERDICT_ITEM;

typedef struct _KSWORD_ARK_PANEL_VERDICT_SET
{
    BOOLEAN Complete;
    KSWORD_ARK_PANEL_VERDICT_ITEM
        Items[KSWORD_ARK_PANEL_BPP_VARIANT_COUNT]
             [KSWORD_ARK_BUGCHECK_VERDICT_LANGUAGE_COUNT]
             [KSWORD_ARK_BUGCHECK_VERDICT_CLASS_COUNT];
} KSWORD_ARK_PANEL_VERDICT_SET, *PKSWORD_ARK_PANEL_VERDICT_SET;

typedef struct _KSWORD_ARK_PANEL_STATE
{
    volatile LONG Ready;
    volatile LONG ActiveVariant;
    volatile LONG ActiveVerdictSet;
    volatile LONG PreferredLanguage;
    KSWORD_ARK_PANEL_VARIANT Variants[KSWORD_ARK_PANEL_BPP_VARIANT_COUNT];
    KSWORD_ARK_PANEL_VERDICT_SET
        VerdictSets[KSWORD_ARK_PANEL_VERDICT_SET_COUNT];
} KSWORD_ARK_PANEL_STATE, *PKSWORD_ARK_PANEL_STATE;

static KSWORD_ARK_PANEL_STATE g_KswordArkPanel;

C_ASSERT(
    KSWORD_ARK_BUGCHECK_VERDICT_CLASS_UNKNOWN ==
    KSWORD_ARK_BUGCHECK_MODULE_UNKNOWN);
C_ASSERT(
    KSWORD_ARK_BUGCHECK_VERDICT_CLASS_OURS ==
    KSWORD_ARK_BUGCHECK_MODULE_OURS);
C_ASSERT(
    KSWORD_ARK_BUGCHECK_VERDICT_CLASS_MICROSOFT ==
    KSWORD_ARK_BUGCHECK_MODULE_MICROSOFT);
C_ASSERT(
    KSWORD_ARK_BUGCHECK_VERDICT_CLASS_THIRD_PARTY ==
    KSWORD_ARK_BUGCHECK_MODULE_THIRD_PARTY);

static NTSTATUS
KswordARKBugcheckPanelInitializeBitmap(
    _Out_writes_bytes_(BitmapCapacity) UCHAR* Bitmap,
    _In_ ULONG BitmapCapacity,
    _In_ ULONG Width,
    _In_ ULONG Height,
    _In_ ULONG BitsPerPixel,
    _Out_ PULONG BitmapLength,
    _Out_ PULONG BitmapStride,
    _Out_ PUCHAR* PixelBytes
    )
{
    PKSWORD_ARK_PANEL_BITMAP_FILE_HEADER fileHeader;
    PKSWORD_ARK_PANEL_BITMAP_INFO_HEADER infoHeader;
    ULONG64 stride;
    ULONG64 imageBytes;
    ULONG64 totalBytes;

    if (Bitmap == NULL ||
        BitmapLength == NULL ||
        BitmapStride == NULL ||
        PixelBytes == NULL ||
        Width == 0 ||
        Height == 0 ||
        (BitsPerPixel != 24UL && BitsPerPixel != 32UL)) {
        return STATUS_INVALID_PARAMETER;
    }

    stride = (((ULONG64)Width * BitsPerPixel + 31ULL) / 32ULL) * 4ULL;
    imageBytes = stride * Height;
    totalBytes =
        sizeof(KSWORD_ARK_PANEL_BITMAP_FILE_HEADER) +
        sizeof(KSWORD_ARK_PANEL_BITMAP_INFO_HEADER) +
        imageBytes;
    if (stride > MAXULONG ||
        imageBytes > MAXULONG ||
        totalBytes > BitmapCapacity ||
        totalBytes > MAXULONG) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    RtlZeroMemory(Bitmap, (SIZE_T)totalBytes);
    fileHeader = (PKSWORD_ARK_PANEL_BITMAP_FILE_HEADER)Bitmap;
    infoHeader = (PKSWORD_ARK_PANEL_BITMAP_INFO_HEADER)(Bitmap + sizeof(*fileHeader));
    fileHeader->Type = 0x4D42U;
    fileHeader->Size = (ULONG)totalBytes;
    fileHeader->PixelOffset = sizeof(*fileHeader) + sizeof(*infoHeader);
    infoHeader->Size = sizeof(*infoHeader);
    infoHeader->Width = (LONG)Width;
    infoHeader->Height = (LONG)Height;
    infoHeader->Planes = 1U;
    infoHeader->BitsPerPixel = (USHORT)BitsPerPixel;
    infoHeader->ImageSize = (ULONG)imageBytes;

    *BitmapLength = (ULONG)totalBytes;
    *BitmapStride = (ULONG)stride;
    *PixelBytes = Bitmap + fileHeader->PixelOffset;
    return STATUS_SUCCESS;
}

typedef NTSTATUS
(NTAPI *PKSWORD_ARK_ZW_QUERY_DEFAULT_UI_LANGUAGE)(
    _Out_ PUSHORT DefaultUILanguageId
    );

static ULONG
KswordARKBugcheckPanelQueryPreferredLanguage(
    VOID
    )
{
    UNICODE_STRING routineName;
    PKSWORD_ARK_ZW_QUERY_DEFAULT_UI_LANGUAGE queryLanguage;
    USHORT languageId;

    languageId = 0;
    RtlInitUnicodeString(&routineName, L"ZwQueryDefaultUILanguage");
    queryLanguage = (PKSWORD_ARK_ZW_QUERY_DEFAULT_UI_LANGUAGE)
        MmGetSystemRoutineAddress(&routineName);
    if (queryLanguage != NULL &&
        NT_SUCCESS(queryLanguage(&languageId)) &&
        (languageId & 0x03FFU) == 0x0004U) {
        return KSWORD_ARK_BUGCHECK_VERDICT_LANGUAGE_CHINESE;
    }
    return KSWORD_ARK_BUGCHECK_VERDICT_LANGUAGE_ENGLISH;
}

static VOID
KswordARKBugcheckPanelReleaseVerdictSet(
    _Inout_ PKSWORD_ARK_PANEL_VERDICT_SET VerdictSet
    )
{
    ULONG variantIndex;

    if (VerdictSet == NULL) {
        return;
    }
    VerdictSet->Complete = FALSE;
    for (variantIndex = 0;
         variantIndex < KSWORD_ARK_PANEL_BPP_VARIANT_COUNT;
         ++variantIndex) {
        ULONG language;

        for (language = 0;
             language < KSWORD_ARK_BUGCHECK_VERDICT_LANGUAGE_COUNT;
             ++language) {
            ULONG classification;

            for (classification = 0;
                 classification < KSWORD_ARK_BUGCHECK_VERDICT_CLASS_COUNT;
                 ++classification) {
                PKSWORD_ARK_PANEL_VERDICT_ITEM item;

                item = &VerdictSet->Items[variantIndex]
                    [language][classification];
                KswordARKBugcheckBgpDestroyRectangle(item->Rectangle);
                item->Rectangle = NULL;
                if (item->BackingBitmap != NULL) {
                    ExFreePoolWithTag(
                        item->BackingBitmap,
                        KSWORD_ARK_PANEL_POOL_TAG);
                    item->BackingBitmap = NULL;
                }
                item->Width = 0;
                item->Height = 0;
            }
        }
    }
}

static NTSTATUS
KswordARKBugcheckPanelValidateVerdictPacket(
    _In_reads_bytes_(PacketLength) const VOID* Packet,
    _In_ ULONG PacketLength,
    _Out_ const KSWORD_ARK_BUGCHECK_VERDICT_RESOURCE_ENTRY** Entries
    )
{
    const KSWORD_ARK_BUGCHECK_VERDICT_RESOURCE_HEADER* header;
    const KSWORD_ARK_BUGCHECK_VERDICT_RESOURCE_ENTRY* entries;
    ULONG64 entriesBytes;
    ULONG64 minimumDataOffset;
    ULONG64 totalDataBytes;
    ULONG seenMask;
    ULONG index;

    if (Packet == NULL || Entries == NULL ||
        PacketLength < sizeof(*header)) {
        return STATUS_BUFFER_TOO_SMALL;
    }
    *Entries = NULL;
    header = (const KSWORD_ARK_BUGCHECK_VERDICT_RESOURCE_HEADER*)Packet;
    entriesBytes =
        (ULONG64)sizeof(KSWORD_ARK_BUGCHECK_VERDICT_RESOURCE_ENTRY) *
        KSWORD_ARK_BUGCHECK_VERDICT_RESOURCE_COUNT;
    minimumDataOffset = (ULONG64)sizeof(*header) + entriesBytes;
    if (header->version != KSWORD_ARK_BUGCHECK_VERDICT_PROTOCOL_VERSION ||
        header->size != sizeof(*header) ||
        header->magic != KSWORD_ARK_BUGCHECK_VERDICT_MAGIC ||
        header->resourceCount !=
            KSWORD_ARK_BUGCHECK_VERDICT_RESOURCE_COUNT ||
        header->entriesOffset != sizeof(*header) ||
        header->totalSize != PacketLength ||
        header->flags != 0 || header->reserved != 0 ||
        minimumDataOffset > PacketLength) {
        return STATUS_INVALID_PARAMETER;
    }

    entries = (const KSWORD_ARK_BUGCHECK_VERDICT_RESOURCE_ENTRY*)(
        (const UCHAR*)Packet + header->entriesOffset);
    totalDataBytes = 0;
    seenMask = 0;
    for (index = 0;
         index < KSWORD_ARK_BUGCHECK_VERDICT_RESOURCE_COUNT;
         ++index) {
        const KSWORD_ARK_BUGCHECK_VERDICT_RESOURCE_ENTRY* entry;
        ULONG64 expectedStride;
        ULONG64 expectedBytes;
        ULONG64 dataEnd;
        ULONG bitIndex;
        ULONG bit;

        entry = &entries[index];
        expectedStride = (ULONG64)entry->width * 4ULL;
        expectedBytes = expectedStride * entry->height;
        dataEnd = (ULONG64)entry->dataOffset + entry->dataLength;
        if (entry->language >=
                KSWORD_ARK_BUGCHECK_VERDICT_LANGUAGE_COUNT ||
            entry->classification >=
                KSWORD_ARK_BUGCHECK_VERDICT_CLASS_COUNT ||
            entry->width == 0 || entry->height == 0 ||
            entry->width > KSWORD_ARK_BUGCHECK_VERDICT_MAX_WIDTH ||
            entry->height > KSWORD_ARK_BUGCHECK_VERDICT_MAX_HEIGHT ||
            entry->format != KSWORD_ARK_BUGCHECK_VERDICT_FORMAT_BGRA32 ||
            expectedStride != entry->stride ||
            expectedBytes == 0 || expectedBytes != entry->dataLength ||
            entry->dataOffset < minimumDataOffset ||
            dataEnd > PacketLength) {
            return STATUS_INVALID_PARAMETER;
        }

        bitIndex = entry->language *
            KSWORD_ARK_BUGCHECK_VERDICT_CLASS_COUNT +
            entry->classification;
        bit = 1UL << bitIndex;
        if ((seenMask & bit) != 0) {
            return STATUS_INVALID_PARAMETER;
        }
        seenMask |= bit;
        totalDataBytes += entry->dataLength;
        if (totalDataBytes >
            KSWORD_ARK_BUGCHECK_VERDICT_MAX_DATA_BYTES) {
            return STATUS_INVALID_PARAMETER;
        }
    }

    if (seenMask !=
        ((1UL << KSWORD_ARK_BUGCHECK_VERDICT_RESOURCE_COUNT) - 1UL)) {
        return STATUS_INVALID_PARAMETER;
    }
    *Entries = entries;
    return STATUS_SUCCESS;
}

static NTSTATUS
KswordARKBugcheckPanelPrepareVerdictItem(
    _In_ ULONG BitsPerPixel,
    _In_ const KSWORD_ARK_BUGCHECK_VERDICT_RESOURCE_ENTRY* Entry,
    _In_reads_bytes_(Entry->dataLength) const UCHAR* SourcePixels,
    _Out_ PKSWORD_ARK_PANEL_VERDICT_ITEM Item
    )
{
    PUCHAR bitmap;
    PUCHAR pixels;
    ULONG64 bitmapCapacity64;
    ULONG bitmapCapacity;
    ULONG bitmapLength;
    ULONG bitmapStride;
    ULONG bytesPerPixel;
    ULONG y;
    NTSTATUS status;

    if (Entry == NULL || SourcePixels == NULL || Item == NULL ||
        (BitsPerPixel != 24UL && BitsPerPixel != 32UL)) {
        return STATUS_INVALID_PARAMETER;
    }
    RtlZeroMemory(Item, sizeof(*Item));
    bitmapCapacity64 =
        sizeof(KSWORD_ARK_PANEL_BITMAP_FILE_HEADER) +
        sizeof(KSWORD_ARK_PANEL_BITMAP_INFO_HEADER) +
        ((((ULONG64)Entry->width * BitsPerPixel + 31ULL) / 32ULL) *
         4ULL * Entry->height);
    if (bitmapCapacity64 > MAXULONG) {
        return STATUS_INTEGER_OVERFLOW;
    }
    bitmapCapacity = (ULONG)bitmapCapacity64;
    bitmap = (PUCHAR)KswordARKAllocateNonPagedPool(
        bitmapCapacity,
        KSWORD_ARK_PANEL_POOL_TAG);
    if (bitmap == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    pixels = NULL;
    status = KswordARKBugcheckPanelInitializeBitmap(
        bitmap,
        bitmapCapacity,
        Entry->width,
        Entry->height,
        BitsPerPixel,
        &bitmapLength,
        &bitmapStride,
        &pixels);
    if (!NT_SUCCESS(status)) {
        ExFreePoolWithTag(bitmap, KSWORD_ARK_PANEL_POOL_TAG);
        return status;
    }

    bytesPerPixel = BitsPerPixel / 8UL;
    for (y = 0; y < Entry->height; ++y) {
        const UCHAR* sourceRow;
        PUCHAR destinationRow;
        ULONG x;

        sourceRow = SourcePixels + ((SIZE_T)y * Entry->stride);
        destinationRow = pixels +
            ((SIZE_T)(Entry->height - 1UL - y) * bitmapStride);
        for (x = 0; x < Entry->width; ++x) {
            const UCHAR* sourcePixel;
            PUCHAR destinationPixel;
            ULONG alpha;

            sourcePixel = sourceRow + ((SIZE_T)x * 4UL);
            destinationPixel = destinationRow +
                ((SIZE_T)x * bytesPerPixel);
            alpha = sourcePixel[3];
            destinationPixel[0] = (UCHAR)(
                (sourcePixel[0] * alpha +
                 KSWORD_ARK_BUGCHECK_LAYOUT_BACKGROUND_BLUE *
                    (255UL - alpha)) / 255UL);
            destinationPixel[1] = (UCHAR)(
                (sourcePixel[1] * alpha +
                 KSWORD_ARK_BUGCHECK_LAYOUT_BACKGROUND_GREEN *
                    (255UL - alpha)) / 255UL);
            destinationPixel[2] = (UCHAR)(
                (sourcePixel[2] * alpha +
                 KSWORD_ARK_BUGCHECK_LAYOUT_BACKGROUND_RED *
                    (255UL - alpha)) / 255UL);
            if (bytesPerPixel == 4UL) {
                destinationPixel[3] = 0xFFU;
            }
        }
    }

    status = KswordARKBugcheckBgpParseBitmap(
        bitmap,
        bitmapLength,
        &Item->Rectangle);
    if (!NT_SUCCESS(status)) {
        ExFreePoolWithTag(bitmap, KSWORD_ARK_PANEL_POOL_TAG);
        return status;
    }
    Item->BackingBitmap = bitmap;
    Item->Width = Entry->width;
    Item->Height = Entry->height;
    return STATUS_SUCCESS;
}

NTSTATUS
KswordARKBugcheckPanelInstallVerdictResources(
    _In_reads_bytes_(PacketLength) const VOID* Packet,
    _In_ ULONG PacketLength
    )
{
    const KSWORD_ARK_BUGCHECK_VERDICT_RESOURCE_ENTRY* entries;
    PKSWORD_ARK_PANEL_VERDICT_SET verdictSet;
    LONG activeSet;
    ULONG stagingSet;
    ULONG index;
    NTSTATUS status;

    if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
        return STATUS_INVALID_DEVICE_STATE;
    }
    if (InterlockedCompareExchange(&g_KswordArkPanel.Ready, 0, 0) == 0) {
        return STATUS_DEVICE_NOT_READY;
    }
    status = KswordARKBugcheckPanelValidateVerdictPacket(
        Packet,
        PacketLength,
        &entries);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    status = KswordARKBugcheckBgpBeginResourceUpdate();
    if (!NT_SUCCESS(status)) {
        return status;
    }

    activeSet = InterlockedCompareExchange(
        &g_KswordArkPanel.ActiveVerdictSet,
        0,
        0);
    stagingSet = activeSet == 0 ? 1UL : 0UL;
    verdictSet = &g_KswordArkPanel.VerdictSets[stagingSet];
    KswordARKBugcheckPanelReleaseVerdictSet(verdictSet);
    status = STATUS_SUCCESS;
    for (index = 0;
         index < KSWORD_ARK_BUGCHECK_VERDICT_RESOURCE_COUNT &&
             NT_SUCCESS(status);
         ++index) {
        const KSWORD_ARK_BUGCHECK_VERDICT_RESOURCE_ENTRY* entry;
        ULONG variantIndex;

        entry = &entries[index];
        for (variantIndex = 0;
             variantIndex < KSWORD_ARK_PANEL_BPP_VARIANT_COUNT &&
                 NT_SUCCESS(status);
             ++variantIndex) {
            ULONG bitsPerPixel;

            bitsPerPixel = variantIndex == KSWORD_ARK_PANEL_BPP24_INDEX
                ? 24UL
                : 32UL;
            status = KswordARKBugcheckPanelPrepareVerdictItem(
                bitsPerPixel,
                entry,
                (const UCHAR*)Packet + entry->dataOffset,
                &verdictSet->Items[variantIndex]
                    [entry->language][entry->classification]);
        }
    }

    if (NT_SUCCESS(status)) {
        verdictSet->Complete = TRUE;
        KeMemoryBarrier();
        InterlockedExchange(
            &g_KswordArkPanel.ActiveVerdictSet,
            (LONG)stagingSet);
    } else {
        KswordARKBugcheckPanelReleaseVerdictSet(verdictSet);
    }
    KswordARKBugcheckBgpEndResourceUpdate();
    return status;
}

static NTSTATUS
KswordARKBugcheckPanelPrepareLogoRectangle(
    _In_ ULONG BitsPerPixel,
    _In_ ULONG Width,
    _In_ ULONG Height,
    _Out_ PVOID* Rectangle
    )
{
    UCHAR* bitmap;
    PUCHAR pixels;
    ULONG bitmapLength;
    ULONG bitmapStride;
    ULONG bytesPerPixel;
    ULONG64 bitmapCapacity64;
    ULONG bitmapCapacity;
    ULONG destinationY;
    NTSTATUS status;

    if (Rectangle == NULL ||
        Width == 0 ||
        Height == 0 ||
        (BitsPerPixel != 24UL && BitsPerPixel != 32UL)) {
        return STATUS_INVALID_PARAMETER;
    }
    *Rectangle = NULL;

    bytesPerPixel = BitsPerPixel / 8UL;
    bitmapCapacity64 =
        sizeof(KSWORD_ARK_PANEL_BITMAP_FILE_HEADER) +
        sizeof(KSWORD_ARK_PANEL_BITMAP_INFO_HEADER) +
        ((((ULONG64)Width *
           BitsPerPixel + 31ULL) / 32ULL) * 4ULL) *
            Height;
    if (bitmapCapacity64 > MAXULONG) {
        return STATUS_INTEGER_OVERFLOW;
    }

    bitmapCapacity = (ULONG)bitmapCapacity64;
    bitmap = (UCHAR*)KswordARKAllocateNonPagedPool(
        bitmapCapacity,
        KSWORD_ARK_PANEL_POOL_TAG);
    if (bitmap == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    pixels = NULL;
    status = KswordARKBugcheckPanelInitializeBitmap(
        bitmap,
        bitmapCapacity,
        Width,
        Height,
        BitsPerPixel,
        &bitmapLength,
        &bitmapStride,
        &pixels);
    if (NT_SUCCESS(status)) {
        for (destinationY = 0;
             destinationY < Height;
             ++destinationY) {
            ULONG destinationX;
            ULONG sourceY;
            PUCHAR destinationRow;
            const UCHAR* sourceRow;

            sourceY = (destinationY * DRIVERGUI_MAINLOGO_HEIGHT) / Height;
            destinationRow =
                pixels +
                ((SIZE_T)(Height - 1UL - destinationY) *
                 bitmapStride);
            sourceRow =
                g_DriverGuiMainLogoBgra +
                 ((SIZE_T)sourceY * DRIVERGUI_MAINLOGO_STRIDE);
            for (destinationX = 0;
                 destinationX < Width;
                 ++destinationX) {
                ULONG alpha;
                ULONG sourceBlue;
                ULONG sourceGreen;
                ULONG sourceRed;
                ULONG sourceX;
                PUCHAR destinationPixel;
                const UCHAR* sourcePixel;

                sourceX = (destinationX * DRIVERGUI_MAINLOGO_WIDTH) / Width;
                destinationPixel =
                    destinationRow + ((SIZE_T)destinationX * bytesPerPixel);
                sourcePixel = sourceRow + ((SIZE_T)sourceX * 4UL);
                sourceBlue = sourcePixel[0];
                sourceGreen = sourcePixel[1];
                sourceRed = sourcePixel[2];
                alpha = sourcePixel[3];

                // Keep the KSwordDEV artwork legible on the dark crash canvas.
                if (alpha != 0 && sourceRed < 72UL &&
                    sourceGreen < 72UL && sourceBlue < 72UL) {
                    sourceRed = KSWORD_ARK_BUGCHECK_LAYOUT_TEXT_RED;
                    sourceGreen = KSWORD_ARK_BUGCHECK_LAYOUT_TEXT_GREEN;
                    sourceBlue = KSWORD_ARK_BUGCHECK_LAYOUT_TEXT_BLUE;
                }
                destinationPixel[0] = (UCHAR)(
                    (sourceBlue * alpha +
                     KSWORD_ARK_BUGCHECK_LAYOUT_BACKGROUND_BLUE *
                         (255UL - alpha)) / 255UL);
                destinationPixel[1] = (UCHAR)(
                    (sourceGreen * alpha +
                     KSWORD_ARK_BUGCHECK_LAYOUT_BACKGROUND_GREEN *
                         (255UL - alpha)) / 255UL);
                destinationPixel[2] = (UCHAR)(
                    (sourceRed * alpha +
                     KSWORD_ARK_BUGCHECK_LAYOUT_BACKGROUND_RED *
                         (255UL - alpha)) / 255UL);
                if (bytesPerPixel == 4UL) {
                    destinationPixel[3] = 0xFFU;
                }
            }
        }

        status = KswordARKBugcheckBgpParseBitmap(
            bitmap,
            bitmapLength,
            Rectangle);
    }

    ExFreePoolWithTag(bitmap, KSWORD_ARK_PANEL_POOL_TAG);
    return status;
}

static NTSTATUS
KswordARKBugcheckPanelPrepareLogos(
    _In_ ULONG VariantIndex,
    _In_ ULONG BitsPerPixel
    )
{
    NTSTATUS status;

    if (VariantIndex >= KSWORD_ARK_PANEL_BPP_VARIANT_COUNT) {
        return STATUS_INVALID_PARAMETER;
    }

    status = KswordARKBugcheckPanelPrepareLogoRectangle(
        BitsPerPixel,
        KSWORD_ARK_BUGCHECK_LAYOUT_LOGO_WIDTH,
        KSWORD_ARK_BUGCHECK_LAYOUT_LOGO_HEIGHT,
        &g_KswordArkPanel.Variants[VariantIndex].LogoRectangle);
    if (!NT_SUCCESS(status)) {
        KswordARKBugcheckBgpDestroyRectangle(
            g_KswordArkPanel.Variants[VariantIndex].LogoRectangle);
        g_KswordArkPanel.Variants[VariantIndex].LogoRectangle = NULL;
    }
    return status;
}

static VOID
KswordARKBugcheckPanelWriteGlyphPixel(
    _Out_writes_bytes_(BytesPerPixel) PUCHAR Pixel,
    _In_ ULONG BytesPerPixel,
    _In_ ULONG ColorIndex,
    _In_ BOOLEAN Foreground
    )
{
    if (!Foreground) {
        // BGP's parsed 32-bit rectangles are rendered as opaque pixels.
        // Match every padded glyph cell to the dark crash canvas.
        Pixel[0] = KSWORD_ARK_BUGCHECK_LAYOUT_BACKGROUND_BLUE;
        Pixel[1] = KSWORD_ARK_BUGCHECK_LAYOUT_BACKGROUND_GREEN;
        Pixel[2] = KSWORD_ARK_BUGCHECK_LAYOUT_BACKGROUND_RED;
        if (BytesPerPixel == 4UL) {
            // BGP requires opaque pixels for reliable 32-bit glyph rendering.
            Pixel[3] = 0xFFU;
        }
        return;
    }

    if (ColorIndex == KswordArkBugcheckLayoutColorAccent) {
        Pixel[0] = KSWORD_ARK_BUGCHECK_LAYOUT_ACCENT_BLUE;
        Pixel[1] = KSWORD_ARK_BUGCHECK_LAYOUT_ACCENT_GREEN;
        Pixel[2] = KSWORD_ARK_BUGCHECK_LAYOUT_ACCENT_RED;
    } else if (ColorIndex == KswordArkBugcheckLayoutColorWarning) {
        Pixel[0] = KSWORD_ARK_BUGCHECK_LAYOUT_WARNING_BLUE;
        Pixel[1] = KSWORD_ARK_BUGCHECK_LAYOUT_WARNING_GREEN;
        Pixel[2] = KSWORD_ARK_BUGCHECK_LAYOUT_WARNING_RED;
    } else if (ColorIndex == KswordArkBugcheckLayoutColorMuted) {
        Pixel[0] = KSWORD_ARK_BUGCHECK_LAYOUT_MUTED_BLUE;
        Pixel[1] = KSWORD_ARK_BUGCHECK_LAYOUT_MUTED_GREEN;
        Pixel[2] = KSWORD_ARK_BUGCHECK_LAYOUT_MUTED_RED;
    } else {
        Pixel[0] = KSWORD_ARK_BUGCHECK_LAYOUT_TEXT_BLUE;
        Pixel[1] = KSWORD_ARK_BUGCHECK_LAYOUT_TEXT_GREEN;
        Pixel[2] = KSWORD_ARK_BUGCHECK_LAYOUT_TEXT_RED;
    }
    if (BytesPerPixel == 4UL) {
        Pixel[3] = 0xFFU;
    }
}

static NTSTATUS
KswordARKBugcheckPanelPrepareGlyph(
    _In_ ULONG VariantIndex,
    _In_ ULONG BitsPerPixel,
    _In_ ULONG ColorIndex,
    _In_ ULONG GlyphIndex
    )
{
    PUCHAR bitmap;
    PUCHAR pixels;
    ULONG bitmapLength;
    ULONG bitmapStride;
    ULONG bytesPerPixel;
    ULONG bitmapRowIndex;
    ULONG bitmapColumnIndex;
    ULONG rowIndex;
    PVOID* rectangle;
    NTSTATUS status;

    if (VariantIndex >= KSWORD_ARK_PANEL_BPP_VARIANT_COUNT ||
        (BitsPerPixel != 24UL && BitsPerPixel != 32UL)) {
        return STATUS_INVALID_PARAMETER;
    }

    bitmap = (PUCHAR)KswordARKAllocateNonPagedPool(
        1024UL,
        KSWORD_ARK_PANEL_POOL_TAG);
    if (bitmap == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    pixels = NULL;
    status = KswordARKBugcheckPanelInitializeBitmap(
        bitmap,
        1024UL,
        KSWORD_ARK_PANEL_GLYPH_BITMAP_WIDTH,
        KSWORD_ARK_PANEL_GLYPH_BITMAP_HEIGHT,
        BitsPerPixel,
        &bitmapLength,
        &bitmapStride,
        &pixels);
    if (!NT_SUCCESS(status)) {
        ExFreePoolWithTag(bitmap, KSWORD_ARK_PANEL_POOL_TAG);
        return status;
    }

    bytesPerPixel = BitsPerPixel / 8UL;
    // Paint the complete padded cell before overlaying foreground bits.
    for (bitmapRowIndex = 0;
         bitmapRowIndex < KSWORD_ARK_PANEL_GLYPH_BITMAP_HEIGHT;
         ++bitmapRowIndex) {
        PUCHAR destinationRow;

        destinationRow =
            pixels +
            ((SIZE_T)(KSWORD_ARK_PANEL_GLYPH_BITMAP_HEIGHT -
                      1UL - bitmapRowIndex) * bitmapStride);
        for (bitmapColumnIndex = 0;
             bitmapColumnIndex < KSWORD_ARK_PANEL_GLYPH_BITMAP_WIDTH;
             ++bitmapColumnIndex) {
            KswordARKBugcheckPanelWriteGlyphPixel(
                destinationRow +
                    ((SIZE_T)bitmapColumnIndex * bytesPerPixel),
                bytesPerPixel,
                ColorIndex,
                FALSE);
        }
    }
    for (rowIndex = 0;
         rowIndex < DRIVERGUI_FONT_HEIGHT;
         ++rowIndex) {
        ULONG columnIndex;
        UCHAR rowBits;
        PUCHAR destinationRow;

        rowBits = g_DriverGuiFont8x12[GlyphIndex][rowIndex];
        destinationRow =
            pixels +
            ((SIZE_T)(KSWORD_ARK_PANEL_GLYPH_BITMAP_HEIGHT -
                      1UL - KSWORD_ARK_PANEL_GLYPH_BORDER - rowIndex) *
             bitmapStride);
        for (columnIndex = 0;
             columnIndex < DRIVERGUI_FONT_WIDTH;
             ++columnIndex) {
            BOOLEAN foreground;

            foreground =
                (rowBits & (UCHAR)(1U << (7UL - columnIndex))) != 0;
            KswordARKBugcheckPanelWriteGlyphPixel(
                destinationRow +
                    ((SIZE_T)(KSWORD_ARK_PANEL_GLYPH_BORDER + columnIndex) *
                     bytesPerPixel),
                bytesPerPixel,
                ColorIndex,
                foreground);
        }
    }

    rectangle = &g_KswordArkPanel.Variants[VariantIndex]
        .GlyphRectangles[ColorIndex][GlyphIndex];
    status = KswordARKBugcheckBgpParseBitmap(
        bitmap,
        bitmapLength,
        rectangle);
    if (!NT_SUCCESS(status)) {
        ExFreePoolWithTag(bitmap, KSWORD_ARK_PANEL_POOL_TAG);
        return status;
    }

    g_KswordArkPanel.Variants[VariantIndex]
        .GlyphBitmaps[ColorIndex][GlyphIndex] = bitmap;
    return STATUS_SUCCESS;
}

static NTSTATUS
KswordARKBugcheckPanelPrepareGlyphs(
    _In_ ULONG VariantIndex,
    _In_ ULONG BitsPerPixel
    )
{
    ULONG colorIndex;

    for (colorIndex = 0;
         colorIndex < KSWORD_ARK_PANEL_COLOR_COUNT;
         ++colorIndex) {
        ULONG glyphIndex;

        for (glyphIndex = 0;
             glyphIndex < DRIVERGUI_FONT_COUNT;
             ++glyphIndex) {
            NTSTATUS status;

            status = KswordARKBugcheckPanelPrepareGlyph(
                VariantIndex,
                BitsPerPixel,
                colorIndex,
                glyphIndex);
            if (!NT_SUCCESS(status)) {
                return status;
            }
        }
    }

    return STATUS_SUCCESS;
}

static NTSTATUS
KswordARKBugcheckPanelPrepareSolidRectangle(
    _In_ ULONG BitsPerPixel,
    _In_ ULONG Width,
    _In_ ULONG Height,
    _Out_ PVOID* Rectangle,
    _Out_ PUCHAR* BackingBitmap
    )
{
    PUCHAR bitmap;
    PUCHAR pixels;
    ULONG64 bitmapCapacity64;
    ULONG bitmapCapacity;
    ULONG bitmapLength;
    ULONG bitmapStride;
    ULONG bytesPerPixel;
    ULONG x;
    ULONG y;
    NTSTATUS status;

    if (Rectangle == NULL || BackingBitmap == NULL ||
        Width == 0 || Height == 0 ||
        (BitsPerPixel != 24UL && BitsPerPixel != 32UL)) {
        return STATUS_INVALID_PARAMETER;
    }
    *Rectangle = NULL;
    *BackingBitmap = NULL;

    bitmapCapacity64 =
        sizeof(KSWORD_ARK_PANEL_BITMAP_FILE_HEADER) +
        sizeof(KSWORD_ARK_PANEL_BITMAP_INFO_HEADER) +
        ((((ULONG64)Width * BitsPerPixel + 31ULL) / 32ULL) *
         4ULL * Height);
    if (bitmapCapacity64 > MAXULONG) {
        return STATUS_INTEGER_OVERFLOW;
    }
    bitmapCapacity = (ULONG)bitmapCapacity64;
    bitmap = (PUCHAR)KswordARKAllocateNonPagedPool(
        bitmapCapacity,
        KSWORD_ARK_PANEL_POOL_TAG);
    if (bitmap == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    pixels = NULL;
    status = KswordARKBugcheckPanelInitializeBitmap(
        bitmap,
        bitmapCapacity,
        Width,
        Height,
        BitsPerPixel,
        &bitmapLength,
        &bitmapStride,
        &pixels);
    if (!NT_SUCCESS(status)) {
        ExFreePoolWithTag(bitmap, KSWORD_ARK_PANEL_POOL_TAG);
        return status;
    }

    bytesPerPixel = BitsPerPixel / 8UL;
    for (y = 0; y < Height; ++y) {
        PUCHAR row;

        row = pixels + ((SIZE_T)y * bitmapStride);
        for (x = 0; x < Width; ++x) {
            PUCHAR pixel;

            pixel = row + ((SIZE_T)x * bytesPerPixel);
            pixel[0] = KSWORD_ARK_BUGCHECK_LAYOUT_BORDER_BLUE;
            pixel[1] = KSWORD_ARK_BUGCHECK_LAYOUT_BORDER_GREEN;
            pixel[2] = KSWORD_ARK_BUGCHECK_LAYOUT_BORDER_RED;
            if (bytesPerPixel == 4UL) {
                pixel[3] = 0xFFU;
            }
        }
    }

    status = KswordARKBugcheckBgpParseBitmap(
        bitmap,
        bitmapLength,
        Rectangle);
    if (!NT_SUCCESS(status)) {
        ExFreePoolWithTag(bitmap, KSWORD_ARK_PANEL_POOL_TAG);
        return status;
    }

    // Retain the source because the private parser's ownership is undocumented.
    *BackingBitmap = bitmap;
    return STATUS_SUCCESS;
}

static NTSTATUS
KswordARKBugcheckPanelPrepareFrames(
    _In_ ULONG VariantIndex,
    _In_ ULONG BitsPerPixel
    )
{
    KSWORD_ARK_BUGCHECK_LAYOUT_FRAME frame;

    if (VariantIndex >= KSWORD_ARK_PANEL_BPP_VARIANT_COUNT) {
        return STATUS_INVALID_PARAMETER;
    }

    for (frame = KswordArkBugcheckLayoutFrameCompactColumn;
         frame < KswordArkBugcheckLayoutFrameCount;
         frame = (KSWORD_ARK_BUGCHECK_LAYOUT_FRAME)(frame + 1)) {
        ULONG width;
        ULONG height;
        NTSTATUS status;

        if (!KswordARKBugcheckLayoutGetFrameMetrics(
                frame,
                &width,
                &height)) {
            return STATUS_INVALID_PARAMETER;
        }

        status = KswordARKBugcheckPanelPrepareSolidRectangle(
            BitsPerPixel,
            width,
            1UL,
            &g_KswordArkPanel.Variants[VariantIndex]
                .FrameHorizontalRectangles[frame],
            &g_KswordArkPanel.Variants[VariantIndex]
                .FrameHorizontalBitmaps[frame]);
        if (NT_SUCCESS(status)) {
            status = KswordARKBugcheckPanelPrepareSolidRectangle(
                BitsPerPixel,
                1UL,
                height,
                &g_KswordArkPanel.Variants[VariantIndex]
                    .FrameVerticalRectangles[frame],
                &g_KswordArkPanel.Variants[VariantIndex]
                    .FrameVerticalBitmaps[frame]);
        }
        if (!NT_SUCCESS(status)) {
            return status;
        }
    }

    return STATUS_SUCCESS;
}

NTSTATUS
KswordARKBugcheckPanelInitialize(
    VOID
    )
{
    KSWORD_ARK_BGP_SCREEN_INFO screen;
    ULONG variantIndex;
    NTSTATUS status;

    if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
        return STATUS_INVALID_DEVICE_STATE;
    }

    RtlZeroMemory(&g_KswordArkPanel, sizeof(g_KswordArkPanel));
    InterlockedExchange(&g_KswordArkPanel.ActiveVerdictSet, -1);
    InterlockedExchange(
        &g_KswordArkPanel.PreferredLanguage,
        (LONG)KswordARKBugcheckPanelQueryPreferredLanguage());
    KswordARKBugcheckBgpRecordPreparation(
        KswordArkBgpPreparationValidatePanelScreen,
        STATUS_PENDING);
    status = KswordARKBugcheckBgpGetScreenInfo(&screen);
    if (!NT_SUCCESS(status)) {
        KswordARKBugcheckBgpRecordPreparation(
            KswordArkBgpPreparationValidatePanelScreen,
            status);
        KswordARKBugcheckBgpRejectPreparation(status);
        return status;
    }
    // Accept the fully hidden pre-ownership mode so both supported rectangle
    // variants can still be prepared at PASSIVE_LEVEL.
    if (screen.BitsPerPixel != KSWORD_ARK_BGP_UNOWNED_BPP &&
        (screen.Width < KSWORD_ARK_BUGCHECK_LAYOUT_REQUIRED_WIDTH ||
         screen.Height < KSWORD_ARK_BUGCHECK_LAYOUT_REQUIRED_HEIGHT ||
         (screen.BitsPerPixel != 24UL &&
          screen.BitsPerPixel != 32UL))) {
        KswordARKBugcheckBgpRecordPreparation(
            KswordArkBgpPreparationValidatePanelScreen,
            STATUS_NOT_SUPPORTED);
        KswordARKBugcheckBgpRejectPreparation(STATUS_NOT_SUPPORTED);
        return STATUS_NOT_SUPPORTED;
    }

    KswordARKBugcheckBgpRecordPreparation(
        KswordArkBgpPreparationValidatePanelScreen,
        STATUS_SUCCESS);
    status = STATUS_SUCCESS;
    for (variantIndex = 0;
         variantIndex < KSWORD_ARK_PANEL_BPP_VARIANT_COUNT &&
             NT_SUCCESS(status);
         ++variantIndex) {
        ULONG bitsPerPixel;

        bitsPerPixel = variantIndex == KSWORD_ARK_PANEL_BPP24_INDEX
            ? 24UL
            : 32UL;
        g_KswordArkPanel.Variants[variantIndex].BitsPerPixel = bitsPerPixel;
        KswordARKBugcheckBgpRecordPreparation(
            KswordArkBgpPreparationPrepareLogo,
            STATUS_PENDING);
        status = KswordARKBugcheckPanelPrepareLogos(
            variantIndex,
            bitsPerPixel);
        KswordARKBugcheckBgpRecordPreparation(
            KswordArkBgpPreparationPrepareLogo,
            status);
        if (NT_SUCCESS(status)) {
            KswordARKBugcheckBgpRecordPreparation(
                KswordArkBgpPreparationPrepareGlyphs,
                STATUS_PENDING);
            status = KswordARKBugcheckPanelPrepareGlyphs(
                variantIndex,
                bitsPerPixel);
            if (NT_SUCCESS(status)) {
                // Frames are parsed with glyph resources before the crash.
                status = KswordARKBugcheckPanelPrepareFrames(
                    variantIndex,
                    bitsPerPixel);
            }
            KswordARKBugcheckBgpRecordPreparation(
                KswordArkBgpPreparationPrepareGlyphs,
                status);
        }
    }
    if (NT_SUCCESS(status)) {
        KswordARKBugcheckBgpRecordPreparation(
            KswordArkBgpPreparationArm,
            STATUS_PENDING);
        status = KswordARKBugcheckBgpArm(
            KSWORD_ARK_BUGCHECK_LAYOUT_REQUIRED_WIDTH,
            KSWORD_ARK_BUGCHECK_LAYOUT_REQUIRED_HEIGHT);
        KswordARKBugcheckBgpRecordPreparation(
            KswordArkBgpPreparationArm,
            status);
    }
    if (!NT_SUCCESS(status)) {
        KswordARKBugcheckPanelShutdown();
        KswordARKBugcheckBgpRejectPreparation(status);
        return status;
    }

    InterlockedExchange(&g_KswordArkPanel.Ready, 1);
    KswordARKBugcheckBgpRecordPreparation(
        KswordArkBgpPreparationComplete,
        STATUS_SUCCESS);
    return STATUS_SUCCESS;
}

VOID
KswordARKBugcheckPanelShutdown(
    VOID
    )
{
    ULONG variantIndex;
    ULONG colorIndex;
    ULONG verdictSetIndex;

    InterlockedExchange(&g_KswordArkPanel.Ready, 0);
    InterlockedExchange(&g_KswordArkPanel.ActiveVariant, 0);
    InterlockedExchange(&g_KswordArkPanel.ActiveVerdictSet, -1);
    for (verdictSetIndex = 0;
         verdictSetIndex < KSWORD_ARK_PANEL_VERDICT_SET_COUNT;
         ++verdictSetIndex) {
        KswordARKBugcheckPanelReleaseVerdictSet(
            &g_KswordArkPanel.VerdictSets[verdictSetIndex]);
    }
    for (variantIndex = 0;
         variantIndex < KSWORD_ARK_PANEL_BPP_VARIANT_COUNT;
         ++variantIndex) {
        KswordARKBugcheckBgpDestroyRectangle(
            g_KswordArkPanel.Variants[variantIndex].LogoRectangle);
        g_KswordArkPanel.Variants[variantIndex].LogoRectangle = NULL;
        for (colorIndex = 0;
             colorIndex < KSWORD_ARK_PANEL_COLOR_COUNT;
             ++colorIndex) {
            ULONG glyphIndex;

            for (glyphIndex = 0;
                 glyphIndex < DRIVERGUI_FONT_COUNT;
                 ++glyphIndex) {
                KswordARKBugcheckBgpDestroyRectangle(
                    g_KswordArkPanel.Variants[variantIndex]
                        .GlyphRectangles[colorIndex][glyphIndex]);
                g_KswordArkPanel.Variants[variantIndex]
                    .GlyphRectangles[colorIndex][glyphIndex] = NULL;
                if (g_KswordArkPanel.Variants[variantIndex]
                        .GlyphBitmaps[colorIndex][glyphIndex] != NULL) {
                    ExFreePoolWithTag(
                        g_KswordArkPanel.Variants[variantIndex]
                            .GlyphBitmaps[colorIndex][glyphIndex],
                        KSWORD_ARK_PANEL_POOL_TAG);
                    g_KswordArkPanel.Variants[variantIndex]
                        .GlyphBitmaps[colorIndex][glyphIndex] = NULL;
                }
            }
        }
        {
            KSWORD_ARK_BUGCHECK_LAYOUT_FRAME frame;

            for (frame = KswordArkBugcheckLayoutFrameCompactColumn;
                 frame < KswordArkBugcheckLayoutFrameCount;
                 frame = (KSWORD_ARK_BUGCHECK_LAYOUT_FRAME)(frame + 1)) {
                KswordARKBugcheckBgpDestroyRectangle(
                    g_KswordArkPanel.Variants[variantIndex]
                        .FrameHorizontalRectangles[frame]);
                g_KswordArkPanel.Variants[variantIndex]
                    .FrameHorizontalRectangles[frame] = NULL;
                KswordARKBugcheckBgpDestroyRectangle(
                    g_KswordArkPanel.Variants[variantIndex]
                        .FrameVerticalRectangles[frame]);
                g_KswordArkPanel.Variants[variantIndex]
                    .FrameVerticalRectangles[frame] = NULL;
                if (g_KswordArkPanel.Variants[variantIndex]
                        .FrameHorizontalBitmaps[frame] != NULL) {
                    ExFreePoolWithTag(
                        g_KswordArkPanel.Variants[variantIndex]
                            .FrameHorizontalBitmaps[frame],
                        KSWORD_ARK_PANEL_POOL_TAG);
                    g_KswordArkPanel.Variants[variantIndex]
                        .FrameHorizontalBitmaps[frame] = NULL;
                }
                if (g_KswordArkPanel.Variants[variantIndex]
                        .FrameVerticalBitmaps[frame] != NULL) {
                    ExFreePoolWithTag(
                        g_KswordArkPanel.Variants[variantIndex]
                            .FrameVerticalBitmaps[frame],
                        KSWORD_ARK_PANEL_POOL_TAG);
                    g_KswordArkPanel.Variants[variantIndex]
                        .FrameVerticalBitmaps[frame] = NULL;
                }
            }
        }
    }
}

static NTSTATUS
KswordARKBugcheckPanelDrawText(
    _In_opt_ PVOID Context,
    _In_ LONG X,
    _In_ LONG Y,
    _In_z_ PCSTR Text,
    _In_ ULONG ColorIndex
    )
{
    LONG activeVariant;
    LONG cursorX;

    UNREFERENCED_PARAMETER(Context);
    if (Text == NULL || ColorIndex >= KSWORD_ARK_PANEL_COLOR_COUNT) {
        return STATUS_INVALID_PARAMETER;
    }

    activeVariant = InterlockedCompareExchange(
        &g_KswordArkPanel.ActiveVariant,
        0,
        0);
    if (activeVariant < 0 ||
        activeVariant >= (LONG)KSWORD_ARK_PANEL_BPP_VARIANT_COUNT) {
        return STATUS_DEVICE_NOT_READY;
    }

    cursorX = X;
    while (*Text != '\0') {
        UCHAR character;
        ULONG glyphIndex;
        NTSTATUS status;

        character = (UCHAR)*Text;
        if (character < DRIVERGUI_FONT_FIRST ||
            character > DRIVERGUI_FONT_LAST) {
            character = (UCHAR)'?';
        }
        glyphIndex = character - DRIVERGUI_FONT_FIRST;
        if (character != (UCHAR)' ') {
            status = KswordARKBugcheckBgpDrawRectangle(
                g_KswordArkPanel.Variants[activeVariant]
                    .GlyphRectangles[ColorIndex][glyphIndex],
                cursorX - (LONG)KSWORD_ARK_PANEL_GLYPH_BORDER,
                Y - (LONG)KSWORD_ARK_PANEL_GLYPH_BORDER);
            if (!NT_SUCCESS(status)) {
                return status;
            }
        }
        cursorX += KSWORD_ARK_PANEL_GLYPH_ADVANCE;
        ++Text;
    }

    return STATUS_SUCCESS;
}

static NTSTATUS
KswordARKBugcheckPanelDrawFrame(
    _In_opt_ PVOID Context,
    _In_ LONG X,
    _In_ LONG Y,
    _In_ KSWORD_ARK_BUGCHECK_LAYOUT_FRAME Frame
    )
{
    LONG activeVariant;
    ULONG width;
    ULONG height;
    NTSTATUS status;

    UNREFERENCED_PARAMETER(Context);
    if (!KswordARKBugcheckLayoutGetFrameMetrics(
            Frame,
            &width,
            &height)) {
        return STATUS_INVALID_PARAMETER;
    }

    activeVariant = InterlockedCompareExchange(
        &g_KswordArkPanel.ActiveVariant,
        0,
        0);
    if (activeVariant < 0 ||
        activeVariant >= (LONG)KSWORD_ARK_PANEL_BPP_VARIANT_COUNT) {
        return STATUS_DEVICE_NOT_READY;
    }

    // Each frame uses four rectangles parsed before the bugcheck occurs.
    status = KswordARKBugcheckBgpDrawRectangle(
        g_KswordArkPanel.Variants[activeVariant]
            .FrameHorizontalRectangles[Frame],
        X,
        Y);
    if (NT_SUCCESS(status)) {
        status = KswordARKBugcheckBgpDrawRectangle(
            g_KswordArkPanel.Variants[activeVariant]
                .FrameHorizontalRectangles[Frame],
            X,
            Y + (LONG)height - 1L);
    }
    if (NT_SUCCESS(status)) {
        status = KswordARKBugcheckBgpDrawRectangle(
            g_KswordArkPanel.Variants[activeVariant]
                .FrameVerticalRectangles[Frame],
            X,
            Y);
    }
    if (NT_SUCCESS(status)) {
        status = KswordARKBugcheckBgpDrawRectangle(
            g_KswordArkPanel.Variants[activeVariant]
                .FrameVerticalRectangles[Frame],
            X + (LONG)width - 1L,
            Y);
    }
    return status;
}

static NTSTATUS
KswordARKBugcheckPanelDrawVerdict(
    _In_opt_ PVOID Context,
    _In_ LONG X,
    _In_ LONG Y,
    _In_ ULONG Classification
    )
{
    LONG activeSet;
    LONG activeVariant;
    LONG preferredLanguage;
    PKSWORD_ARK_PANEL_VERDICT_SET verdictSet;
    PKSWORD_ARK_PANEL_VERDICT_ITEM item;

    UNREFERENCED_PARAMETER(Context);
    activeSet = InterlockedCompareExchange(
        &g_KswordArkPanel.ActiveVerdictSet,
        0,
        0);
    activeVariant = InterlockedCompareExchange(
        &g_KswordArkPanel.ActiveVariant,
        0,
        0);
    preferredLanguage = InterlockedCompareExchange(
        &g_KswordArkPanel.PreferredLanguage,
        0,
        0);
    if (activeSet < 0 ||
        activeSet >= (LONG)KSWORD_ARK_PANEL_VERDICT_SET_COUNT ||
        activeVariant < 0 ||
        activeVariant >= (LONG)KSWORD_ARK_PANEL_BPP_VARIANT_COUNT) {
        return STATUS_NOT_FOUND;
    }
    if (preferredLanguage < 0 ||
        preferredLanguage >=
            (LONG)KSWORD_ARK_BUGCHECK_VERDICT_LANGUAGE_COUNT) {
        preferredLanguage =
            KSWORD_ARK_BUGCHECK_VERDICT_LANGUAGE_ENGLISH;
    }
    if (Classification >= KSWORD_ARK_BUGCHECK_VERDICT_CLASS_COUNT) {
        Classification = KSWORD_ARK_BUGCHECK_VERDICT_CLASS_UNKNOWN;
    }

    verdictSet = &g_KswordArkPanel.VerdictSets[activeSet];
    if (!verdictSet->Complete) {
        return STATUS_NOT_FOUND;
    }
    item = &verdictSet->Items[activeVariant]
        [preferredLanguage][Classification];
    if (item->Rectangle == NULL) {
        return STATUS_NOT_FOUND;
    }
    return KswordARKBugcheckBgpDrawRectangle(item->Rectangle, X, Y);
}

NTSTATUS
KswordARKBugcheckPanelDraw(
    _In_ const KSWORD_ARK_BUGCHECK_DIAGNOSTICS* Diagnostics,
    _In_ ULONG CallbackMask,
    _In_ ULONG ModuleCount
    )
{
    KSWORD_ARK_BGP_DUMP_STATE bgpState;
    KSWORD_ARK_BUGCHECK_LAYOUT_CANVAS canvas;
    LONG activeVariant;
    LONG originX;
    NTSTATUS status;

    if (Diagnostics == NULL ||
        InterlockedCompareExchange(&g_KswordArkPanel.Ready, 0, 0) == 0) {
        return STATUS_DEVICE_NOT_READY;
    }

    status = KswordARKBugcheckBgpBeginDraw();
    if (!NT_SUCCESS(status)) {
        return status;
    }

    activeVariant = KswordARKBugcheckBgpGetCurrentBpp() == 24UL
        ? (LONG)KSWORD_ARK_PANEL_BPP24_INDEX
        : (LONG)KSWORD_ARK_PANEL_BPP32_INDEX;
    InterlockedExchange(&g_KswordArkPanel.ActiveVariant, activeVariant);
    KswordARKBugcheckBgpSnapshot(&bgpState);
    originX = KswordARKBugcheckLayoutOriginX(
        bgpState.ScreenWidth,
        bgpState.ScreenHeight);

    // Clear only after BeginDraw has acquired ownership and validated geometry.
    status = KswordARKBugcheckBgpClearScreen(
        KSWORD_ARK_PANEL_BACKGROUND_ARGB);
    if (NT_SUCCESS(status)) {
        status = KswordARKBugcheckBgpDrawRectangle(
            g_KswordArkPanel.Variants[activeVariant].LogoRectangle,
            originX + KSWORD_ARK_BUGCHECK_LAYOUT_LOGO_X,
            KSWORD_ARK_BUGCHECK_LAYOUT_LOGO_Y);
    }
    if (NT_SUCCESS(status)) {
        RtlZeroMemory(&canvas, sizeof(canvas));
        canvas.Width = bgpState.ScreenWidth;
        canvas.Height = bgpState.ScreenHeight;
        canvas.DrawText = KswordARKBugcheckPanelDrawText;
        canvas.DrawFrame = KswordARKBugcheckPanelDrawFrame;
        canvas.DrawVerdict = KswordARKBugcheckPanelDrawVerdict;
        status = KswordARKBugcheckLayoutDraw(
            &canvas,
            Diagnostics,
            CallbackMask,
            ModuleCount);
    }

    KswordARKBugcheckBgpFinishDraw(status);
    return status;
}
