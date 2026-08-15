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
#include "bugcheck_panel.h"
#include "../../platform/pool_compat.h"

#include <ntstrsafe.h>
#include <stdarg.h>

#include "Generated/AsciiFont8x12.h"
#include "Generated/MainLogoBitmap.h"

#define KSWORD_ARK_PANEL_POOL_TAG 'lPgK'
#define KSWORD_ARK_PANEL_REQUIRED_WIDTH 640UL
#define KSWORD_ARK_PANEL_REQUIRED_HEIGHT 480UL
#define KSWORD_ARK_PANEL_FULL_WIDTH 1024UL
#define KSWORD_ARK_PANEL_FULL_HEIGHT 768UL
#define KSWORD_ARK_PANEL_WHITE_ARGB 0xFFFFFFFFUL
#define KSWORD_ARK_PANEL_GLYPH_ADVANCE 9L
#define KSWORD_ARK_PANEL_LINE_ADVANCE 16L
#define KSWORD_ARK_PANEL_GLYPH_BORDER 1UL
#define KSWORD_ARK_PANEL_GLYPH_BITMAP_WIDTH \
    (DRIVERGUI_FONT_WIDTH + (KSWORD_ARK_PANEL_GLYPH_BORDER * 2UL))
#define KSWORD_ARK_PANEL_GLYPH_BITMAP_HEIGHT \
    (DRIVERGUI_FONT_HEIGHT + (KSWORD_ARK_PANEL_GLYPH_BORDER * 2UL))
#define KSWORD_ARK_PANEL_LOGO_X 24L
#define KSWORD_ARK_PANEL_LOGO_Y 20L
#define KSWORD_ARK_PANEL_TITLE_X 653L
#define KSWORD_ARK_PANEL_TITLE_Y 40L
#define KSWORD_ARK_PANEL_VERDICT_Y 68L
#define KSWORD_ARK_PANEL_DIAGNOSTIC_X 28L
#define KSWORD_ARK_PANEL_DIAGNOSTIC_Y 260L
#define KSWORD_ARK_PANEL_WRAP_CHARACTERS 38UL
#define KSWORD_ARK_PANEL_COMPACT_LINE_ADVANCE 14L
#define KSWORD_ARK_PANEL_COMPACT_LOGO_WIDTH 240UL
#define KSWORD_ARK_PANEL_COMPACT_LOGO_HEIGHT 84UL
#define KSWORD_ARK_PANEL_COMPACT_LOGO_X 16L
#define KSWORD_ARK_PANEL_COMPACT_LOGO_Y 12L
#define KSWORD_ARK_PANEL_COMPACT_TITLE_X 280L
#define KSWORD_ARK_PANEL_COMPACT_TITLE_Y 18L
#define KSWORD_ARK_PANEL_COMPACT_SUMMARY_Y 42L
#define KSWORD_ARK_PANEL_COMPACT_LEFT_X 16L
#define KSWORD_ARK_PANEL_COMPACT_RIGHT_X 330L
#define KSWORD_ARK_PANEL_COMPACT_DIAGNOSTIC_Y 126L
#define KSWORD_ARK_PANEL_COMPACT_PROGRESS_GAP 56L
#define KSWORD_ARK_PANEL_COLOR_BLACK 0UL
#define KSWORD_ARK_PANEL_COLOR_BLUE 1UL
#define KSWORD_ARK_PANEL_COLOR_COUNT 2UL
#define KSWORD_ARK_PANEL_BPP24_INDEX 0UL
#define KSWORD_ARK_PANEL_BPP32_INDEX 1UL
#define KSWORD_ARK_PANEL_BPP_VARIANT_COUNT 2UL

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
    PVOID CompactLogoRectangle;
    PVOID GlyphRectangles[KSWORD_ARK_PANEL_COLOR_COUNT][DRIVERGUI_FONT_COUNT];
    // Keep the source BMPs resident for the lifetime of the parsed glyphs.
    // BgpGxParseBitmap is private and its ownership contract is not documented.
    // A persistent nonpaged backing buffer prevents a small-rectangle parser
    // from retaining a reused preparation stack buffer.
    PUCHAR GlyphBitmaps[KSWORD_ARK_PANEL_COLOR_COUNT][DRIVERGUI_FONT_COUNT];
} KSWORD_ARK_PANEL_VARIANT, *PKSWORD_ARK_PANEL_VARIANT;

typedef struct _KSWORD_ARK_PANEL_STATE
{
    volatile LONG Ready;
    volatile LONG ActiveVariant;
    KSWORD_ARK_PANEL_VARIANT Variants[KSWORD_ARK_PANEL_BPP_VARIANT_COUNT];
    CHAR LineBuffer[KSWORD_ARK_BUGCHECK_PANEL_LINE_CHARS];
} KSWORD_ARK_PANEL_STATE, *PKSWORD_ARK_PANEL_STATE;

static KSWORD_ARK_PANEL_STATE g_KswordArkPanel;

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
                ULONG sourceX;
                PUCHAR destinationPixel;
                const UCHAR* sourcePixel;

                sourceX = (destinationX * DRIVERGUI_MAINLOGO_WIDTH) / Width;
                destinationPixel =
                    destinationRow + ((SIZE_T)destinationX * bytesPerPixel);
                sourcePixel = sourceRow + ((SIZE_T)sourceX * 4UL);
                destinationPixel[0] = sourcePixel[0];
                destinationPixel[1] = sourcePixel[1];
                destinationPixel[2] = sourcePixel[2];
                if (bytesPerPixel == 4UL) {
                    destinationPixel[3] = sourcePixel[3];
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
        DRIVERGUI_MAINLOGO_WIDTH,
        DRIVERGUI_MAINLOGO_HEIGHT,
        &g_KswordArkPanel.Variants[VariantIndex].LogoRectangle);
    if (NT_SUCCESS(status)) {
        status = KswordARKBugcheckPanelPrepareLogoRectangle(
            BitsPerPixel,
            KSWORD_ARK_PANEL_COMPACT_LOGO_WIDTH,
            KSWORD_ARK_PANEL_COMPACT_LOGO_HEIGHT,
            &g_KswordArkPanel.Variants[VariantIndex]
                .CompactLogoRectangle);
    }
    if (!NT_SUCCESS(status)) {
        KswordARKBugcheckBgpDestroyRectangle(
            g_KswordArkPanel.Variants[VariantIndex].LogoRectangle);
        g_KswordArkPanel.Variants[VariantIndex].LogoRectangle = NULL;
        KswordARKBugcheckBgpDestroyRectangle(
            g_KswordArkPanel.Variants[VariantIndex].CompactLogoRectangle);
        g_KswordArkPanel.Variants[VariantIndex].CompactLogoRectangle = NULL;
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
        // Use an opaque white background so every glyph cell remains white.
        Pixel[0] = 0xFFU;
        Pixel[1] = 0xFFU;
        Pixel[2] = 0xFFU;
        if (BytesPerPixel == 4UL) {
            // Match the opaque ARGB colors used by the original BGP renderer.
            Pixel[3] = 0xFFU;
        }
        return;
    }

    if (ColorIndex == KSWORD_ARK_PANEL_COLOR_BLUE) {
        Pixel[0] = 0xD4U;
        Pixel[1] = 0x78U;
        Pixel[2] = 0x00U;
    } else {
        Pixel[0] = 0x00U;
        Pixel[1] = 0x00U;
        Pixel[2] = 0x00U;
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
    // Paint the complete padded cell white before overlaying foreground bits.
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
        (screen.Width < KSWORD_ARK_PANEL_REQUIRED_WIDTH ||
         screen.Height < KSWORD_ARK_PANEL_REQUIRED_HEIGHT ||
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
            KSWORD_ARK_PANEL_REQUIRED_WIDTH,
            KSWORD_ARK_PANEL_REQUIRED_HEIGHT);
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

    InterlockedExchange(&g_KswordArkPanel.Ready, 0);
    InterlockedExchange(&g_KswordArkPanel.ActiveVariant, 0);
    for (variantIndex = 0;
         variantIndex < KSWORD_ARK_PANEL_BPP_VARIANT_COUNT;
         ++variantIndex) {
        KswordARKBugcheckBgpDestroyRectangle(
            g_KswordArkPanel.Variants[variantIndex].LogoRectangle);
        g_KswordArkPanel.Variants[variantIndex].LogoRectangle = NULL;
        KswordARKBugcheckBgpDestroyRectangle(
            g_KswordArkPanel.Variants[variantIndex].CompactLogoRectangle);
        g_KswordArkPanel.Variants[variantIndex].CompactLogoRectangle = NULL;
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
    }
}

static NTSTATUS
KswordARKBugcheckPanelDrawText(
    _In_ LONG X,
    _In_ LONG Y,
    _In_z_ PCSTR Text,
    _In_ ULONG ColorIndex
    )
{
    LONG activeVariant;
    LONG cursorX;

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
KswordARKBugcheckPanelDrawWrappedText(
    _In_ LONG X,
    _Inout_ PLONG Y,
    _In_z_ PCSTR Text,
    _In_ ULONG ColorIndex,
    _In_ ULONG MaximumCharacters
    )
{
    PCSTR cursor;

    if (Y == NULL || Text == NULL || MaximumCharacters == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    cursor = Text;
    while (*cursor != '\0') {
        ULONG lineLength;
        ULONG copyLength;
        NTSTATUS status;

        lineLength = 0;
        while (cursor[lineLength] != '\0' &&
               lineLength < MaximumCharacters) {
            ++lineLength;
        }
        copyLength = lineLength;
        if (cursor[lineLength] != '\0') {
            while (copyLength > 0 && cursor[copyLength] != ' ') {
                --copyLength;
            }
            if (copyLength == 0) {
                copyLength = lineLength;
            }
        }

        copyLength = min(
            copyLength,
            (ULONG)sizeof(g_KswordArkPanel.LineBuffer) - 1UL);
        RtlCopyMemory(g_KswordArkPanel.LineBuffer, cursor, copyLength);
        g_KswordArkPanel.LineBuffer[copyLength] = '\0';
        status = KswordARKBugcheckPanelDrawText(
            X,
            *Y,
            g_KswordArkPanel.LineBuffer,
            ColorIndex);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        *Y += KSWORD_ARK_PANEL_LINE_ADVANCE;
        cursor += copyLength;
        while (*cursor == ' ') {
            ++cursor;
        }
    }

    return STATUS_SUCCESS;
}

static NTSTATUS
KswordARKBugcheckPanelDrawFormattedLine(
    _In_ LONG X,
    _Inout_ PLONG Y,
    _In_ ULONG ColorIndex,
    _In_z_ _Printf_format_string_ PCSTR Format,
    ...
    )
{
    va_list arguments;
    NTSTATUS status;

    if (Y == NULL || Format == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    va_start(arguments, Format);
    status = RtlStringCbVPrintfA(
        g_KswordArkPanel.LineBuffer,
        sizeof(g_KswordArkPanel.LineBuffer),
        Format,
        arguments);
    va_end(arguments);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = KswordARKBugcheckPanelDrawText(
        X,
        *Y,
        g_KswordArkPanel.LineBuffer,
        ColorIndex);
    if (NT_SUCCESS(status)) {
        *Y += KSWORD_ARK_PANEL_LINE_ADVANCE;
    }
    return status;
}

static NTSTATUS
KswordARKBugcheckPanelDrawCompactLine(
    _In_ LONG X,
    _Inout_ PLONG Y,
    _In_ ULONG ColorIndex,
    _In_z_ _Printf_format_string_ PCSTR Format,
    ...
    )
{
    va_list arguments;
    NTSTATUS status;

    if (Y == NULL || Format == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    va_start(arguments, Format);
    status = RtlStringCbVPrintfA(
        g_KswordArkPanel.LineBuffer,
        sizeof(g_KswordArkPanel.LineBuffer),
        Format,
        arguments);
    va_end(arguments);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = KswordARKBugcheckPanelDrawText(
        X,
        *Y,
        g_KswordArkPanel.LineBuffer,
        ColorIndex);
    if (NT_SUCCESS(status)) {
        *Y += KSWORD_ARK_PANEL_COMPACT_LINE_ADVANCE;
    }
    return status;
}

static PCSTR
KswordARKBugcheckPanelCompactSummaryLine1(
    _In_ ULONG BugCheckCode
    )
{
    switch (BugCheckCode) {
    case 0x000000EF: return "CRITICAL PROCESS";
    case 0x0000007E: return "SYSTEM THREAD EXCEPTION";
    case 0x000000D1: return "DRIVER IRQL FAILURE";
    case 0x00000133: return "DPC WATCHDOG FAILURE";
    default: return "WINDOWS STOPPED SAFELY";
    }
}

static PCSTR
KswordARKBugcheckPanelCompactSummaryLine2(
    _In_ ULONG BugCheckCode
    )
{
    switch (BugCheckCode) {
    case 0x000000EF: return "TERMINATED UNEXPECTEDLY";
    case 0x0000007E: return "WAS NOT HANDLED";
    case 0x000000D1: return "AT ELEVATED IRQL";
    case 0x00000133: return "RESPONDED TOO SLOWLY";
    default: return "TO PROTECT SYSTEM DATA";
    }
}

static PCSTR
KswordARKBugcheckPanelCompactObjectType(
    _In_ const KSWORD_ARK_BUGCHECK_DIAGNOSTICS* Diagnostics
    )
{
    if (Diagnostics != NULL && Diagnostics->BugCheckCode == 0x000000EF) {
        if (Diagnostics->Parameter2 == 0) {
            return "PROCESS";
        }
        if (Diagnostics->Parameter2 == 1) {
            return "THREAD";
        }
    }
    return "OBJECT";
}

static PCSTR
KswordARKBugcheckPanelCompactModuleText(
    _In_ const KSWORD_ARK_BUGCHECK_DIAGNOSTICS* Diagnostics
    )
{
    if (Diagnostics == NULL ||
        Diagnostics->CandidateModule[0] == '\0' ||
        Diagnostics->CandidateModule[0] == '(') {
        return "NOT IDENTIFIED";
    }
    return Diagnostics->CandidateModule;
}

static NTSTATUS
KswordARKBugcheckPanelDrawCompactBody(
    _In_ const KSWORD_ARK_BUGCHECK_DIAGNOSTICS* Diagnostics,
    _In_ ULONG CallbackMask,
    _In_ ULONG ModuleCount,
    _Inout_ PLONG Y
    )
{
    LONG leftY;
    LONG rightY;
    NTSTATUS status;

    if (Diagnostics == NULL || Y == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    UNREFERENCED_PARAMETER(CallbackMask);
    UNREFERENCED_PARAMETER(ModuleCount);

    leftY = *Y;
    rightY = *Y;
    status = KswordARKBugcheckPanelDrawCompactLine(
        KSWORD_ARK_PANEL_COMPACT_LEFT_X,
        &leftY,
        KSWORD_ARK_PANEL_COLOR_BLUE,
        "STOP CODE: 0x%08lX",
        Diagnostics->BugCheckCode);
    if (NT_SUCCESS(status)) {
        status = KswordARKBugcheckPanelDrawCompactLine(
            KSWORD_ARK_PANEL_COMPACT_RIGHT_X,
            &rightY,
            KSWORD_ARK_PANEL_COLOR_BLUE,
            "SUMMARY:");
    }
    if (NT_SUCCESS(status)) {
        status = KswordARKBugcheckPanelDrawCompactLine(
            KSWORD_ARK_PANEL_COMPACT_LEFT_X,
            &leftY,
            KSWORD_ARK_PANEL_COLOR_BLUE,
            "NAME: %s",
            KswordARKBugcheckName(Diagnostics->BugCheckCode));
    }
    if (NT_SUCCESS(status)) {
        status = KswordARKBugcheckPanelDrawCompactLine(
            KSWORD_ARK_PANEL_COMPACT_RIGHT_X,
            &rightY,
            KSWORD_ARK_PANEL_COLOR_BLUE,
            "%s",
            KswordARKBugcheckPanelCompactSummaryLine1(
                Diagnostics->BugCheckCode));
    }
    if (NT_SUCCESS(status)) {
        status = KswordARKBugcheckPanelDrawCompactLine(
            KSWORD_ARK_PANEL_COMPACT_LEFT_X,
            &leftY,
            KSWORD_ARK_PANEL_COLOR_BLACK,
            "OBJECT: %s",
            KswordARKBugcheckPanelCompactObjectType(Diagnostics));
    }
    if (NT_SUCCESS(status)) {
        status = KswordARKBugcheckPanelDrawCompactLine(
            KSWORD_ARK_PANEL_COMPACT_RIGHT_X,
            &rightY,
            KSWORD_ARK_PANEL_COLOR_BLACK,
            "%s",
            KswordARKBugcheckPanelCompactSummaryLine2(
                Diagnostics->BugCheckCode));
    }
    if (NT_SUCCESS(status)) {
        status = KswordARKBugcheckPanelDrawCompactLine(
            KSWORD_ARK_PANEL_COMPACT_LEFT_X,
            &leftY,
            KSWORD_ARK_PANEL_COLOR_BLACK,
            "OBJECT PTR: 0x%p",
            (PVOID)Diagnostics->Parameter1);
    }
    if (NT_SUCCESS(status)) {
        status = KswordARKBugcheckPanelDrawCompactLine(
            KSWORD_ARK_PANEL_COMPACT_RIGHT_X,
            &rightY,
            KSWORD_ARK_PANEL_COLOR_BLACK,
            "DUMP: %s",
            KswordARKBugcheckDumpTypeText(Diagnostics->LastDumpType));
    }
    if (NT_SUCCESS(status)) {
        if (Diagnostics->BugCheckCode == 0x000000EF) {
            status = KswordARKBugcheckPanelDrawCompactLine(
                KSWORD_ARK_PANEL_COMPACT_LEFT_X,
                &leftY,
                KSWORD_ARK_PANEL_COLOR_BLACK,
                "FAULT IP: NOT PROVIDED");
        } else {
            status = KswordARKBugcheckPanelDrawCompactLine(
                KSWORD_ARK_PANEL_COMPACT_LEFT_X,
                &leftY,
                KSWORD_ARK_PANEL_COLOR_BLACK,
                "FAULT IP: 0x%p",
                (PVOID)Diagnostics->FaultAddress);
        }
    }
    if (NT_SUCCESS(status)) {
        status = KswordARKBugcheckPanelDrawCompactLine(
            KSWORD_ARK_PANEL_COMPACT_RIGHT_X,
            &rightY,
            KSWORD_ARK_PANEL_COLOR_BLACK,
            "ACTION: PRESERVE DUMP");
    }
    if (NT_SUCCESS(status)) {
        status = KswordARKBugcheckPanelDrawCompactLine(
            KSWORD_ARK_PANEL_COMPACT_LEFT_X,
            &leftY,
            KSWORD_ARK_PANEL_COLOR_BLUE,
            "MODULE: %s",
            KswordARKBugcheckPanelCompactModuleText(Diagnostics));
    }
    if (NT_SUCCESS(status)) {
        status = KswordARKBugcheckPanelDrawCompactLine(
            KSWORD_ARK_PANEL_COMPACT_RIGHT_X,
            &rightY,
            KSWORD_ARK_PANEL_COLOR_BLACK,
            "CHECK: RECENT DRIVERS");
    }
    if (NT_SUCCESS(status)) {
        status = KswordARKBugcheckPanelDrawCompactLine(
            KSWORD_ARK_PANEL_COMPACT_LEFT_X,
            &leftY,
            KSWORD_ARK_PANEL_COLOR_BLACK,
            "CLASS: %s",
            KswordARKBugcheckModuleClassText(Diagnostics->CandidateClass));
    }
    if (NT_SUCCESS(status)) {
        status = KswordARKBugcheckPanelDrawCompactLine(
            KSWORD_ARK_PANEL_COMPACT_RIGHT_X,
            &rightY,
            KSWORD_ARK_PANEL_COLOR_BLACK,
            "CHECK: EVENT VIEWER");
    }

    // Leave the central progress-text band clear because Windows paints dump
    // progress there after the callback returns.
    leftY += KSWORD_ARK_PANEL_COMPACT_PROGRESS_GAP;
    rightY += KSWORD_ARK_PANEL_COMPACT_PROGRESS_GAP;
    if (NT_SUCCESS(status)) {
        status = KswordARKBugcheckPanelDrawCompactLine(
            KSWORD_ARK_PANEL_COMPACT_LEFT_X,
            &leftY,
            KSWORD_ARK_PANEL_COLOR_BLACK,
            "CONFIDENCE: %s",
            KswordARKBugcheckConfidenceText(Diagnostics->CandidateConfidence));
    }
    if (NT_SUCCESS(status)) {
        status = KswordARKBugcheckPanelDrawCompactLine(
            KSWORD_ARK_PANEL_COMPACT_RIGHT_X,
            &rightY,
            KSWORD_ARK_PANEL_COLOR_BLACK,
            "CHECK: SYSTEM INTEGRITY");
    }
    if (NT_SUCCESS(status)) {
        status = KswordARKBugcheckPanelDrawCompactLine(
            KSWORD_ARK_PANEL_COMPACT_LEFT_X,
            &leftY,
            KSWORD_ARK_PANEL_COLOR_BLACK,
            "PARAM2: 0x%p",
            (PVOID)Diagnostics->Parameter2);
    }
    if (NT_SUCCESS(status)) {
        status = KswordARKBugcheckPanelDrawCompactLine(
            KSWORD_ARK_PANEL_COMPACT_LEFT_X,
            &leftY,
            KSWORD_ARK_PANEL_COLOR_BLACK,
            "PARAM3: 0x%p",
            (PVOID)Diagnostics->Parameter3);
    }
    if (NT_SUCCESS(status)) {
        status = KswordARKBugcheckPanelDrawCompactLine(
            KSWORD_ARK_PANEL_COMPACT_RIGHT_X,
            &rightY,
            KSWORD_ARK_PANEL_COLOR_BLACK,
            "CAPTURE: COMPLETE");
    }
    if (NT_SUCCESS(status)) {
        status = KswordARKBugcheckPanelDrawCompactLine(
            KSWORD_ARK_PANEL_COMPACT_LEFT_X,
            &leftY,
            KSWORD_ARK_PANEL_COLOR_BLACK,
            "PARAM4: 0x%p",
            (PVOID)Diagnostics->Parameter4);
    }
    if (NT_SUCCESS(status)) {
        status = KswordARKBugcheckPanelDrawCompactLine(
            KSWORD_ARK_PANEL_COMPACT_RIGHT_X,
            &rightY,
            KSWORD_ARK_PANEL_COLOR_BLACK,
            "NEXT: REVIEW DUMP");
    }
    if (NT_SUCCESS(status)) {
        status = KswordARKBugcheckPanelDrawCompactLine(
            KSWORD_ARK_PANEL_COMPACT_RIGHT_X,
            &rightY,
            KSWORD_ARK_PANEL_COLOR_BLACK,
            "KSWORD ARK: CAPTURED");
    }
    *Y = leftY > rightY ? leftY : rightY;
    return status;
}

NTSTATUS
KswordARKBugcheckPanelDraw(
    _In_ const KSWORD_ARK_BUGCHECK_DIAGNOSTICS* Diagnostics,
    _In_ ULONG CallbackMask,
    _In_ ULONG ModuleCount
    )
{
    KSWORD_ARK_BGP_DUMP_STATE bgpState;
    LONG activeVariant;
    LONG verdictY;
    LONG diagnosticY;
    LONG logoX;
    LONG logoY;
    LONG titleX;
    LONG titleY;
    LONG summaryY;
    PVOID logoRectangle;
    BOOLEAN compactLayout;
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
    compactLayout = bgpState.ScreenWidth < KSWORD_ARK_PANEL_FULL_WIDTH ||
        bgpState.ScreenHeight < KSWORD_ARK_PANEL_FULL_HEIGHT;
    logoX = compactLayout
        ? KSWORD_ARK_PANEL_COMPACT_LOGO_X
        : KSWORD_ARK_PANEL_LOGO_X;
    logoY = compactLayout
        ? KSWORD_ARK_PANEL_COMPACT_LOGO_Y
        : KSWORD_ARK_PANEL_LOGO_Y;
    titleX = compactLayout
        ? KSWORD_ARK_PANEL_COMPACT_TITLE_X
        : KSWORD_ARK_PANEL_TITLE_X;
    titleY = compactLayout
        ? KSWORD_ARK_PANEL_COMPACT_TITLE_Y
        : KSWORD_ARK_PANEL_TITLE_Y;
    verdictY = KSWORD_ARK_PANEL_VERDICT_Y;
    logoRectangle = compactLayout
        ? g_KswordArkPanel.Variants[activeVariant].CompactLogoRectangle
        : g_KswordArkPanel.Variants[activeVariant].LogoRectangle;

    status = KswordARKBugcheckBgpClearScreen(KSWORD_ARK_PANEL_WHITE_ARGB);
    if (NT_SUCCESS(status)) {
        status = KswordARKBugcheckBgpDrawRectangle(
            logoRectangle,
            logoX,
            logoY);
    }
    if (NT_SUCCESS(status)) {
        status = KswordARKBugcheckPanelDrawText(
            titleX,
            titleY,
            "KSWORD ARK CRASH DIAGNOSTICS",
            KSWORD_ARK_PANEL_COLOR_BLUE);
    }

    if (compactLayout) {
        summaryY = KSWORD_ARK_PANEL_COMPACT_SUMMARY_Y;
        if (NT_SUCCESS(status)) {
            status = KswordARKBugcheckPanelDrawCompactLine(
                titleX,
                &summaryY,
                KSWORD_ARK_PANEL_COLOR_BLACK,
                "CRASH DATA CAPTURED");
        }
        if (NT_SUCCESS(status)) {
            status = KswordARKBugcheckPanelDrawCompactLine(
                titleX,
                &summaryY,
                KSWORD_ARK_PANEL_COLOR_BLACK,
                "PRESERVE THE NEWEST DUMP");
        }
        diagnosticY = KSWORD_ARK_PANEL_COMPACT_DIAGNOSTIC_Y;
        if (NT_SUCCESS(status)) {
            status = KswordARKBugcheckPanelDrawCompactBody(
                Diagnostics,
                CallbackMask,
                ModuleCount,
                &diagnosticY);
        }
        KswordARKBugcheckBgpFinishDraw(status);
        return status;
    }

    if (NT_SUCCESS(status)) {
        status = KswordARKBugcheckPanelDrawWrappedText(
            titleX,
            &verdictY,
            KswordARKBugcheckVerdictText(Diagnostics->CandidateClass),
            KSWORD_ARK_PANEL_COLOR_BLUE,
            KSWORD_ARK_PANEL_WRAP_CHARACTERS);
    }

    diagnosticY = KSWORD_ARK_PANEL_DIAGNOSTIC_Y;
    if (NT_SUCCESS(status)) {
        status = KswordARKBugcheckPanelDrawFormattedLine(
            KSWORD_ARK_PANEL_DIAGNOSTIC_X,
            &diagnosticY,
            KSWORD_ARK_PANEL_COLOR_BLUE,
            "STOP CODE : 0x%08lX",
            Diagnostics->BugCheckCode);
    }
    if (NT_SUCCESS(status)) {
        status = KswordARKBugcheckPanelDrawFormattedLine(
            KSWORD_ARK_PANEL_DIAGNOSTIC_X,
            &diagnosticY,
            KSWORD_ARK_PANEL_COLOR_BLUE,
            "STOP NAME : %s",
            KswordARKBugcheckName(Diagnostics->BugCheckCode));
    }
    if (NT_SUCCESS(status)) {
        status = KswordARKBugcheckPanelDrawFormattedLine(
            KSWORD_ARK_PANEL_DIAGNOSTIC_X,
            &diagnosticY,
            KSWORD_ARK_PANEL_COLOR_BLACK,
            "PARAM1    : 0x%p",
            (PVOID)Diagnostics->Parameter1);
    }
    if (NT_SUCCESS(status)) {
        status = KswordARKBugcheckPanelDrawFormattedLine(
            KSWORD_ARK_PANEL_DIAGNOSTIC_X,
            &diagnosticY,
            KSWORD_ARK_PANEL_COLOR_BLACK,
            "PARAM2    : 0x%p",
            (PVOID)Diagnostics->Parameter2);
    }
    if (NT_SUCCESS(status)) {
        status = KswordARKBugcheckPanelDrawFormattedLine(
            KSWORD_ARK_PANEL_DIAGNOSTIC_X,
            &diagnosticY,
            KSWORD_ARK_PANEL_COLOR_BLACK,
            "PARAM3    : 0x%p",
            (PVOID)Diagnostics->Parameter3);
    }
    if (NT_SUCCESS(status)) {
        status = KswordARKBugcheckPanelDrawFormattedLine(
            KSWORD_ARK_PANEL_DIAGNOSTIC_X,
            &diagnosticY,
            KSWORD_ARK_PANEL_COLOR_BLACK,
            "PARAM4    : 0x%p",
            (PVOID)Diagnostics->Parameter4);
    }
    if (NT_SUCCESS(status)) {
        status = KswordARKBugcheckPanelDrawFormattedLine(
            KSWORD_ARK_PANEL_DIAGNOSTIC_X,
            &diagnosticY,
            KSWORD_ARK_PANEL_COLOR_BLACK,
            "FAULT IP  : param%lu 0x%p (%s)",
            Diagnostics->FaultParameter,
            (PVOID)Diagnostics->FaultAddress,
            Diagnostics->FaultMeaning);
    }

    diagnosticY += 6L;
    if (NT_SUCCESS(status)) {
        status = KswordARKBugcheckPanelDrawFormattedLine(
            KSWORD_ARK_PANEL_DIAGNOSTIC_X,
            &diagnosticY,
            KSWORD_ARK_PANEL_COLOR_BLACK,
            "REASON    : %s (%lu)",
            KswordARKBugcheckReasonText(Diagnostics->LastReason),
            Diagnostics->LastReason);
    }
    if (NT_SUCCESS(status)) {
        status = KswordARKBugcheckPanelDrawFormattedLine(
            KSWORD_ARK_PANEL_DIAGNOSTIC_X,
            &diagnosticY,
            KSWORD_ARK_PANEL_COLOR_BLACK,
            "DUMP TYPE : %s (%lu)",
            KswordARKBugcheckDumpTypeText(Diagnostics->LastDumpType),
            Diagnostics->LastDumpType);
    }
    if (NT_SUCCESS(status)) {
        status = KswordARKBugcheckPanelDrawFormattedLine(
            KSWORD_ARK_PANEL_DIAGNOSTIC_X,
            &diagnosticY,
            KSWORD_ARK_PANEL_COLOR_BLACK,
            "IRQL/CPU  : %lu / %lu",
            Diagnostics->Irql,
            Diagnostics->Cpu);
    }
    diagnosticY += 6L;
    if (NT_SUCCESS(status)) {
        status = KswordARKBugcheckPanelDrawFormattedLine(
            KSWORD_ARK_PANEL_DIAGNOSTIC_X,
            &diagnosticY,
            KSWORD_ARK_PANEL_COLOR_BLUE,
            "MODULE    : %s",
            Diagnostics->CandidateModule);
    }
    if (NT_SUCCESS(status)) {
        status = KswordARKBugcheckPanelDrawFormattedLine(
            KSWORD_ARK_PANEL_DIAGNOSTIC_X,
            &diagnosticY,
            KSWORD_ARK_PANEL_COLOR_BLACK,
            "ADDRESS   : 0x%p",
            (PVOID)Diagnostics->CandidateAddress);
    }
    if (NT_SUCCESS(status)) {
        status = KswordARKBugcheckPanelDrawFormattedLine(
            KSWORD_ARK_PANEL_DIAGNOSTIC_X,
            &diagnosticY,
            KSWORD_ARK_PANEL_COLOR_BLACK,
            "MOD RANGE : base=0x%p size=0x%lX off=0x%p",
            (PVOID)Diagnostics->CandidateModuleBase,
            Diagnostics->CandidateModuleSize,
            (PVOID)Diagnostics->CandidateModuleOffset);
    }
    if (NT_SUCCESS(status)) {
        status = KswordARKBugcheckPanelDrawFormattedLine(
            KSWORD_ARK_PANEL_DIAGNOSTIC_X,
            &diagnosticY,
            KSWORD_ARK_PANEL_COLOR_BLACK,
            "CAND SRC  : param%lu / %s",
            Diagnostics->CandidateParameter,
            Diagnostics->CandidateSource);
    }
    if (NT_SUCCESS(status)) {
        status = KswordARKBugcheckPanelDrawFormattedLine(
            KSWORD_ARK_PANEL_DIAGNOSTIC_X,
            &diagnosticY,
            KSWORD_ARK_PANEL_COLOR_BLACK,
            "CLASS     : %s",
            KswordARKBugcheckModuleClassText(Diagnostics->CandidateClass));
    }
    if (NT_SUCCESS(status)) {
        status = KswordARKBugcheckPanelDrawFormattedLine(
            KSWORD_ARK_PANEL_DIAGNOSTIC_X,
            &diagnosticY,
            KSWORD_ARK_PANEL_COLOR_BLACK,
            "CONFIDENCE: %s",
            KswordARKBugcheckConfidenceText(Diagnostics->CandidateConfidence));
    }

    diagnosticY += 6L;
    if (NT_SUCCESS(status)) {
        status = KswordARKBugcheckPanelDrawFormattedLine(
            KSWORD_ARK_PANEL_DIAGNOSTIC_X,
            &diagnosticY,
            KSWORD_ARK_PANEL_COLOR_BLACK,
            "DRIVER    : DriverObject=0x%p DeviceObject=0x%p",
            g_KswordArkBugcheckState.DriverObject,
            g_KswordArkBugcheckState.DeviceObject);
    }
    KswordARKBugcheckBgpFinishDraw(status);
    return status;
}
