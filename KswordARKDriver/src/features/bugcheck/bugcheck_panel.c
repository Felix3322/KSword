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
#define KSWORD_ARK_PANEL_REQUIRED_WIDTH 1024UL
#define KSWORD_ARK_PANEL_REQUIRED_HEIGHT 768UL
#define KSWORD_ARK_PANEL_WHITE_ARGB 0xFFFFFFFFUL
#define KSWORD_ARK_PANEL_GLYPH_ADVANCE 9L
#define KSWORD_ARK_PANEL_LINE_ADVANCE 16L
#define KSWORD_ARK_PANEL_LOGO_X 24L
#define KSWORD_ARK_PANEL_LOGO_Y 20L
#define KSWORD_ARK_PANEL_TITLE_X 653L
#define KSWORD_ARK_PANEL_TITLE_Y 40L
#define KSWORD_ARK_PANEL_VERDICT_Y 68L
#define KSWORD_ARK_PANEL_DIAGNOSTIC_X 28L
#define KSWORD_ARK_PANEL_DIAGNOSTIC_Y 260L
#define KSWORD_ARK_PANEL_WRAP_CHARACTERS 38UL
#define KSWORD_ARK_PANEL_COLOR_BLACK 0UL
#define KSWORD_ARK_PANEL_COLOR_BLUE 1UL
#define KSWORD_ARK_PANEL_COLOR_COUNT 2UL

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

typedef struct _KSWORD_ARK_PANEL_STATE
{
    volatile LONG Ready;
    ULONG BitsPerPixel;
    PVOID LogoRectangle;
    PVOID GlyphRectangles[KSWORD_ARK_PANEL_COLOR_COUNT][DRIVERGUI_FONT_COUNT];
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
KswordARKBugcheckPanelPrepareLogo(
    VOID
    )
{
    UCHAR* bitmap;
    PUCHAR pixels;
    ULONG bitmapLength;
    ULONG bitmapStride;
    ULONG bytesPerPixel;
    ULONG64 bitmapCapacity64;
    ULONG bitmapCapacity;
    ULONG sourceY;
    NTSTATUS status;

    bytesPerPixel = g_KswordArkPanel.BitsPerPixel / 8UL;
    bitmapCapacity64 =
        sizeof(KSWORD_ARK_PANEL_BITMAP_FILE_HEADER) +
        sizeof(KSWORD_ARK_PANEL_BITMAP_INFO_HEADER) +
        ((((ULONG64)DRIVERGUI_MAINLOGO_WIDTH *
           g_KswordArkPanel.BitsPerPixel + 31ULL) / 32ULL) * 4ULL) *
            DRIVERGUI_MAINLOGO_HEIGHT;
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
        DRIVERGUI_MAINLOGO_WIDTH,
        DRIVERGUI_MAINLOGO_HEIGHT,
        g_KswordArkPanel.BitsPerPixel,
        &bitmapLength,
        &bitmapStride,
        &pixels);
    if (NT_SUCCESS(status)) {
        for (sourceY = 0;
             sourceY < DRIVERGUI_MAINLOGO_HEIGHT;
             ++sourceY) {
            ULONG sourceX;
            PUCHAR destinationRow;
            const UCHAR* sourceRow;

            destinationRow =
                pixels +
                ((SIZE_T)(DRIVERGUI_MAINLOGO_HEIGHT - 1UL - sourceY) *
                 bitmapStride);
            sourceRow =
                g_DriverGuiMainLogoBgra +
                ((SIZE_T)sourceY * DRIVERGUI_MAINLOGO_STRIDE);
            for (sourceX = 0;
                 sourceX < DRIVERGUI_MAINLOGO_WIDTH;
                 ++sourceX) {
                PUCHAR destinationPixel;
                const UCHAR* sourcePixel;

                destinationPixel =
                    destinationRow + ((SIZE_T)sourceX * bytesPerPixel);
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
            &g_KswordArkPanel.LogoRectangle);
    }

    ExFreePoolWithTag(bitmap, KSWORD_ARK_PANEL_POOL_TAG);
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
        Pixel[0] = 0xFFU;
        Pixel[1] = 0xFFU;
        Pixel[2] = 0xFFU;
        if (BytesPerPixel == 4UL) {
            Pixel[3] = 0x00U;
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
    _In_ ULONG ColorIndex,
    _In_ ULONG GlyphIndex
    )
{
    UCHAR bitmap[512];
    PUCHAR pixels;
    ULONG bitmapLength;
    ULONG bitmapStride;
    ULONG bytesPerPixel;
    ULONG rowIndex;
    NTSTATUS status;

    pixels = NULL;
    status = KswordARKBugcheckPanelInitializeBitmap(
        bitmap,
        sizeof(bitmap),
        DRIVERGUI_FONT_WIDTH,
        DRIVERGUI_FONT_HEIGHT,
        g_KswordArkPanel.BitsPerPixel,
        &bitmapLength,
        &bitmapStride,
        &pixels);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    bytesPerPixel = g_KswordArkPanel.BitsPerPixel / 8UL;
    for (rowIndex = 0;
         rowIndex < DRIVERGUI_FONT_HEIGHT;
         ++rowIndex) {
        ULONG columnIndex;
        UCHAR rowBits;
        PUCHAR destinationRow;

        rowBits = g_DriverGuiFont8x12[GlyphIndex][rowIndex];
        destinationRow =
            pixels +
            ((SIZE_T)(DRIVERGUI_FONT_HEIGHT - 1UL - rowIndex) *
             bitmapStride);
        for (columnIndex = 0;
             columnIndex < DRIVERGUI_FONT_WIDTH;
             ++columnIndex) {
            BOOLEAN foreground;

            foreground =
                (rowBits & (UCHAR)(1U << (7UL - columnIndex))) != 0;
            KswordARKBugcheckPanelWriteGlyphPixel(
                destinationRow + ((SIZE_T)columnIndex * bytesPerPixel),
                bytesPerPixel,
                ColorIndex,
                foreground);
        }
    }

    return KswordARKBugcheckBgpParseBitmap(
        bitmap,
        bitmapLength,
        &g_KswordArkPanel.GlyphRectangles[ColorIndex][GlyphIndex]);
}

static NTSTATUS
KswordARKBugcheckPanelPrepareGlyphs(
    VOID
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
    NTSTATUS status;

    if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
        return STATUS_INVALID_DEVICE_STATE;
    }

    RtlZeroMemory(&g_KswordArkPanel, sizeof(g_KswordArkPanel));
    status = KswordARKBugcheckBgpGetScreenInfo(&screen);
    if (!NT_SUCCESS(status)) {
        KswordARKBugcheckBgpRejectPreparation(status);
        return status;
    }
    if (screen.Width < KSWORD_ARK_PANEL_REQUIRED_WIDTH ||
        screen.Height < KSWORD_ARK_PANEL_REQUIRED_HEIGHT ||
        (screen.BitsPerPixel != 24UL && screen.BitsPerPixel != 32UL)) {
        KswordARKBugcheckBgpRejectPreparation(STATUS_NOT_SUPPORTED);
        return STATUS_NOT_SUPPORTED;
    }

    g_KswordArkPanel.BitsPerPixel = screen.BitsPerPixel;
    status = KswordARKBugcheckPanelPrepareLogo();
    if (NT_SUCCESS(status)) {
        status = KswordARKBugcheckPanelPrepareGlyphs();
    }
    if (NT_SUCCESS(status)) {
        status = KswordARKBugcheckBgpArm(
            KSWORD_ARK_PANEL_REQUIRED_WIDTH,
            KSWORD_ARK_PANEL_REQUIRED_HEIGHT);
    }
    if (!NT_SUCCESS(status)) {
        KswordARKBugcheckPanelShutdown();
        KswordARKBugcheckBgpRejectPreparation(status);
        return status;
    }

    InterlockedExchange(&g_KswordArkPanel.Ready, 1);
    return STATUS_SUCCESS;
}

VOID
KswordARKBugcheckPanelShutdown(
    VOID
    )
{
    ULONG colorIndex;

    InterlockedExchange(&g_KswordArkPanel.Ready, 0);
    KswordARKBugcheckBgpDestroyRectangle(g_KswordArkPanel.LogoRectangle);
    g_KswordArkPanel.LogoRectangle = NULL;
    for (colorIndex = 0;
         colorIndex < KSWORD_ARK_PANEL_COLOR_COUNT;
         ++colorIndex) {
        ULONG glyphIndex;

        for (glyphIndex = 0;
             glyphIndex < DRIVERGUI_FONT_COUNT;
             ++glyphIndex) {
            KswordARKBugcheckBgpDestroyRectangle(
                g_KswordArkPanel.GlyphRectangles[colorIndex][glyphIndex]);
            g_KswordArkPanel.GlyphRectangles[colorIndex][glyphIndex] = NULL;
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
    LONG cursorX;

    if (Text == NULL || ColorIndex >= KSWORD_ARK_PANEL_COLOR_COUNT) {
        return STATUS_INVALID_PARAMETER;
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
                g_KswordArkPanel.GlyphRectangles[ColorIndex][glyphIndex],
                cursorX,
                Y);
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

NTSTATUS
KswordARKBugcheckPanelDraw(
    _In_ const KSWORD_ARK_BUGCHECK_DIAGNOSTICS* Diagnostics,
    _In_ ULONG CallbackMask,
    _In_ ULONG ModuleCount
    )
{
    KSWORD_ARK_BGP_DUMP_STATE bgpState;
    LONG verdictY;
    LONG diagnosticY;
    NTSTATUS status;

    if (Diagnostics == NULL ||
        InterlockedCompareExchange(&g_KswordArkPanel.Ready, 0, 0) == 0) {
        return STATUS_DEVICE_NOT_READY;
    }

    status = KswordARKBugcheckBgpBeginDraw();
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = KswordARKBugcheckBgpClearScreen(KSWORD_ARK_PANEL_WHITE_ARGB);
    if (NT_SUCCESS(status)) {
        status = KswordARKBugcheckBgpDrawRectangle(
            g_KswordArkPanel.LogoRectangle,
            KSWORD_ARK_PANEL_LOGO_X,
            KSWORD_ARK_PANEL_LOGO_Y);
    }
    if (NT_SUCCESS(status)) {
        status = KswordARKBugcheckPanelDrawText(
            KSWORD_ARK_PANEL_TITLE_X,
            KSWORD_ARK_PANEL_TITLE_Y,
            "KSWORD ARK PHYSICAL BUGCHECK DIAGNOSTICS",
            KSWORD_ARK_PANEL_COLOR_BLUE);
    }

    verdictY = KSWORD_ARK_PANEL_VERDICT_Y;
    if (NT_SUCCESS(status)) {
        status = KswordARKBugcheckPanelDrawWrappedText(
            KSWORD_ARK_PANEL_TITLE_X,
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
    if (NT_SUCCESS(status)) {
        status = KswordARKBugcheckPanelDrawFormattedLine(
            KSWORD_ARK_PANEL_DIAGNOSTIC_X,
            &diagnosticY,
            KSWORD_ARK_PANEL_COLOR_BLACK,
            "PERF CTR  : 0x%p",
            (PVOID)(ULONG_PTR)Diagnostics->PerfCounter.QuadPart);
    }
    if (NT_SUCCESS(status)) {
        status = KswordARKBugcheckPanelDrawFormattedLine(
            KSWORD_ARK_PANEL_DIAGNOSTIC_X,
            &diagnosticY,
            KSWORD_ARK_PANEL_COLOR_BLACK,
            "DUMP I/O  : offset=0x%p length=0x%lX",
            (PVOID)(ULONG_PTR)Diagnostics->DumpOffset,
            Diagnostics->DumpBufferLength);
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
    if (NT_SUCCESS(status)) {
        status = KswordARKBugcheckPanelDrawFormattedLine(
            KSWORD_ARK_PANEL_DIAGNOSTIC_X,
            &diagnosticY,
            KSWORD_ARK_PANEL_COLOR_BLACK,
            "CALLBACKS : BC=%lu TRIAGE=%lu DUMP=%lu SECONDARY=%lu",
            (CallbackMask & 0x1UL) != 0,
            (CallbackMask & 0x8UL) != 0,
            (CallbackMask & 0x4UL) != 0,
            (CallbackMask & 0x2UL) != 0);
    }
    if (NT_SUCCESS(status)) {
        status = KswordARKBugcheckPanelDrawFormattedLine(
            KSWORD_ARK_PANEL_DIAGNOSTIC_X,
            &diagnosticY,
            KSWORD_ARK_PANEL_COLOR_BLACK,
            "MODULES   : cached=%lu",
            ModuleCount);
    }

    KswordARKBugcheckBgpSnapshot(&bgpState);
    diagnosticY += 6L;
    if (NT_SUCCESS(status)) {
        status = KswordARKBugcheckPanelDrawFormattedLine(
            KSWORD_ARK_PANEL_DIAGNOSTIC_X,
            &diagnosticY,
            KSWORD_ARK_PANEL_COLOR_BLUE,
            "BGP STATE : state=%lu stage=0x%08lX features=0x%08lX",
            bgpState.State,
            bgpState.Stage,
            bgpState.FeatureMask);
    }
    if (NT_SUCCESS(status)) {
        status = KswordARKBugcheckPanelDrawFormattedLine(
            KSWORD_ARK_PANEL_DIAGNOSTIC_X,
            &diagnosticY,
            KSWORD_ARK_PANEL_COLOR_BLACK,
            "BGP STATUS: last=0x%08lX clear=0x%08lX draw=0x%08lX",
            bgpState.LastStatus,
            bgpState.ClearStatus,
            bgpState.DrawStatus);
    }
    if (NT_SUCCESS(status)) {
        status = KswordARKBugcheckPanelDrawFormattedLine(
            KSWORD_ARK_PANEL_DIAGNOSTIC_X,
            &diagnosticY,
            KSWORD_ARK_PANEL_COLOR_BLACK,
            "BGP SCREEN: %lux%lux%lu required=%lux%lu",
            bgpState.ScreenWidth,
            bgpState.ScreenHeight,
            bgpState.ScreenBpp,
            bgpState.RequiredWidth,
            bgpState.RequiredHeight);
    }

    KswordARKBugcheckBgpFinishDraw(status);
    return status;
}
