/*++

Module Name:

    bugcheck_layout.c

Abstract:

    Shared crash-safe information layout for the BGP and VMware framebuffer
    bugcheck renderers. The implementation formats only captured data and uses
    caller-supplied drawing callbacks without allocation or pageable services.

--*/

#include "bugcheck_layout.h"
#include "bugcheck_layout_detailed.h"

#include <ntstrsafe.h>
#include <stdarg.h>

typedef struct _KSWORD_ARK_BUGCHECK_LAYOUT_FRAME_METRICS
{
    ULONG Width;
    ULONG Height;
} KSWORD_ARK_BUGCHECK_LAYOUT_FRAME_METRICS;

typedef struct _KSWORD_ARK_BUGCHECK_LAYOUT_WRITER
{
    const KSWORD_ARK_BUGCHECK_LAYOUT_CANVAS* Canvas;
    LONG OriginX;
    NTSTATUS Status;
    CHAR Line[KSWORD_ARK_BUGCHECK_PANEL_LINE_CHARS];
} KSWORD_ARK_BUGCHECK_LAYOUT_WRITER;

static const KSWORD_ARK_BUGCHECK_LAYOUT_FRAME_METRICS
    g_KswordArkBugcheckLayoutFrames[KswordArkBugcheckLayoutFrameCount] = {
        { 296UL, 112UL },
        { 608UL, 126UL },
        { 344UL, 184UL },
        { 312UL, 184UL },
        { 328UL, 184UL },
        { 344UL, 174UL },
        { 312UL, 174UL },
        { 328UL, 174UL },
        { 484UL, 176UL },
        { 500UL, 176UL },
        { 470UL, 207UL },
        { 350UL, 207UL },
        { 416UL, 207UL },
        { 314UL, 162UL },
        { 328UL, 162UL },
        { 278UL, 162UL },
        { 316UL, 162UL },
        { 480UL, 205UL },
        { 348UL, 205UL },
        { 412UL, 98UL },
        { 412UL, 103UL }
    };

C_ASSERT(
    RTL_NUMBER_OF(g_KswordArkBugcheckLayoutFrames) ==
    KswordArkBugcheckLayoutFrameCount);

BOOLEAN
KswordARKBugcheckLayoutIsDetailed(
    _In_ ULONG Width,
    _In_ ULONG Height
    )
{
    // The wide 720-line mode matches the information-dense design safely.
    return Width >= KSWORD_ARK_BUGCHECK_LAYOUT_DETAILED_WIDTH &&
        Height >= KSWORD_ARK_BUGCHECK_LAYOUT_DETAILED_HEIGHT;
}

BOOLEAN
KswordARKBugcheckLayoutIsCompact(
    _In_ ULONG Width,
    _In_ ULONG Height
    )
{
    // The 640x480 crash fallback needs its dedicated two-column layout.
    return !KswordARKBugcheckLayoutIsDetailed(Width, Height) &&
        (Width < KSWORD_ARK_BUGCHECK_LAYOUT_FULL_WIDTH ||
         Height < KSWORD_ARK_BUGCHECK_LAYOUT_FULL_HEIGHT);
}

LONG
KswordARKBugcheckLayoutOriginX(
    _In_ ULONG Width,
    _In_ ULONG Height
    )
{
    ULONG canvasWidth;

    // Center whichever fixed canvas the current crash mode can safely fit.
    if (KswordARKBugcheckLayoutIsDetailed(Width, Height)) {
        canvasWidth = KSWORD_ARK_BUGCHECK_LAYOUT_DETAILED_WIDTH;
    } else if (KswordARKBugcheckLayoutIsCompact(Width, Height)) {
        canvasWidth = KSWORD_ARK_BUGCHECK_LAYOUT_REQUIRED_WIDTH;
    } else {
        canvasWidth = KSWORD_ARK_BUGCHECK_LAYOUT_FULL_WIDTH;
    }
    if (Width > canvasWidth) {
        return (LONG)((Width - canvasWidth) / 2UL);
    }
    return 0L;
}

BOOLEAN
KswordARKBugcheckLayoutGetFrameMetrics(
    _In_ KSWORD_ARK_BUGCHECK_LAYOUT_FRAME Frame,
    _Out_ PULONG Width,
    _Out_ PULONG Height
    )
{
    if (Width == NULL || Height == NULL ||
        Frame < KswordArkBugcheckLayoutFrameCompactColumn ||
        Frame >= KswordArkBugcheckLayoutFrameCount) {
        return FALSE;
    }

    *Width = g_KswordArkBugcheckLayoutFrames[Frame].Width;
    *Height = g_KswordArkBugcheckLayoutFrames[Frame].Height;
    return TRUE;
}

static VOID
KswordARKBugcheckLayoutClipLine(
    _Inout_updates_z_(Capacity) PCHAR Text,
    _In_ ULONG Capacity,
    _In_ ULONG MaximumCharacters
    )
{
    SIZE_T length;

    if (Text == NULL || Capacity == 0 || MaximumCharacters == 0) {
        return;
    }
    if (MaximumCharacters >= Capacity) {
        MaximumCharacters = Capacity - 1UL;
    }

    length = 0;
    while (length + 1UL < Capacity && Text[length] != '\0') {
        ++length;
    }
    if (length <= MaximumCharacters) {
        return;
    }

    if (MaximumCharacters > 3UL) {
        Text[MaximumCharacters - 3UL] = '.';
        Text[MaximumCharacters - 2UL] = '.';
        Text[MaximumCharacters - 1UL] = '.';
    }
    Text[MaximumCharacters] = '\0';
}

static VOID
KswordARKBugcheckLayoutWriteFormatted(
    _Inout_ KSWORD_ARK_BUGCHECK_LAYOUT_WRITER* Writer,
    _In_ LONG X,
    _In_ LONG Y,
    _In_ ULONG ColorIndex,
    _In_ ULONG MaximumCharacters,
    _In_z_ _Printf_format_string_ PCSTR Format,
    ...
    )
{
    va_list arguments;

    if (Writer == NULL || !NT_SUCCESS(Writer->Status)) {
        return;
    }

    va_start(arguments, Format);
    Writer->Status = RtlStringCbVPrintfA(
        Writer->Line,
        sizeof(Writer->Line),
        Format,
        arguments);
    va_end(arguments);
    if (!NT_SUCCESS(Writer->Status)) {
        return;
    }

    KswordARKBugcheckLayoutClipLine(
        Writer->Line,
        (ULONG)RTL_NUMBER_OF(Writer->Line),
        MaximumCharacters);
    Writer->Status = Writer->Canvas->DrawText(
        Writer->Canvas->Context,
        Writer->OriginX + X,
        Y,
        Writer->Line,
        ColorIndex);
}

static VOID
KswordARKBugcheckLayoutWriteFrame(
    _Inout_ KSWORD_ARK_BUGCHECK_LAYOUT_WRITER* Writer,
    _In_ LONG X,
    _In_ LONG Y,
    _In_ KSWORD_ARK_BUGCHECK_LAYOUT_FRAME Frame
    )
{
    if (Writer == NULL || !NT_SUCCESS(Writer->Status)) {
        return;
    }

    Writer->Status = Writer->Canvas->DrawFrame(
        Writer->Canvas->Context,
        Writer->OriginX + X,
        Y,
        Frame);
}

static PCSTR
KswordARKBugcheckLayoutModuleText(
    _In_ const KSWORD_ARK_BUGCHECK_DIAGNOSTICS* Diagnostics
    )
{
    // Parenthesized resolver notes are not module names and add visual noise.
    if (Diagnostics->CandidateModule[0] == '\0' ||
        Diagnostics->CandidateModule[0] == '(') {
        return "NOT IDENTIFIED";
    }
    return Diagnostics->CandidateModule;
}

static PCSTR
KswordARKBugcheckLayoutSummaryText(
    _In_ ULONG Classification
    )
{
    switch (Classification) {
    case KSWORD_ARK_BUGCHECK_MODULE_OURS:
        return "KSWORDARK MAY BE INVOLVED.";
    case KSWORD_ARK_BUGCHECK_MODULE_MICROSOFT:
        return "PARAMETERS POINT TO MICROSOFT CODE.";
    case KSWORD_ARK_BUGCHECK_MODULE_THIRD_PARTY:
        return "PARAMETERS POINT TO THIRD-PARTY CODE.";
    default:
        return "THE FAULTING COMPONENT IS UNKNOWN.";
    }
}

static VOID
KswordARKBugcheckLayoutWriteHeader(
    _Inout_ KSWORD_ARK_BUGCHECK_LAYOUT_WRITER* Writer,
    _In_ const KSWORD_ARK_BUGCHECK_DIAGNOSTICS* Diagnostics,
    _In_ BOOLEAN Compact
    )
{
    if (Compact) {
        KswordARKBugcheckLayoutWriteFormatted(
            Writer, 280L, 18L, KswordArkBugcheckLayoutColorAccent, 37UL,
            "KSWORD ARK CRASH DIAGNOSTICS");
        KswordARKBugcheckLayoutWriteFormatted(
            Writer, 280L, 40L, KswordArkBugcheckLayoutColorText, 37UL,
            "A FATAL KERNEL ERROR OCCURRED.");
        KswordARKBugcheckLayoutWriteFormatted(
            Writer, 280L, 56L, KswordArkBugcheckLayoutColorMuted, 37UL,
            "CRASH CONTEXT CAPTURED.");
        KswordARKBugcheckLayoutWriteFormatted(
            Writer, 280L, 72L, KswordArkBugcheckLayoutColorMuted, 37UL,
            "PRESERVE THE NEWEST DUMP.");
        return;
    }

    KswordARKBugcheckLayoutWriteFormatted(
        Writer, 280L, 18L, KswordArkBugcheckLayoutColorAccent, 50UL,
        "KSWORD ARK CRASH DIAGNOSTICS");
    KswordARKBugcheckLayoutWriteFormatted(
        Writer, 280L, 40L, KswordArkBugcheckLayoutColorText, 58UL,
        "A FATAL KERNEL ERROR HAS OCCURRED.");
    KswordARKBugcheckLayoutWriteFormatted(
        Writer, 280L, 56L, KswordArkBugcheckLayoutColorMuted, 58UL,
        "THE SYSTEM HAS STOPPED TO PROTECT DATA.");
    KswordARKBugcheckLayoutWriteFormatted(
        Writer, 280L, 72L, KswordArkBugcheckLayoutColorMuted, 58UL,
        "THIS SCREEN PRESERVES THE CRASH CONTEXT.");
    KswordARKBugcheckLayoutWriteFormatted(
        Writer, 880L, 20L, KswordArkBugcheckLayoutColorText, 14UL,
        "CRASH CPU %02lu", Diagnostics->Cpu);
    KswordARKBugcheckLayoutWriteFormatted(
        Writer, 880L, 42L, KswordArkBugcheckLayoutColorMuted, 14UL,
        "IRQL %lu", Diagnostics->Irql);
}

static VOID
KswordARKBugcheckLayoutDrawCompact(
    _Inout_ KSWORD_ARK_BUGCHECK_LAYOUT_WRITER* Writer,
    _In_ const KSWORD_ARK_BUGCHECK_DIAGNOSTICS* Diagnostics,
    _In_ ULONG CallbackMask,
    _In_ ULONG ModuleCount
    )
{
    PCSTR moduleText;

    moduleText = KswordARKBugcheckLayoutModuleText(Diagnostics);
    KswordARKBugcheckLayoutWriteFrame(
        Writer, 16L, 110L, KswordArkBugcheckLayoutFrameCompactColumn);
    KswordARKBugcheckLayoutWriteFrame(
        Writer, 328L, 110L, KswordArkBugcheckLayoutFrameCompactColumn);
    KswordARKBugcheckLayoutWriteFrame(
        Writer, 16L, 292L, KswordArkBugcheckLayoutFrameCompactWide);

    KswordARKBugcheckLayoutWriteFormatted(
        Writer, 28L, 120L, KswordArkBugcheckLayoutColorMuted, 29UL,
        "BUGCHECK");
    KswordARKBugcheckLayoutWriteFormatted(
        Writer, 28L, 138L, KswordArkBugcheckLayoutColorAccent, 29UL,
        "%s", KswordARKBugcheckName(Diagnostics->BugCheckCode));
    KswordARKBugcheckLayoutWriteFormatted(
        Writer, 28L, 152L, KswordArkBugcheckLayoutColorText, 29UL,
        "CODE  0x%08lX", Diagnostics->BugCheckCode);
    KswordARKBugcheckLayoutWriteFormatted(
        Writer, 28L, 166L, KswordArkBugcheckLayoutColorText, 29UL,
        "ARG1  0x%p", (PVOID)Diagnostics->Parameter1);
    KswordARKBugcheckLayoutWriteFormatted(
        Writer, 28L, 180L, KswordArkBugcheckLayoutColorText, 29UL,
        "ARG2  0x%p", (PVOID)Diagnostics->Parameter2);
    KswordARKBugcheckLayoutWriteFormatted(
        Writer, 28L, 194L, KswordArkBugcheckLayoutColorText, 29UL,
        "ARG3  0x%p", (PVOID)Diagnostics->Parameter3);
    KswordARKBugcheckLayoutWriteFormatted(
        Writer, 28L, 208L, KswordArkBugcheckLayoutColorText, 29UL,
        "ARG4  0x%p", (PVOID)Diagnostics->Parameter4);

    KswordARKBugcheckLayoutWriteFormatted(
        Writer, 340L, 120L, KswordArkBugcheckLayoutColorMuted, 29UL,
        "FAULT CONTEXT");
    KswordARKBugcheckLayoutWriteFormatted(
        Writer, 340L, 138L, KswordArkBugcheckLayoutColorAccent, 29UL,
        "IP    0x%p", (PVOID)Diagnostics->FaultAddress);
    KswordARKBugcheckLayoutWriteFormatted(
        Writer, 340L, 152L, KswordArkBugcheckLayoutColorText, 29UL,
        "PARAM %lu  %s",
        Diagnostics->FaultParameter,
        Diagnostics->FaultMeaning);
    KswordARKBugcheckLayoutWriteFormatted(
        Writer, 340L, 166L, KswordArkBugcheckLayoutColorText, 29UL,
        "CPU %lu   IRQL %lu", Diagnostics->Cpu, Diagnostics->Irql);
    KswordARKBugcheckLayoutWriteFormatted(
        Writer, 340L, 180L, KswordArkBugcheckLayoutColorText, 29UL,
        "MODULE  %s", moduleText);
    KswordARKBugcheckLayoutWriteFormatted(
        Writer, 340L, 194L, KswordArkBugcheckLayoutColorText, 29UL,
        "CLASS   %s",
        KswordARKBugcheckModuleClassText(Diagnostics->CandidateClass));
    KswordARKBugcheckLayoutWriteFormatted(
        Writer, 340L, 208L, KswordArkBugcheckLayoutColorText, 29UL,
        "CONF    %s",
        KswordARKBugcheckConfidenceText(Diagnostics->CandidateConfidence));

    // The 228..284 band remains empty for Windows dump progress text.
    KswordARKBugcheckLayoutWriteFormatted(
        Writer, 28L, 302L, KswordArkBugcheckLayoutColorMuted, 32UL,
        "FAULTING MODULE");
    KswordARKBugcheckLayoutWriteFormatted(
        Writer, 28L, 320L, KswordArkBugcheckLayoutColorAccent, 32UL,
        "%s", moduleText);
    KswordARKBugcheckLayoutWriteFormatted(
        Writer, 28L, 336L, KswordArkBugcheckLayoutColorText, 32UL,
        "BASE  0x%p", (PVOID)Diagnostics->CandidateModuleBase);
    KswordARKBugcheckLayoutWriteFormatted(
        Writer, 28L, 352L, KswordArkBugcheckLayoutColorText, 32UL,
        "SIZE  0x%08lX", Diagnostics->CandidateModuleSize);
    KswordARKBugcheckLayoutWriteFormatted(
        Writer, 28L, 368L, KswordArkBugcheckLayoutColorText, 32UL,
        "OFF   0x%p", (PVOID)Diagnostics->CandidateModuleOffset);
    KswordARKBugcheckLayoutWriteFormatted(
        Writer, 28L, 384L, KswordArkBugcheckLayoutColorText, 32UL,
        "ADDR  0x%p", (PVOID)Diagnostics->CandidateAddress);

    KswordARKBugcheckLayoutWriteFormatted(
        Writer, 340L, 302L, KswordArkBugcheckLayoutColorMuted, 30UL,
        "DUMP STATUS");
    KswordARKBugcheckLayoutWriteFormatted(
        Writer, 340L, 320L, KswordArkBugcheckLayoutColorAccent, 30UL,
        "STAGE  %s", KswordARKBugcheckDumpTypeText(Diagnostics->LastDumpType));
    KswordARKBugcheckLayoutWriteFormatted(
        Writer, 340L, 336L, KswordArkBugcheckLayoutColorText, 30UL,
        "REASON %s", KswordARKBugcheckReasonText(Diagnostics->LastReason));
    KswordARKBugcheckLayoutWriteFormatted(
        Writer, 340L, 352L, KswordArkBugcheckLayoutColorText, 30UL,
        "CALLBACKS 0x%02lX", CallbackMask & 0x0FUL);
    KswordARKBugcheckLayoutWriteFormatted(
        Writer, 340L, 368L, KswordArkBugcheckLayoutColorText, 30UL,
        "MODULES   %lu", ModuleCount);
    KswordARKBugcheckLayoutWriteFormatted(
        Writer, 340L, 384L, KswordArkBugcheckLayoutColorText, 30UL,
        "ACTION  PRESERVE NEWEST DUMP");

    KswordARKBugcheckLayoutWriteFormatted(
        Writer, 16L, 442L, KswordArkBugcheckLayoutColorMuted, 68UL,
        "WINDOWS IS WRITING THE CRASH DUMP. DO NOT POWER OFF.");
}

static VOID
KswordARKBugcheckLayoutDrawFull(
    _Inout_ KSWORD_ARK_BUGCHECK_LAYOUT_WRITER* Writer,
    _In_ const KSWORD_ARK_BUGCHECK_DIAGNOSTICS* Diagnostics,
    _In_ ULONG CallbackMask,
    _In_ ULONG ModuleCount
    )
{
    PCSTR moduleText;

    moduleText = KswordARKBugcheckLayoutModuleText(Diagnostics);
    KswordARKBugcheckLayoutWriteFrame(
        Writer, 16L, 110L, KswordArkBugcheckLayoutFrameFullTopLeft);
    KswordARKBugcheckLayoutWriteFrame(
        Writer, 364L, 110L, KswordArkBugcheckLayoutFrameFullTopMiddle);
    KswordARKBugcheckLayoutWriteFrame(
        Writer, 680L, 110L, KswordArkBugcheckLayoutFrameFullTopRight);
    KswordARKBugcheckLayoutWriteFrame(
        Writer, 16L, 298L, KswordArkBugcheckLayoutFrameFullMiddleLeft);
    KswordARKBugcheckLayoutWriteFrame(
        Writer, 364L, 298L, KswordArkBugcheckLayoutFrameFullMiddleMiddle);
    KswordARKBugcheckLayoutWriteFrame(
        Writer, 680L, 298L, KswordArkBugcheckLayoutFrameFullMiddleRight);
    KswordARKBugcheckLayoutWriteFrame(
        Writer, 16L, 476L, KswordArkBugcheckLayoutFrameFullBottomLeft);
    KswordARKBugcheckLayoutWriteFrame(
        Writer, 508L, 476L, KswordArkBugcheckLayoutFrameFullBottomRight);

    KswordARKBugcheckLayoutWriteFormatted(
        Writer, 28L, 122L, KswordArkBugcheckLayoutColorMuted, 35UL,
        "BUGCHECK");
    KswordARKBugcheckLayoutWriteFormatted(
        Writer, 28L, 144L, KswordArkBugcheckLayoutColorAccent, 35UL,
        "%s", KswordARKBugcheckName(Diagnostics->BugCheckCode));
    KswordARKBugcheckLayoutWriteFormatted(
        Writer, 28L, 164L, KswordArkBugcheckLayoutColorAccent, 35UL,
        "0x%08lX", Diagnostics->BugCheckCode);
    KswordARKBugcheckLayoutWriteFormatted(
        Writer, 28L, 190L, KswordArkBugcheckLayoutColorText, 35UL,
        "SYSTEM STOPPED SAFELY");
    KswordARKBugcheckLayoutWriteFormatted(
        Writer, 28L, 208L, KswordArkBugcheckLayoutColorMuted, 35UL,
        "%s", KswordARKBugcheckLayoutSummaryText(Diagnostics->CandidateClass));
    KswordARKBugcheckLayoutWriteFormatted(
        Writer, 28L, 226L, KswordArkBugcheckLayoutColorText, 35UL,
        "CONFIDENCE  %s",
        KswordARKBugcheckConfidenceText(Diagnostics->CandidateConfidence));
    KswordARKBugcheckLayoutWriteFormatted(
        Writer, 28L, 244L, KswordArkBugcheckLayoutColorText, 35UL,
        "CAPTURE     COMPLETE");

    KswordARKBugcheckLayoutWriteFormatted(
        Writer, 376L, 122L, KswordArkBugcheckLayoutColorMuted, 31UL,
        "FAULT CONTEXT");
    KswordARKBugcheckLayoutWriteFormatted(
        Writer, 376L, 144L, KswordArkBugcheckLayoutColorAccent, 31UL,
        "IP      0x%p", (PVOID)Diagnostics->FaultAddress);
    KswordARKBugcheckLayoutWriteFormatted(
        Writer, 376L, 164L, KswordArkBugcheckLayoutColorText, 31UL,
        "PARAM   %lu", Diagnostics->FaultParameter);
    KswordARKBugcheckLayoutWriteFormatted(
        Writer, 376L, 182L, KswordArkBugcheckLayoutColorText, 31UL,
        "MEANING %s", Diagnostics->FaultMeaning);
    KswordARKBugcheckLayoutWriteFormatted(
        Writer, 376L, 200L, KswordArkBugcheckLayoutColorText, 31UL,
        "CPU     %lu", Diagnostics->Cpu);
    KswordARKBugcheckLayoutWriteFormatted(
        Writer, 376L, 218L, KswordArkBugcheckLayoutColorText, 31UL,
        "IRQL    %lu", Diagnostics->Irql);
    KswordARKBugcheckLayoutWriteFormatted(
        Writer, 376L, 236L, KswordArkBugcheckLayoutColorText, 31UL,
        "SOURCE  %s", Diagnostics->CandidateSource);
    KswordARKBugcheckLayoutWriteFormatted(
        Writer, 376L, 254L, KswordArkBugcheckLayoutColorText, 31UL,
        "ADDRESS 0x%p", (PVOID)Diagnostics->CandidateAddress);

    KswordARKBugcheckLayoutWriteFormatted(
        Writer, 692L, 122L, KswordArkBugcheckLayoutColorMuted, 32UL,
        "DUMP STATUS");
    KswordARKBugcheckLayoutWriteFormatted(
        Writer, 692L, 144L, KswordArkBugcheckLayoutColorAccent, 32UL,
        "STAGE   %s", KswordARKBugcheckDumpTypeText(Diagnostics->LastDumpType));
    KswordARKBugcheckLayoutWriteFormatted(
        Writer, 692L, 164L, KswordArkBugcheckLayoutColorText, 32UL,
        "REASON  %s", KswordARKBugcheckReasonText(Diagnostics->LastReason));
    KswordARKBugcheckLayoutWriteFormatted(
        Writer, 692L, 182L, KswordArkBugcheckLayoutColorText, 32UL,
        "OFFSET  0x%p", (PVOID)(ULONG_PTR)Diagnostics->DumpOffset);
    KswordARKBugcheckLayoutWriteFormatted(
        Writer, 692L, 200L, KswordArkBugcheckLayoutColorText, 32UL,
        "CHUNK   0x%08lX", Diagnostics->DumpBufferLength);
    KswordARKBugcheckLayoutWriteFormatted(
        Writer, 692L, 218L, KswordArkBugcheckLayoutColorText, 32UL,
        "CALLBACKS 0x%02lX", CallbackMask & 0x0FUL);
    KswordARKBugcheckLayoutWriteFormatted(
        Writer, 692L, 236L, KswordArkBugcheckLayoutColorText, 32UL,
        "CAPTURE COMPLETE");
    KswordARKBugcheckLayoutWriteFormatted(
        Writer, 692L, 254L, KswordArkBugcheckLayoutColorMuted, 32UL,
        "PROGRESS IS MANAGED BY WINDOWS");

    KswordARKBugcheckLayoutWriteFormatted(
        Writer, 28L, 310L, KswordArkBugcheckLayoutColorMuted, 35UL,
        "CRASH PARAMETERS");
    KswordARKBugcheckLayoutWriteFormatted(
        Writer, 28L, 334L, KswordArkBugcheckLayoutColorText, 35UL,
        "ARG1  0x%p", (PVOID)Diagnostics->Parameter1);
    KswordARKBugcheckLayoutWriteFormatted(
        Writer, 28L, 354L, KswordArkBugcheckLayoutColorText, 35UL,
        "ARG2  0x%p", (PVOID)Diagnostics->Parameter2);
    KswordARKBugcheckLayoutWriteFormatted(
        Writer, 28L, 374L, KswordArkBugcheckLayoutColorText, 35UL,
        "ARG3  0x%p", (PVOID)Diagnostics->Parameter3);
    KswordARKBugcheckLayoutWriteFormatted(
        Writer, 28L, 394L, KswordArkBugcheckLayoutColorText, 35UL,
        "ARG4  0x%p", (PVOID)Diagnostics->Parameter4);
    KswordARKBugcheckLayoutWriteFormatted(
        Writer, 28L, 420L, KswordArkBugcheckLayoutColorMuted, 35UL,
        "FAULT VALUE COMES FROM ARG%lu", Diagnostics->FaultParameter);

    KswordARKBugcheckLayoutWriteFormatted(
        Writer, 376L, 310L, KswordArkBugcheckLayoutColorMuted, 31UL,
        "FAULTING MODULE");
    KswordARKBugcheckLayoutWriteFormatted(
        Writer, 376L, 334L, KswordArkBugcheckLayoutColorAccent, 31UL,
        "%s", moduleText);
    KswordARKBugcheckLayoutWriteFormatted(
        Writer, 376L, 354L, KswordArkBugcheckLayoutColorText, 31UL,
        "BASE   0x%p", (PVOID)Diagnostics->CandidateModuleBase);
    KswordARKBugcheckLayoutWriteFormatted(
        Writer, 376L, 374L, KswordArkBugcheckLayoutColorText, 31UL,
        "SIZE   0x%08lX", Diagnostics->CandidateModuleSize);
    KswordARKBugcheckLayoutWriteFormatted(
        Writer, 376L, 394L, KswordArkBugcheckLayoutColorText, 31UL,
        "OFFSET 0x%p", (PVOID)Diagnostics->CandidateModuleOffset);
    KswordARKBugcheckLayoutWriteFormatted(
        Writer, 376L, 414L, KswordArkBugcheckLayoutColorText, 31UL,
        "CLASS  %s",
        KswordARKBugcheckModuleClassText(Diagnostics->CandidateClass));
    KswordARKBugcheckLayoutWriteFormatted(
        Writer, 376L, 434L, KswordArkBugcheckLayoutColorText, 31UL,
        "CONF   %s",
        KswordARKBugcheckConfidenceText(Diagnostics->CandidateConfidence));

    KswordARKBugcheckLayoutWriteFormatted(
        Writer, 692L, 310L, KswordArkBugcheckLayoutColorMuted, 32UL,
        "SYSTEM SNAPSHOT");
    KswordARKBugcheckLayoutWriteFormatted(
        Writer, 692L, 334L, KswordArkBugcheckLayoutColorText, 32UL,
        "CPU / IRQL   %lu / %lu", Diagnostics->Cpu, Diagnostics->Irql);
    KswordARKBugcheckLayoutWriteFormatted(
        Writer, 692L, 354L, KswordArkBugcheckLayoutColorText, 32UL,
        "CACHED MODULES  %lu", ModuleCount);
    KswordARKBugcheckLayoutWriteFormatted(
        Writer, 692L, 374L, KswordArkBugcheckLayoutColorText, 32UL,
        "DRIVER OBJ  0x%p", g_KswordArkBugcheckState.DriverObject);
    KswordARKBugcheckLayoutWriteFormatted(
        Writer, 692L, 394L, KswordArkBugcheckLayoutColorText, 32UL,
        "DEVICE OBJ  0x%p", g_KswordArkBugcheckState.DeviceObject);
    KswordARKBugcheckLayoutWriteFormatted(
        Writer, 692L, 414L, KswordArkBugcheckLayoutColorText, 32UL,
        "CLASSIC / TRIAGE  %lu / %lu",
        (ULONG)((CallbackMask & 0x1UL) != 0),
        (ULONG)((CallbackMask & 0x8UL) != 0));
    KswordARKBugcheckLayoutWriteFormatted(
        Writer, 692L, 434L, KswordArkBugcheckLayoutColorText, 32UL,
        "DUMP / SECONDARY  %lu / %lu",
        (ULONG)((CallbackMask & 0x4UL) != 0),
        (ULONG)((CallbackMask & 0x2UL) != 0));

    KswordARKBugcheckLayoutWriteFormatted(
        Writer, 28L, 488L, KswordArkBugcheckLayoutColorMuted, 50UL,
        "DIAGNOSTIC SUMMARY");
    KswordARKBugcheckLayoutWriteFormatted(
        Writer, 28L, 512L, KswordArkBugcheckLayoutColorAccent, 50UL,
        "%s", KswordARKBugcheckLayoutSummaryText(Diagnostics->CandidateClass));
    KswordARKBugcheckLayoutWriteFormatted(
        Writer, 28L, 534L, KswordArkBugcheckLayoutColorText, 50UL,
        "CANDIDATE  %s", moduleText);
    KswordARKBugcheckLayoutWriteFormatted(
        Writer, 28L, 554L, KswordArkBugcheckLayoutColorText, 50UL,
        "CONFIDENCE %s",
        KswordARKBugcheckConfidenceText(Diagnostics->CandidateConfidence));
    KswordARKBugcheckLayoutWriteFormatted(
        Writer, 28L, 582L, KswordArkBugcheckLayoutColorText, 50UL,
        "ACTION  PRESERVE AND ANALYZE THE NEWEST DUMP");
    KswordARKBugcheckLayoutWriteFormatted(
        Writer, 28L, 604L, KswordArkBugcheckLayoutColorMuted, 50UL,
        "REPORT  ATTACH THIS SCREEN AND THE CRASH DUMP");

    KswordARKBugcheckLayoutWriteFormatted(
        Writer, 520L, 488L, KswordArkBugcheckLayoutColorMuted, 52UL,
        "HELP");
    KswordARKBugcheckLayoutWriteFormatted(
        Writer, 520L, 512L, KswordArkBugcheckLayoutColorText, 52UL,
        "> PRESERVE THE NEWEST CRASH DUMP.");
    KswordARKBugcheckLayoutWriteFormatted(
        Writer, 520L, 534L, KswordArkBugcheckLayoutColorText, 52UL,
        "> REVIEW RECENT DRIVER OR HARDWARE CHANGES.");
    KswordARKBugcheckLayoutWriteFormatted(
        Writer, 520L, 556L, KswordArkBugcheckLayoutColorText, 52UL,
        "> ANALYZE THE DUMP IN KSWORDARK.");
    KswordARKBugcheckLayoutWriteFormatted(
        Writer, 520L, 578L, KswordArkBugcheckLayoutColorText, 52UL,
        "> DO NOT POWER OFF DURING DUMP WRITING.");
    KswordARKBugcheckLayoutWriteFormatted(
        Writer, 520L, 606L, KswordArkBugcheckLayoutColorMuted, 52UL,
        "WINDOWS CONTROLS THE FINAL RESTART.");

    // Keep the lower progress band free for text painted by Windows itself.
    KswordARKBugcheckLayoutWriteFormatted(
        Writer, 16L, 724L, KswordArkBugcheckLayoutColorMuted, 80UL,
        "WAITING FOR WINDOWS TO COMPLETE THE CRASH DUMP. DO NOT POWER OFF.");
}

NTSTATUS
KswordARKBugcheckLayoutDraw(
    _In_ const KSWORD_ARK_BUGCHECK_LAYOUT_CANVAS* Canvas,
    _In_ const KSWORD_ARK_BUGCHECK_DIAGNOSTICS* Diagnostics,
    _In_ ULONG CallbackMask,
    _In_ ULONG ModuleCount
    )
{
    KSWORD_ARK_BUGCHECK_LAYOUT_WRITER writer;
    BOOLEAN compact;
    BOOLEAN detailed;

    if (Canvas == NULL || Diagnostics == NULL ||
        Canvas->DrawText == NULL || Canvas->DrawFrame == NULL ||
        Canvas->Width < KSWORD_ARK_BUGCHECK_LAYOUT_REQUIRED_WIDTH ||
        Canvas->Height < KSWORD_ARK_BUGCHECK_LAYOUT_REQUIRED_HEIGHT) {
        return STATUS_INVALID_PARAMETER;
    }

    RtlZeroMemory(&writer, sizeof(writer));
    writer.Canvas = Canvas;
    writer.OriginX = KswordARKBugcheckLayoutOriginX(
        Canvas->Width,
        Canvas->Height);
    writer.Status = STATUS_SUCCESS;
    detailed = KswordARKBugcheckLayoutIsDetailed(
        Canvas->Width,
        Canvas->Height);
    compact = KswordARKBugcheckLayoutIsCompact(Canvas->Width, Canvas->Height);

    if (detailed) {
        return KswordARKBugcheckLayoutDrawDetailed(
            Canvas,
            Diagnostics,
            CallbackMask,
            ModuleCount);
    }
    KswordARKBugcheckLayoutWriteHeader(&writer, Diagnostics, compact);
    if (compact) {
        KswordARKBugcheckLayoutDrawCompact(
            &writer,
            Diagnostics,
            CallbackMask,
            ModuleCount);
    } else {
        KswordARKBugcheckLayoutDrawFull(
            &writer,
            Diagnostics,
            CallbackMask,
            ModuleCount);
    }
    return writer.Status;
}
