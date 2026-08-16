/*++

Module Name:

    bugcheck_layout_detailed.c

Abstract:

    Information-dense 1280x720 crash layout for the physical BGP and VMware
    framebuffer renderers. Unavailable debugger data is labeled explicitly
    instead of being fabricated or collected through unsafe crash-time work.

--*/

#include "bugcheck_layout_detailed.h"

#include <ntstrsafe.h>
#include <stdarg.h>

typedef struct _KSWORD_ARK_BUGCHECK_DETAILED_WRITER
{
    const KSWORD_ARK_BUGCHECK_LAYOUT_CANVAS* Canvas;
    LONG OriginX;
    NTSTATUS Status;
    CHAR Line[KSWORD_ARK_BUGCHECK_PANEL_LINE_CHARS];
} KSWORD_ARK_BUGCHECK_DETAILED_WRITER;

// This helper clips every formatted row before it reaches the fixed canvas.
static VOID
KswordARKBugcheckDetailedClipLine(
    _Inout_updates_z_(Capacity) PCHAR Text,
    _In_ ULONG Capacity,
    _In_ ULONG MaximumCharacters
    )
{
    SIZE_T length;

    if (Text == NULL || Capacity == 0UL || MaximumCharacters == 0UL) {
        return;
    }
    if (MaximumCharacters >= Capacity) {
        MaximumCharacters = Capacity - 1UL;
    }

    length = 0UL;
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

// This helper formats into a fixed stack buffer and never allocates memory.
static VOID
KswordARKBugcheckDetailedWrite(
    _Inout_ KSWORD_ARK_BUGCHECK_DETAILED_WRITER* Writer,
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

    KswordARKBugcheckDetailedClipLine(
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

// This helper forwards a pre-generated frame to the active renderer.
static VOID
KswordARKBugcheckDetailedFrame(
    _Inout_ KSWORD_ARK_BUGCHECK_DETAILED_WRITER* Writer,
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

// This helper removes internal resolver notes from the public module label.
static PCSTR
KswordARKBugcheckDetailedModuleText(
    _In_ const KSWORD_ARK_BUGCHECK_DIAGNOSTICS* Diagnostics
    )
{
    if (Diagnostics->CandidateModule[0] == '\0' ||
        Diagnostics->CandidateModule[0] == '(') {
        return "NOT IDENTIFIED";
    }
    return Diagnostics->CandidateModule;
}

// This helper returns a safe source label when no resolver supplied one.
static PCSTR
KswordARKBugcheckDetailedSourceText(
    _In_ const KSWORD_ARK_BUGCHECK_DIAGNOSTICS* Diagnostics
    )
{
    if (Diagnostics->CandidateSource[0] == '\0') {
        return "NOT IDENTIFIED";
    }
    return Diagnostics->CandidateSource;
}

// The header exposes captured state and the availability contract at a glance.
static VOID
KswordARKBugcheckDetailedDrawHeader(
    _Inout_ KSWORD_ARK_BUGCHECK_DETAILED_WRITER* Writer,
    _In_ const KSWORD_ARK_BUGCHECK_DIAGNOSTICS* Diagnostics,
    _In_ ULONG CallbackMask
    )
{
    KswordARKBugcheckDetailedWrite(
        Writer, 280L, 18L, KswordArkBugcheckLayoutColorAccent, 58UL,
        "KSWORD ARK CRASH DIAGNOSTICS");
    KswordARKBugcheckDetailedWrite(
        Writer, 280L, 40L, KswordArkBugcheckLayoutColorText, 72UL,
        "A FATAL KERNEL ERROR HAS OCCURRED.");
    KswordARKBugcheckDetailedWrite(
        Writer, 280L, 56L, KswordArkBugcheckLayoutColorMuted, 72UL,
        "THE SYSTEM STOPPED TO PROTECT DATA AND PRESERVE CRASH CONTEXT.");
    KswordARKBugcheckDetailedWrite(
        Writer, 280L, 72L, KswordArkBugcheckLayoutColorWarning, 72UL,
        "AMBER FIELDS REQUIRE MEMORY.DMP ANALYSIS AFTER RESTART.");
    KswordARKBugcheckDetailedWrite(
        Writer, 1122L, 18L, KswordArkBugcheckLayoutColorText, 16UL,
        "CRASH CPU %02lu", Diagnostics->Cpu);
    KswordARKBugcheckDetailedWrite(
        Writer, 1122L, 36L, KswordArkBugcheckLayoutColorText, 16UL,
        "IRQL      %02lu", Diagnostics->Irql);
    KswordARKBugcheckDetailedWrite(
        Writer, 1122L, 54L, KswordArkBugcheckLayoutColorText, 16UL,
        "CALLBACKS 0x%02lX", CallbackMask & 0x0FUL);
    KswordARKBugcheckDetailedWrite(
        Writer, 1122L, 72L, KswordArkBugcheckLayoutColorWarning, 16UL,
        "UPTIME DUMP ONLY");
}

// The BugCheck panel contains only callback arguments and derived verdicts.
static VOID
KswordARKBugcheckDetailedDrawBugcheck(
    _Inout_ KSWORD_ARK_BUGCHECK_DETAILED_WRITER* Writer,
    _In_ const KSWORD_ARK_BUGCHECK_DIAGNOSTICS* Diagnostics
    )
{
    KswordARKBugcheckDetailedWrite(
        Writer, 28L, 112L, KswordArkBugcheckLayoutColorMuted, 48UL,
        "BUGCHECK");
    KswordARKBugcheckDetailedWrite(
        Writer, 388L, 112L, KswordArkBugcheckLayoutColorAccent, 12UL,
        "[CAPTURED]");
    KswordARKBugcheckDetailedWrite(
        Writer, 28L, 134L, KswordArkBugcheckLayoutColorAccent, 48UL,
        "%s", KswordARKBugcheckName(Diagnostics->BugCheckCode));
    KswordARKBugcheckDetailedWrite(
        Writer, 28L, 152L, KswordArkBugcheckLayoutColorAccent, 48UL,
        "0x%08lX", Diagnostics->BugCheckCode);
    KswordARKBugcheckDetailedWrite(
        Writer, 28L, 174L, KswordArkBugcheckLayoutColorText, 48UL,
        "ARG1  0x%p", (PVOID)Diagnostics->Parameter1);
    KswordARKBugcheckDetailedWrite(
        Writer, 28L, 190L, KswordArkBugcheckLayoutColorText, 48UL,
        "ARG2  0x%p", (PVOID)Diagnostics->Parameter2);
    KswordARKBugcheckDetailedWrite(
        Writer, 28L, 206L, KswordArkBugcheckLayoutColorText, 48UL,
        "ARG3  0x%p", (PVOID)Diagnostics->Parameter3);
    KswordARKBugcheckDetailedWrite(
        Writer, 28L, 222L, KswordArkBugcheckLayoutColorText, 48UL,
        "ARG4  0x%p", (PVOID)Diagnostics->Parameter4);
    KswordARKBugcheckDetailedWrite(
        Writer, 28L, 242L, KswordArkBugcheckLayoutColorText, 48UL,
        "FAULT PARAM %lu  %s",
        Diagnostics->FaultParameter,
        Diagnostics->FaultMeaning);
    KswordARKBugcheckDetailedWrite(
        Writer, 28L, 258L, KswordArkBugcheckLayoutColorText, 48UL,
        "FAULT IP  0x%p", (PVOID)Diagnostics->FaultAddress);
    KswordARKBugcheckDetailedWrite(
        Writer, 28L, 278L, KswordArkBugcheckLayoutColorAccent, 48UL,
        "%s", KswordARKBugcheckVerdictText(Diagnostics->CandidateClass));
    KswordARKBugcheckDetailedWrite(
        Writer, 28L, 294L, KswordArkBugcheckLayoutColorText, 48UL,
        "CONFIDENCE %s",
        KswordARKBugcheckConfidenceText(Diagnostics->CandidateConfidence));
}

// The fault panel separates captured callback values from debugger registers.
static VOID
KswordARKBugcheckDetailedDrawFaultContext(
    _Inout_ KSWORD_ARK_BUGCHECK_DETAILED_WRITER* Writer,
    _In_ const KSWORD_ARK_BUGCHECK_DIAGNOSTICS* Diagnostics
    )
{
    PCSTR moduleText;

    moduleText = KswordARKBugcheckDetailedModuleText(Diagnostics);
    KswordARKBugcheckDetailedWrite(
        Writer, 504L, 112L, KswordArkBugcheckLayoutColorMuted, 35UL,
        "FAULT CONTEXT");
    KswordARKBugcheckDetailedWrite(
        Writer, 778L, 112L, KswordArkBugcheckLayoutColorWarning, 8UL,
        "[MIXED]");
    KswordARKBugcheckDetailedWrite(
        Writer, 504L, 136L, KswordArkBugcheckLayoutColorAccent, 35UL,
        "RIP     0x%p", (PVOID)Diagnostics->FaultAddress);
    KswordARKBugcheckDetailedWrite(
        Writer, 504L, 152L, KswordArkBugcheckLayoutColorText, 35UL,
        "CPU     %lu", Diagnostics->Cpu);
    KswordARKBugcheckDetailedWrite(
        Writer, 504L, 168L, KswordArkBugcheckLayoutColorText, 35UL,
        "IRQL    %lu", Diagnostics->Irql);
    KswordARKBugcheckDetailedWrite(
        Writer, 504L, 184L, KswordArkBugcheckLayoutColorText, 35UL,
        "SOURCE  %s", KswordARKBugcheckDetailedSourceText(Diagnostics));
    KswordARKBugcheckDetailedWrite(
        Writer, 504L, 200L, KswordArkBugcheckLayoutColorText, 35UL,
        "MODULE  %s", moduleText);
    KswordARKBugcheckDetailedWrite(
        Writer, 504L, 216L, KswordArkBugcheckLayoutColorText, 35UL,
        "CLASS   %s",
        KswordARKBugcheckModuleClassText(Diagnostics->CandidateClass));
    KswordARKBugcheckDetailedWrite(
        Writer, 504L, 232L, KswordArkBugcheckLayoutColorText, 35UL,
        "CONF    %s",
        KswordARKBugcheckConfidenceText(Diagnostics->CandidateConfidence));
    KswordARKBugcheckDetailedWrite(
        Writer, 504L, 252L, KswordArkBugcheckLayoutColorWarning, 35UL,
        "RSP     DUMP ONLY");
    KswordARKBugcheckDetailedWrite(
        Writer, 504L, 268L, KswordArkBugcheckLayoutColorWarning, 35UL,
        "RFLAGS  DUMP ONLY");
    KswordARKBugcheckDetailedWrite(
        Writer, 504L, 284L, KswordArkBugcheckLayoutColorWarning, 35UL,
        "CR2     DUMP ONLY");
}

// Instruction bytes are never dereferenced in the high-IRQL callback path.
static VOID
KswordARKBugcheckDetailedDrawInstruction(
    _Inout_ KSWORD_ARK_BUGCHECK_DETAILED_WRITER* Writer,
    _In_ const KSWORD_ARK_BUGCHECK_DIAGNOSTICS* Diagnostics
    )
{
    KswordARKBugcheckDetailedWrite(
        Writer, 860L, 112L, KswordArkBugcheckLayoutColorMuted, 43UL,
        "FAULTING INSTRUCTION");
    KswordARKBugcheckDetailedWrite(
        Writer, 1160L, 112L, KswordArkBugcheckLayoutColorWarning, 11UL,
        "[DUMP ONLY]");
    KswordARKBugcheckDetailedWrite(
        Writer, 860L, 138L, KswordArkBugcheckLayoutColorWarning, 43UL,
        "PREVIOUS   REQUIRES MEMORY.DMP");
    KswordARKBugcheckDetailedWrite(
        Writer, 860L, 158L, KswordArkBugcheckLayoutColorAccent, 43UL,
        "> CURRENT  0x%p", (PVOID)Diagnostics->FaultAddress);
    KswordARKBugcheckDetailedWrite(
        Writer, 860L, 178L, KswordArkBugcheckLayoutColorWarning, 43UL,
        "NEXT       REQUIRES MEMORY.DMP");
    KswordARKBugcheckDetailedWrite(
        Writer, 860L, 206L, KswordArkBugcheckLayoutColorText, 43UL,
        "ADDRESS   0x%p", (PVOID)Diagnostics->CandidateAddress);
    KswordARKBugcheckDetailedWrite(
        Writer, 860L, 224L, KswordArkBugcheckLayoutColorText, 43UL,
        "ACCESS    %s", Diagnostics->FaultMeaning);
    KswordARKBugcheckDetailedWrite(
        Writer, 860L, 242L, KswordArkBugcheckLayoutColorWarning, 43UL,
        "BYTES     NOT READ AT BUGCHECK IRQL");
    KswordARKBugcheckDetailedWrite(
        Writer, 860L, 260L, KswordArkBugcheckLayoutColorWarning, 43UL,
        "SYMBOL    RESOLVE AFTER RESTART");
    KswordARKBugcheckDetailedWrite(
        Writer, 860L, 282L, KswordArkBugcheckLayoutColorMuted, 43UL,
        "WINDBG    .TRAP / .CXR / UB / U");
}

// Thread and process details are intentionally deferred to dump analysis.
static VOID
KswordARKBugcheckDetailedDrawThread(
    _Inout_ KSWORD_ARK_BUGCHECK_DETAILED_WRITER* Writer,
    _In_ const KSWORD_ARK_BUGCHECK_DIAGNOSTICS* Diagnostics
    )
{
    KswordARKBugcheckDetailedWrite(
        Writer, 28L, 323L, KswordArkBugcheckLayoutColorMuted, 32UL,
        "CURRENT THREAD / PROCESS");
    KswordARKBugcheckDetailedWrite(
        Writer, 226L, 323L, KswordArkBugcheckLayoutColorWarning, 11UL,
        "[DUMP ONLY]");
    KswordARKBugcheckDetailedWrite(
        Writer, 28L, 348L, KswordArkBugcheckLayoutColorWarning, 32UL,
        "THREAD   NOT CAPTURED");
    KswordARKBugcheckDetailedWrite(
        Writer, 28L, 364L, KswordArkBugcheckLayoutColorWarning, 32UL,
        "PROCESS  NOT CAPTURED");
    KswordARKBugcheckDetailedWrite(
        Writer, 28L, 380L, KswordArkBugcheckLayoutColorWarning, 32UL,
        "START    DUMP ONLY");
    KswordARKBugcheckDetailedWrite(
        Writer, 28L, 396L, KswordArkBugcheckLayoutColorWarning, 32UL,
        "STATE    DUMP ONLY");
    KswordARKBugcheckDetailedWrite(
        Writer, 28L, 412L, KswordArkBugcheckLayoutColorText, 32UL,
        "CPU      %lu", Diagnostics->Cpu);
    KswordARKBugcheckDetailedWrite(
        Writer, 28L, 428L, KswordArkBugcheckLayoutColorText, 32UL,
        "IRQL     %lu", Diagnostics->Irql);
    KswordARKBugcheckDetailedWrite(
        Writer, 28L, 448L, KswordArkBugcheckLayoutColorMuted, 32UL,
        "WINDBG   !THREAD / !PROCESS");
}

// Stack walking is represented honestly because unwind work is not crash-safe.
static VOID
KswordARKBugcheckDetailedDrawStack(
    _Inout_ KSWORD_ARK_BUGCHECK_DETAILED_WRITER* Writer
    )
{
    KswordARKBugcheckDetailedWrite(
        Writer, 346L, 323L, KswordArkBugcheckLayoutColorMuted, 34UL,
        "STACK TRACE / TOP FRAMES");
    KswordARKBugcheckDetailedWrite(
        Writer, 558L, 323L, KswordArkBugcheckLayoutColorWarning, 11UL,
        "[DUMP ONLY]");
    KswordARKBugcheckDetailedWrite(
        Writer, 346L, 348L, KswordArkBugcheckLayoutColorWarning, 34UL,
        "#00  REQUIRES MEMORY.DMP");
    KswordARKBugcheckDetailedWrite(
        Writer, 346L, 364L, KswordArkBugcheckLayoutColorWarning, 34UL,
        "#01  REQUIRES UNWIND METADATA");
    KswordARKBugcheckDetailedWrite(
        Writer, 346L, 380L, KswordArkBugcheckLayoutColorWarning, 34UL,
        "#02  REQUIRES REGISTER CONTEXT");
    KswordARKBugcheckDetailedWrite(
        Writer, 346L, 396L, KswordArkBugcheckLayoutColorWarning, 34UL,
        "#03  RESOLVE WITH SYMBOLS");
    KswordARKBugcheckDetailedWrite(
        Writer, 346L, 416L, KswordArkBugcheckLayoutColorText, 34UL,
        "COMMAND  !ANALYZE -V");
    KswordARKBugcheckDetailedWrite(
        Writer, 346L, 432L, KswordArkBugcheckLayoutColorText, 34UL,
        "COMMAND  KV / .TRAP / .CXR");
    KswordARKBugcheckDetailedWrite(
        Writer, 346L, 448L, KswordArkBugcheckLayoutColorMuted, 34UL,
        "NO UNSAFE LIVE STACK WALK ATTEMPTED");
}

// Module identity is resolved from the nonpaged cache prepared before failure.
static VOID
KswordARKBugcheckDetailedDrawModule(
    _Inout_ KSWORD_ARK_BUGCHECK_DETAILED_WRITER* Writer,
    _In_ const KSWORD_ARK_BUGCHECK_DIAGNOSTICS* Diagnostics
    )
{
    KswordARKBugcheckDetailedWrite(
        Writer, 678L, 323L, KswordArkBugcheckLayoutColorMuted, 28UL,
        "FAULTING MODULE");
    KswordARKBugcheckDetailedWrite(
        Writer, 848L, 323L, KswordArkBugcheckLayoutColorAccent, 10UL,
        "[CAPTURED]");
    KswordARKBugcheckDetailedWrite(
        Writer, 678L, 348L, KswordArkBugcheckLayoutColorAccent, 28UL,
        "%s", KswordARKBugcheckDetailedModuleText(Diagnostics));
    KswordARKBugcheckDetailedWrite(
        Writer, 678L, 368L, KswordArkBugcheckLayoutColorText, 28UL,
        "BASE   0x%p", (PVOID)Diagnostics->CandidateModuleBase);
    KswordARKBugcheckDetailedWrite(
        Writer, 678L, 384L, KswordArkBugcheckLayoutColorText, 28UL,
        "SIZE   0x%08lX", Diagnostics->CandidateModuleSize);
    KswordARKBugcheckDetailedWrite(
        Writer, 678L, 400L, KswordArkBugcheckLayoutColorText, 28UL,
        "OFFSET 0x%p", (PVOID)Diagnostics->CandidateModuleOffset);
    KswordARKBugcheckDetailedWrite(
        Writer, 678L, 416L, KswordArkBugcheckLayoutColorText, 28UL,
        "CLASS  %s",
        KswordARKBugcheckModuleClassText(Diagnostics->CandidateClass));
    KswordARKBugcheckDetailedWrite(
        Writer, 678L, 432L, KswordArkBugcheckLayoutColorText, 28UL,
        "SOURCE %s", KswordARKBugcheckDetailedSourceText(Diagnostics));
    KswordARKBugcheckDetailedWrite(
        Writer, 678L, 448L, KswordArkBugcheckLayoutColorWarning, 28UL,
        "VERSION / PDB  DUMP ONLY");
}

// Windows blackbox streams are listed without claiming callback availability.
static VOID
KswordARKBugcheckDetailedDrawBlackbox(
    _Inout_ KSWORD_ARK_BUGCHECK_DETAILED_WRITER* Writer
    )
{
    KswordARKBugcheckDetailedWrite(
        Writer, 960L, 323L, KswordArkBugcheckLayoutColorMuted, 32UL,
        "BLACKBOX SNAPSHOT");
    KswordARKBugcheckDetailedWrite(
        Writer, 1160L, 323L, KswordArkBugcheckLayoutColorWarning, 11UL,
        "[DUMP ONLY]");
    KswordARKBugcheckDetailedWrite(
        Writer, 960L, 348L, KswordArkBugcheckLayoutColorWarning, 32UL,
        "BSD       QUERY AFTER RESTART");
    KswordARKBugcheckDetailedWrite(
        Writer, 960L, 364L, KswordArkBugcheckLayoutColorWarning, 32UL,
        "NTFS      QUERY AFTER RESTART");
    KswordARKBugcheckDetailedWrite(
        Writer, 960L, 380L, KswordArkBugcheckLayoutColorWarning, 32UL,
        "PNP       QUERY AFTER RESTART");
    KswordARKBugcheckDetailedWrite(
        Writer, 960L, 396L, KswordArkBugcheckLayoutColorWarning, 32UL,
        "WINLOGON  QUERY AFTER RESTART");
    KswordARKBugcheckDetailedWrite(
        Writer, 960L, 416L, KswordArkBugcheckLayoutColorWarning, 32UL,
        "LAST DRIVER   NOT CAPTURED");
    KswordARKBugcheckDetailedWrite(
        Writer, 960L, 432L, KswordArkBugcheckLayoutColorWarning, 32UL,
        "LAST PROCESS  NOT CAPTURED");
    KswordARKBugcheckDetailedWrite(
        Writer, 960L, 448L, KswordArkBugcheckLayoutColorMuted, 32UL,
        "WINDBG  !BLACKBOXBSD / NTFS / PNP");
}

// The processor panel reports only state that the callback captures safely.
static VOID
KswordARKBugcheckDetailedDrawCpu(
    _Inout_ KSWORD_ARK_BUGCHECK_DETAILED_WRITER* Writer,
    _In_ const KSWORD_ARK_BUGCHECK_DIAGNOSTICS* Diagnostics,
    _In_ PCSTR ModuleText
    )
{
    KswordARKBugcheckDetailedWrite(
        Writer, 28L, 489L, KswordArkBugcheckLayoutColorMuted, 50UL,
        "CPU SUMMARY");
    KswordARKBugcheckDetailedWrite(
        Writer, 342L, 489L, KswordArkBugcheckLayoutColorWarning, 18UL,
        "[CRASH CPU LIVE]");
    KswordARKBugcheckDetailedWrite(
        Writer, 28L, 514L, KswordArkBugcheckLayoutColorMuted, 50UL,
        "CPU  STATE       IRQL  CURRENT FUNCTION");
    KswordARKBugcheckDetailedWrite(
        Writer, 28L, 536L, KswordArkBugcheckLayoutColorAccent, 50UL,
        "%02lu   BUGCHECK    %02lu    %s+0x%p",
        Diagnostics->Cpu,
        Diagnostics->Irql,
        ModuleText,
        (PVOID)Diagnostics->CandidateModuleOffset);
    KswordARKBugcheckDetailedWrite(
        Writer, 28L, 558L, KswordArkBugcheckLayoutColorWarning, 50UL,
        "OTHER CPU STATES REQUIRE MEMORY.DMP");
    KswordARKBugcheckDetailedWrite(
        Writer, 28L, 578L, KswordArkBugcheckLayoutColorWarning, 50UL,
        "ACTIVE CPU COUNT NOT CAPTURED AT BUGCHECK");
    KswordARKBugcheckDetailedWrite(
        Writer, 28L, 602L, KswordArkBugcheckLayoutColorText, 50UL,
        "WINDBG  !PRCB / !RUNAWAY / ~* KV");
    KswordARKBugcheckDetailedWrite(
        Writer, 28L, 622L, KswordArkBugcheckLayoutColorMuted, 50UL,
        "GROUP NUMBER AND PER-CPU THREADS ARE DUMP ONLY");
    KswordARKBugcheckDetailedWrite(
        Writer, 28L, 650L, KswordArkBugcheckLayoutColorAccent, 50UL,
        "CAPTURED CPU / IRQL  %lu / %lu",
        Diagnostics->Cpu,
        Diagnostics->Irql);
}

// The dump panel presents callback state without inventing a percentage.
static VOID
KswordARKBugcheckDetailedDrawDump(
    _Inout_ KSWORD_ARK_BUGCHECK_DETAILED_WRITER* Writer,
    _In_ const KSWORD_ARK_BUGCHECK_DIAGNOSTICS* Diagnostics,
    _In_ ULONG CallbackMask,
    _In_ ULONG ModuleCount
    )
{
    KswordARKBugcheckDetailedWrite(
        Writer, 512L, 489L, KswordArkBugcheckLayoutColorMuted, 36UL,
        "DUMP STATUS");
    KswordARKBugcheckDetailedWrite(
        Writer, 750L, 489L, KswordArkBugcheckLayoutColorAccent, 10UL,
        "[CAPTURED]");
    KswordARKBugcheckDetailedWrite(
        Writer, 512L, 514L, KswordArkBugcheckLayoutColorText, 36UL,
        "TYPE      %s",
        KswordARKBugcheckDumpTypeText(Diagnostics->LastDumpType));
    KswordARKBugcheckDetailedWrite(
        Writer, 512L, 530L, KswordArkBugcheckLayoutColorAccent, 36UL,
        "STAGE     %s",
        KswordARKBugcheckReasonText(Diagnostics->LastReason));
    KswordARKBugcheckDetailedWrite(
        Writer, 512L, 546L, KswordArkBugcheckLayoutColorText, 36UL,
        "OFFSET    0x%p", (PVOID)(ULONG_PTR)Diagnostics->DumpOffset);
    KswordARKBugcheckDetailedWrite(
        Writer, 512L, 562L, KswordArkBugcheckLayoutColorText, 36UL,
        "CHUNK     0x%08lX", Diagnostics->DumpBufferLength);
    KswordARKBugcheckDetailedWrite(
        Writer, 512L, 578L, KswordArkBugcheckLayoutColorText, 36UL,
        "CALLBACKS 0x%02lX", CallbackMask & 0x0FUL);
    KswordARKBugcheckDetailedWrite(
        Writer, 512L, 594L, KswordArkBugcheckLayoutColorText, 36UL,
        "MODULES   %lu", ModuleCount);
    KswordARKBugcheckDetailedWrite(
        Writer, 512L, 610L, KswordArkBugcheckLayoutColorText, 36UL,
        "DRIVER    0x%p", g_KswordArkBugcheckState.DriverObject);
    KswordARKBugcheckDetailedWrite(
        Writer, 512L, 626L, KswordArkBugcheckLayoutColorText, 36UL,
        "DEVICE    0x%p", g_KswordArkBugcheckState.DeviceObject);
    KswordARKBugcheckDetailedWrite(
        Writer, 512L, 646L, KswordArkBugcheckLayoutColorWarning, 36UL,
        "PERCENT   CONTROLLED BY WINDOWS");
    KswordARKBugcheckDetailedWrite(
        Writer, 512L, 662L, KswordArkBugcheckLayoutColorMuted, 36UL,
        "DO NOT POWER OFF DURING DUMP WRITING");
}

// Event metadata states clearly which identifiers only exist after reboot.
static VOID
KswordARKBugcheckDetailedDrawEvent(
    _Inout_ KSWORD_ARK_BUGCHECK_DETAILED_WRITER* Writer,
    _In_ const KSWORD_ARK_BUGCHECK_DIAGNOSTICS* Diagnostics
    )
{
    KswordARKBugcheckDetailedWrite(
        Writer, 864L, 489L, KswordArkBugcheckLayoutColorMuted, 43UL,
        "EVENT INFO");
    KswordARKBugcheckDetailedWrite(
        Writer, 1130L, 489L, KswordArkBugcheckLayoutColorWarning, 14UL,
        "[MIXED SOURCE]");
    KswordARKBugcheckDetailedWrite(
        Writer, 864L, 514L, KswordArkBugcheckLayoutColorText, 43UL,
        "PERF COUNTER  0x%p",
        (PVOID)(ULONG_PTR)Diagnostics->PerfCounter.QuadPart);
    KswordARKBugcheckDetailedWrite(
        Writer, 864L, 530L, KswordArkBugcheckLayoutColorText, 43UL,
        "BUGCHECK      0x%08lX", Diagnostics->BugCheckCode);
    KswordARKBugcheckDetailedWrite(
        Writer, 864L, 546L, KswordArkBugcheckLayoutColorWarning, 43UL,
        "EVENT TIME / REPORT ID  ASSIGNED AFTER RESTART");
    KswordARKBugcheckDetailedWrite(
        Writer, 864L, 562L, KswordArkBugcheckLayoutColorMuted, 43UL,
        "DUMP TARGET   MEMORY.DMP");
}

// Static recovery guidance occupies the last detailed panel.
static VOID
KswordARKBugcheckDetailedDrawHelp(
    _Inout_ KSWORD_ARK_BUGCHECK_DETAILED_WRITER* Writer
    )
{
    KswordARKBugcheckDetailedWrite(
        Writer, 864L, 591L, KswordArkBugcheckLayoutColorMuted, 43UL,
        "NEXT ACTION");
    KswordARKBugcheckDetailedWrite(
        Writer, 1120L, 591L, KswordArkBugcheckLayoutColorAccent, 15UL,
        "[SAFE GUIDANCE]");
    KswordARKBugcheckDetailedWrite(
        Writer, 864L, 614L, KswordArkBugcheckLayoutColorText, 43UL,
        "> PRESERVE THE NEWEST CRASH DUMP.");
    KswordARKBugcheckDetailedWrite(
        Writer, 864L, 630L, KswordArkBugcheckLayoutColorText, 43UL,
        "> AFTER RESTART ATTACH THIS SCREEN AND MEMORY.DMP.");
    KswordARKBugcheckDetailedWrite(
        Writer, 864L, 646L, KswordArkBugcheckLayoutColorText, 43UL,
        "> RESOLVE AMBER FIELDS WITH WINDBG OR KSWORDARK.");
    KswordARKBugcheckDetailedWrite(
        Writer, 864L, 662L, KswordArkBugcheckLayoutColorWarning, 43UL,
        "> DO NOT POWER OFF WHILE WINDOWS WRITES THE DUMP.");
}

// The public entry renders the complete 1280x720 information architecture.
NTSTATUS
KswordARKBugcheckLayoutDrawDetailed(
    _In_ const KSWORD_ARK_BUGCHECK_LAYOUT_CANVAS* Canvas,
    _In_ const KSWORD_ARK_BUGCHECK_DIAGNOSTICS* Diagnostics,
    _In_ ULONG CallbackMask,
    _In_ ULONG ModuleCount
    )
{
    KSWORD_ARK_BUGCHECK_DETAILED_WRITER writer;
    PCSTR moduleText;

    if (Canvas == NULL || Diagnostics == NULL ||
        Canvas->DrawText == NULL || Canvas->DrawFrame == NULL ||
        Canvas->Width < KSWORD_ARK_BUGCHECK_LAYOUT_DETAILED_WIDTH ||
        Canvas->Height < KSWORD_ARK_BUGCHECK_LAYOUT_DETAILED_HEIGHT) {
        return STATUS_INVALID_PARAMETER;
    }

    RtlZeroMemory(&writer, sizeof(writer));
    writer.Canvas = Canvas;
    writer.OriginX = KswordARKBugcheckLayoutOriginX(
        Canvas->Width,
        Canvas->Height);
    writer.Status = STATUS_SUCCESS;
    moduleText = KswordARKBugcheckDetailedModuleText(Diagnostics);

    // Every frame uses resources created at PASSIVE_LEVEL before the failure.
    KswordARKBugcheckDetailedFrame(
        &writer, 16L, 100L, KswordArkBugcheckLayoutFrameDetailedTopLeft);
    KswordARKBugcheckDetailedFrame(
        &writer, 492L, 100L, KswordArkBugcheckLayoutFrameDetailedTopMiddle);
    KswordARKBugcheckDetailedFrame(
        &writer, 848L, 100L, KswordArkBugcheckLayoutFrameDetailedTopRight);
    KswordARKBugcheckDetailedFrame(
        &writer, 16L, 311L, KswordArkBugcheckLayoutFrameDetailedMiddleThread);
    KswordARKBugcheckDetailedFrame(
        &writer, 334L, 311L, KswordArkBugcheckLayoutFrameDetailedMiddleStack);
    KswordARKBugcheckDetailedFrame(
        &writer, 666L, 311L, KswordArkBugcheckLayoutFrameDetailedMiddleModule);
    KswordARKBugcheckDetailedFrame(
        &writer, 948L, 311L, KswordArkBugcheckLayoutFrameDetailedMiddleBlackbox);
    KswordARKBugcheckDetailedFrame(
        &writer, 16L, 477L, KswordArkBugcheckLayoutFrameDetailedBottomCpu);
    KswordARKBugcheckDetailedFrame(
        &writer, 500L, 477L, KswordArkBugcheckLayoutFrameDetailedBottomDump);
    KswordARKBugcheckDetailedFrame(
        &writer, 852L, 477L, KswordArkBugcheckLayoutFrameDetailedBottomEvent);
    KswordARKBugcheckDetailedFrame(
        &writer, 852L, 579L, KswordArkBugcheckLayoutFrameDetailedBottomHelp);

    KswordARKBugcheckDetailedDrawHeader(&writer, Diagnostics, CallbackMask);
    KswordARKBugcheckDetailedDrawBugcheck(&writer, Diagnostics);
    KswordARKBugcheckDetailedDrawFaultContext(&writer, Diagnostics);
    KswordARKBugcheckDetailedDrawInstruction(&writer, Diagnostics);
    KswordARKBugcheckDetailedDrawThread(&writer, Diagnostics);
    KswordARKBugcheckDetailedDrawStack(&writer);
    KswordARKBugcheckDetailedDrawModule(&writer, Diagnostics);
    KswordARKBugcheckDetailedDrawBlackbox(&writer);
    KswordARKBugcheckDetailedDrawCpu(&writer, Diagnostics, moduleText);
    KswordARKBugcheckDetailedDrawDump(
        &writer,
        Diagnostics,
        CallbackMask,
        ModuleCount);
    KswordARKBugcheckDetailedDrawEvent(&writer, Diagnostics);
    KswordARKBugcheckDetailedDrawHelp(&writer);
    KswordARKBugcheckDetailedWrite(
        &writer, 16L, 700L, KswordArkBugcheckLayoutColorMuted, 72UL,
        "BLUE=CAPTURED  AMBER=DUMP ONLY  WAITING FOR WINDOWS DUMP COMPLETION");
    return writer.Status;
}
