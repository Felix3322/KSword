#pragma once

#include <ntddk.h>

#define KSWORD_ARK_BGP_FEATURE_CLEAR       0x00000001UL
#define KSWORD_ARK_BGP_FEATURE_DRAW        0x00000002UL
#define KSWORD_ARK_BGP_FEATURE_ACQUIRE     0x00000004UL
#define KSWORD_ARK_BGP_FEATURE_RELEASE     0x00000008UL
#define KSWORD_ARK_BGP_FEATURE_RESOLUTION  0x00000010UL
#define KSWORD_ARK_BGP_FEATURE_BPP         0x00000020UL
#define KSWORD_ARK_BGP_FEATURE_PARSE       0x00000040UL
#define KSWORD_ARK_BGP_FEATURE_DESTROY     0x00000080UL
#define KSWORD_ARK_BGP_FEATURE_INBV        0x00000100UL
#define KSWORD_ARK_BGP_UNOWNED_BPP         1UL

#define KSWORD_ARK_BGP_SIGNATURE_COUNT 8UL
#define KSWORD_ARK_BGP_TIMELINE_COUNT 16UL

typedef enum _KSWORD_ARK_BGP_STATE
{
    KswordArkBgpStateUninitialized = 0,
    KswordArkBgpStateQueryOnly,
    KswordArkBgpStateReady,
    KswordArkBgpStateArmed,
    KswordArkBgpStateDrawn,
    KswordArkBgpStateRejected,
    KswordArkBgpStateUnloading
} KSWORD_ARK_BGP_STATE;

typedef enum _KSWORD_ARK_BGP_STAGE
{
    KswordArkBgpStageIdle = 0,
    KswordArkBgpStageCallbackEntered = 0x0100,
    KswordArkBgpStageOwnershipBefore = 0x0200,
    KswordArkBgpStageOwnershipAfter = 0x0201,
    KswordArkBgpStageAcquireBefore = 0x0300,
    KswordArkBgpStageAcquireAfter = 0x0301,
    KswordArkBgpStageScreenBefore = 0x0350,
    KswordArkBgpStageScreenAfter = 0x0351,
    KswordArkBgpStageClearBefore = 0x0400,
    KswordArkBgpStageClearAfter = 0x0401,
    KswordArkBgpStageDrawBefore = 0x0500,
    KswordArkBgpStageDrawAfter = 0x0501,
    KswordArkBgpStageReleaseBefore = 0x0600,
    KswordArkBgpStageReleaseAfter = 0x0601,
    KswordArkBgpStageComplete = 0x0700,
    KswordArkBgpStageRejected = 0x80000000UL
} KSWORD_ARK_BGP_STAGE;

// These values identify the exact PASSIVE_LEVEL preparation operation that
// most recently ran, so a load-time report can distinguish resolver, display,
// bitmap, glyph, and arming failures without doing file I/O during a bugcheck.
typedef enum _KSWORD_ARK_BGP_PREPARATION_STAGE
{
    KswordArkBgpPreparationIdle = 0,
    KswordArkBgpPreparationResolveFunctions,
    KswordArkBgpPreparationReadScreen,
    KswordArkBgpPreparationBackendReady,
    KswordArkBgpPreparationValidatePanelScreen,
    KswordArkBgpPreparationPrepareLogo,
    KswordArkBgpPreparationPrepareGlyphs,
    KswordArkBgpPreparationArm,
    KswordArkBgpPreparationComplete
} KSWORD_ARK_BGP_PREPARATION_STAGE;

typedef struct _KSWORD_ARK_BGP_SCREEN_INFO
{
    ULONG Width;
    ULONG Height;
    ULONG BitsPerPixel;
    ULONG Reserved;
} KSWORD_ARK_BGP_SCREEN_INFO, *PKSWORD_ARK_BGP_SCREEN_INFO;

typedef struct _KSWORD_ARK_BGP_TIMELINE_ENTRY
{
    ULONG Stage;
    ULONG Status;
} KSWORD_ARK_BGP_TIMELINE_ENTRY, *PKSWORD_ARK_BGP_TIMELINE_ENTRY;

typedef struct _KSWORD_ARK_BGP_DUMP_STATE
{
    ULONG Version;
    ULONG Size;
    ULONG State;
    ULONG PreparationStage;
    ULONG PreparationStatus;
    ULONG Stage;
    ULONG LastStatus;
    ULONG ClearStatus;
    ULONG DrawStatus;
    ULONG FeatureMask;
    ULONG ScreenWidth;
    ULONG ScreenHeight;
    ULONG ScreenBpp;
    ULONG RequiredWidth;
    ULONG RequiredHeight;
    ULONG64 DrawCount;
    ULONG SignatureFamily[KSWORD_ARK_BGP_SIGNATURE_COUNT];
    ULONG TimelineCount;
    KSWORD_ARK_BGP_TIMELINE_ENTRY Timeline[KSWORD_ARK_BGP_TIMELINE_COUNT];
} KSWORD_ARK_BGP_DUMP_STATE, *PKSWORD_ARK_BGP_DUMP_STATE;

NTSTATUS
KswordARKBugcheckBgpInitialize(
    VOID
    );

VOID
KswordARKBugcheckBgpShutdown(
    VOID
    );

NTSTATUS
KswordARKBugcheckBgpGetScreenInfo(
    _Out_ PKSWORD_ARK_BGP_SCREEN_INFO Screen
    );

NTSTATUS
KswordARKBugcheckBgpParseBitmap(
    _In_reads_bytes_(BitmapLength) const VOID* Bitmap,
    _In_ ULONG BitmapLength,
    _Out_ PVOID* Rectangle
    );

VOID
KswordARKBugcheckBgpDestroyRectangle(
    _In_opt_ PVOID Rectangle
    );

NTSTATUS
KswordARKBugcheckBgpArm(
    _In_ ULONG RequiredWidth,
    _In_ ULONG RequiredHeight
    );

VOID
KswordARKBugcheckBgpRejectPreparation(
    _In_ NTSTATUS Status
    );

// Record one load-time preparation operation in nonpaged BGP state. The
// caller supplies the operation and its current or final NTSTATUS value.
VOID
KswordARKBugcheckBgpRecordPreparation(
    _In_ KSWORD_ARK_BGP_PREPARATION_STAGE Stage,
    _In_ NTSTATUS Status
    );

// Return the latest BGP BPP value cached by the crash-time screen probe.
// The caller uses it only after display ownership has been acquired.
ULONG
KswordARKBugcheckBgpGetCurrentBpp(
    VOID
    );

NTSTATUS
KswordARKBugcheckBgpBeginDraw(
    VOID
    );

NTSTATUS
KswordARKBugcheckBgpClearScreen(
    _In_ ULONG ArgbColor
    );

NTSTATUS
KswordARKBugcheckBgpDrawRectangle(
    _In_ PVOID Rectangle,
    _In_ LONG X,
    _In_ LONG Y
    );

VOID
KswordARKBugcheckBgpFinishDraw(
    _In_ NTSTATUS DrawStatus
    );

VOID
KswordARKBugcheckBgpSnapshot(
    _Out_ PKSWORD_ARK_BGP_DUMP_STATE Snapshot
    );
