/*++

Module Name:

    bugcheck_bgp_lifecycle.c

Abstract:

    PASSIVE_LEVEL lifecycle, bitmap parsing, arming, and secondary-dump
    snapshot support for the physical BGP renderer.

--*/

#include "bugcheck_bgp.h"
#include "bugcheck_bgp_internal.h"

NTSTATUS
KswordARKBugcheckBgpInitialize(
    VOID
    )
{
    KSWORD_ARK_BGP_SCREEN_INFO screen;
    NTSTATUS status;

    if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
        return STATUS_INVALID_DEVICE_STATE;
    }

    RtlZeroMemory(&g_KswordArkBgp, sizeof(g_KswordArkBgp));
    InterlockedExchange(
        &g_KswordArkBgp.State,
        KswordArkBgpStateUninitialized);
    InterlockedExchange(&g_KswordArkBgp.ClearStatus, STATUS_PENDING);
    InterlockedExchange(&g_KswordArkBgp.DrawStatus, STATUS_PENDING);

    status = KswordARKBugcheckBgpResolveFunctions();
    InterlockedExchange(&g_KswordArkBgp.LastStatus, (LONG)status);
    if (NT_SUCCESS(status)) {
        status = KswordARKBugcheckBgpReadScreen(&screen);
        InterlockedExchange(&g_KswordArkBgp.LastStatus, (LONG)status);
        if (NT_SUCCESS(status)) {
            g_KswordArkBgp.Screen = screen;
        }
    }

    if (!NT_SUCCESS(status)) {
        InterlockedExchange(
            &g_KswordArkBgp.State,
            KswordArkBgpStateQueryOnly);
        return status;
    }

    InterlockedExchange(&g_KswordArkBgp.State, KswordArkBgpStateReady);
    return STATUS_SUCCESS;
}

VOID
KswordARKBugcheckBgpShutdown(
    VOID
    )
{
    InterlockedExchange(&g_KswordArkBgp.State, KswordArkBgpStateUnloading);
    if (InterlockedExchange(&g_KswordArkBgp.LockHeld, 0) != 0 &&
        g_KswordArkBgp.Release != NULL) {
        g_KswordArkBgp.Release();
    }
    g_KswordArkBgp.RequiredWidth = 0;
    g_KswordArkBgp.RequiredHeight = 0;
}

NTSTATUS
KswordARKBugcheckBgpGetScreenInfo(
    _Out_ PKSWORD_ARK_BGP_SCREEN_INFO Screen
    )
{
    if (Screen == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    if (InterlockedCompareExchange(
            &g_KswordArkBgp.State,
            0,
            0) != KswordArkBgpStateReady) {
        RtlZeroMemory(Screen, sizeof(*Screen));
        return STATUS_DEVICE_NOT_READY;
    }

    *Screen = g_KswordArkBgp.Screen;
    return STATUS_SUCCESS;
}

NTSTATUS
KswordARKBugcheckBgpParseBitmap(
    _In_reads_bytes_(BitmapLength) const VOID* Bitmap,
    _In_ ULONG BitmapLength,
    _Out_ PVOID* Rectangle
    )
{
    PVOID parsedRectangle;
    NTSTATUS status;

    if (Rectangle == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *Rectangle = NULL;
    if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
        return STATUS_INVALID_DEVICE_STATE;
    }
    if (InterlockedCompareExchange(
            &g_KswordArkBgp.State,
            0,
            0) != KswordArkBgpStateReady ||
        g_KswordArkBgp.ParseBitmap == NULL) {
        return STATUS_DEVICE_NOT_READY;
    }

    status = KswordARKBugcheckBgpValidateBitmap(Bitmap, BitmapLength);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    parsedRectangle = NULL;
    status = g_KswordArkBgp.ParseBitmap(Bitmap, &parsedRectangle);
    if (!NT_SUCCESS(status) || parsedRectangle == NULL) {
        return NT_SUCCESS(status) ? STATUS_UNSUCCESSFUL : status;
    }

    *Rectangle = parsedRectangle;
    return STATUS_SUCCESS;
}

VOID
KswordARKBugcheckBgpDestroyRectangle(
    _In_opt_ PVOID Rectangle
    )
{
    if (Rectangle != NULL && g_KswordArkBgp.DestroyRectangle != NULL) {
        (VOID)g_KswordArkBgp.DestroyRectangle(Rectangle);
    }
}

NTSTATUS
KswordARKBugcheckBgpArm(
    _In_ ULONG RequiredWidth,
    _In_ ULONG RequiredHeight
    )
{
    if (InterlockedCompareExchange(
            &g_KswordArkBgp.State,
            0,
            0) != KswordArkBgpStateReady ||
        RequiredWidth == 0 ||
        RequiredHeight == 0 ||
        RequiredWidth > g_KswordArkBgp.Screen.Width ||
        RequiredHeight > g_KswordArkBgp.Screen.Height) {
        return STATUS_NOT_SUPPORTED;
    }

    g_KswordArkBgp.RequiredWidth = RequiredWidth;
    g_KswordArkBgp.RequiredHeight = RequiredHeight;
    InterlockedExchange(&g_KswordArkBgp.DrawStarted, 0);
    InterlockedExchange(&g_KswordArkBgp.DrawStageStarted, 0);
    InterlockedExchange(&g_KswordArkBgp.Stage, KswordArkBgpStageIdle);
    InterlockedExchange(&g_KswordArkBgp.ClearStatus, STATUS_PENDING);
    InterlockedExchange(&g_KswordArkBgp.DrawStatus, STATUS_PENDING);
    InterlockedExchange(&g_KswordArkBgp.TimelineCount, 0);
    RtlZeroMemory(g_KswordArkBgp.Timeline, sizeof(g_KswordArkBgp.Timeline));
    InterlockedExchange(&g_KswordArkBgp.LastStatus, STATUS_SUCCESS);
    InterlockedExchange(&g_KswordArkBgp.State, KswordArkBgpStateArmed);
    return STATUS_SUCCESS;
}

VOID
KswordARKBugcheckBgpRejectPreparation(
    _In_ NTSTATUS Status
    )
{
    InterlockedExchange(&g_KswordArkBgp.LastStatus, (LONG)Status);
    InterlockedExchange(&g_KswordArkBgp.State, KswordArkBgpStateRejected);
    KswordARKBugcheckBgpRecordStage(
        (LONG)(KswordArkBgpStageRejected | 3UL),
        Status);
}
VOID
KswordARKBugcheckBgpSnapshot(
    _Out_ PKSWORD_ARK_BGP_DUMP_STATE Snapshot
    )
{
    LONG timelineCount;
    ULONG timelineIndex;

    if (Snapshot == NULL) {
        return;
    }

    RtlZeroMemory(Snapshot, sizeof(*Snapshot));
    Snapshot->Version = 1UL;
    Snapshot->Size = sizeof(*Snapshot);
    Snapshot->State = (ULONG)InterlockedCompareExchange(
        &g_KswordArkBgp.State,
        0,
        0);
    Snapshot->Stage = (ULONG)InterlockedCompareExchange(
        &g_KswordArkBgp.Stage,
        0,
        0);
    Snapshot->LastStatus = (ULONG)InterlockedCompareExchange(
        &g_KswordArkBgp.LastStatus,
        0,
        0);
    Snapshot->ClearStatus = (ULONG)InterlockedCompareExchange(
        &g_KswordArkBgp.ClearStatus,
        0,
        0);
    Snapshot->DrawStatus = (ULONG)InterlockedCompareExchange(
        &g_KswordArkBgp.DrawStatus,
        0,
        0);
    Snapshot->FeatureMask = g_KswordArkBgp.FeatureMask;
    Snapshot->ScreenWidth = g_KswordArkBgp.Screen.Width;
    Snapshot->ScreenHeight = g_KswordArkBgp.Screen.Height;
    Snapshot->ScreenBpp = g_KswordArkBgp.Screen.BitsPerPixel;
    Snapshot->RequiredWidth = g_KswordArkBgp.RequiredWidth;
    Snapshot->RequiredHeight = g_KswordArkBgp.RequiredHeight;
    Snapshot->DrawCount = (ULONG64)InterlockedCompareExchange64(
        &g_KswordArkBgp.DrawCount,
        0,
        0);
    RtlCopyMemory(
        Snapshot->SignatureFamily,
        g_KswordArkBgp.SignatureFamily,
        sizeof(Snapshot->SignatureFamily));

    timelineCount = InterlockedCompareExchange(
        &g_KswordArkBgp.TimelineCount,
        0,
        0);
    if (timelineCount < 0) {
        timelineCount = 0;
    }
    Snapshot->TimelineCount = min(
        (ULONG)timelineCount,
        (ULONG)RTL_NUMBER_OF(Snapshot->Timeline));
    for (timelineIndex = 0;
         timelineIndex < Snapshot->TimelineCount;
         ++timelineIndex) {
        Snapshot->Timeline[timelineIndex].Stage =
            (ULONG)InterlockedCompareExchange(
                &g_KswordArkBgp.Timeline[timelineIndex].Stage,
                0,
                0);
        Snapshot->Timeline[timelineIndex].Status =
            (ULONG)InterlockedCompareExchange(
                &g_KswordArkBgp.Timeline[timelineIndex].Status,
                0,
                0);
    }
}
