#pragma once

#include <ntddk.h>
#include <wdf.h>

#include "driver/KswordArkBugcheckIoctl.h"

EXTERN_C_START

// Temporary fail-closed build gate for the complete driver-side blue screen
// diagnostic path. This does not affect the rest of the driver or user-mode UI.
#define KSWORD_ARK_BUGCHECK_DIAGNOSTICS_ENABLED 0

// Resolve the physical-machine BGP backend, prepare every crash-time rectangle
// at PASSIVE_LEVEL, and register dump-preserving bugcheck callbacks. Missing
// private features leave the renderer fail-closed without blocking diagnostics.
NTSTATUS
KswordARKBugcheckInitialize(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ WDFDEVICE ControlDevice
    );

// Deregister callbacks before destroying the prebuilt BGP rectangles.
VOID
KswordARKBugcheckUninitialize(
    VOID
    );

// Feed the crash-safe process/module identity caches from the driver's existing
// notify callbacks. Writers run before a crash; the bugcheck path only reads
// fixed nonpaged snapshots and never dereferences an arbitrary crash parameter.
VOID
KswordARKBugcheckTrackProcess(
    _In_ PEPROCESS Process,
    _In_ HANDLE ProcessId,
    _Inout_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo
    );

VOID
KswordARKBugcheckTrackLoadedImage(
    _In_opt_ PUNICODE_STRING FullImageName,
    _In_ HANDLE ProcessId,
    _In_ PIMAGE_INFO ImageInfo
    );

// Optional bitmap upload adapter registered through ioctl_registry.c.
NTSTATUS
KswordARKBugcheckIoctlSetBitmap(
    _In_ WDFDEVICE Device,
    _In_ WDFREQUEST Request,
    _In_ size_t InputBufferLength,
    _In_ size_t OutputBufferLength,
    _Out_ size_t* BytesReturned
    );

NTSTATUS
KswordARKBugcheckIoctlSetVerdictResources(
    _In_ WDFDEVICE Device,
    _In_ WDFREQUEST Request,
    _In_ size_t InputBufferLength,
    _In_ size_t OutputBufferLength,
    _Out_ size_t* BytesReturned
    );


// Initialize and tear down the independent one-shot BugCheck delay guard.
// HVCI systems use a delay-only callback; other systems may use the exported
// KeBugCheckEx entry hook and must restore it before driver unload. The guard
// is intentionally not coupled to the optional VMware panel.
VOID
KswordARKBugcheckGuardInitialize(
    VOID
    );

VOID
KswordARKBugcheckGuardUninitialize(
    VOID
    );

NTSTATUS
KswordARKBugcheckGuardIoctlConfigure(
    _In_ WDFDEVICE Device,
    _In_ WDFREQUEST Request,
    _In_ size_t InputBufferLength,
    _In_ size_t OutputBufferLength,
    _Out_ size_t* BytesReturned
    );
EXTERN_C_END

