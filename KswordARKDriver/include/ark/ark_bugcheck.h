#pragma once

#include <ntddk.h>
#include <wdf.h>

#include "driver/KswordArkBugcheckIoctl.h"

EXTERN_C_START

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

// Optional bitmap upload adapter registered through ioctl_registry.c.
NTSTATUS
KswordARKBugcheckIoctlSetBitmap(
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

