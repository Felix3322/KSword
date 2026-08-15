#pragma once

#include <ntddk.h>

// Write the completed PASSIVE_LEVEL BGP preparation state to a fixed text
// report under the Windows temporary directory. No bugcheck callback calls it.
NTSTATUS
KswordARKBugcheckWritePreparationLog(
    _In_ NTSTATUS BgpInitializeStatus,
    _In_ NTSTATUS PanelInitializeStatus,
    _In_ NTSTATUS CallbackRegistrationStatus
    );
