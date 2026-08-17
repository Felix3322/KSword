#pragma once

#include <ntddk.h>

typedef struct _KSWORD_ARK_BUGCHECK_DIAGNOSTICS
    KSWORD_ARK_BUGCHECK_DIAGNOSTICS;
typedef KSWORD_ARK_BUGCHECK_DIAGNOSTICS*
    PKSWORD_ARK_BUGCHECK_DIAGNOSTICS;

NTSTATUS
KswordARKBugcheckPanelInitialize(
    VOID
    );

VOID
KswordARKBugcheckPanelShutdown(
    VOID
    );

NTSTATUS
KswordARKBugcheckPanelInstallVerdictResources(
    _In_reads_bytes_(PacketLength) const VOID* Packet,
    _In_ ULONG PacketLength
    );

NTSTATUS
KswordARKBugcheckPanelDraw(
    _In_ const KSWORD_ARK_BUGCHECK_DIAGNOSTICS* Diagnostics,
    _In_ ULONG CallbackMask,
    _In_ ULONG ModuleCount
    );
