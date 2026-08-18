#pragma once

#include "bugcheck_internal.h"

// Decode only stop-code parameters that Microsoft documents as a direct
// instruction/module address. Object pointers, reserved fields, and subtype-
// dependent data must not be promoted into a faulting-module claim.
BOOLEAN
KswordARKBugcheckDecodePrimaryAddress(
    _Inout_ PKSWORD_ARK_BUGCHECK_DIAGNOSTICS Diagnostics,
    _Out_ PULONG_PTR Address,
    _Out_ PULONG ParameterIndex,
    _Out_ PULONG Confidence
    );

// Return the documented semantic role of one raw stop-code parameter.  The
// returned labels are deliberately short enough for the crash-safe panel.
PCSTR
KswordARKBugcheckDecodeParameterRole(
    _In_ const KSWORD_ARK_BUGCHECK_DIAGNOSTICS* Diagnostics,
    _In_ ULONG ParameterIndex
    );
