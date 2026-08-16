#pragma once

#include "bugcheck_layout.h"

NTSTATUS
KswordARKBugcheckLayoutDrawDetailed(
    _In_ const KSWORD_ARK_BUGCHECK_LAYOUT_CANVAS* Canvas,
    _In_ const KSWORD_ARK_BUGCHECK_DIAGNOSTICS* Diagnostics,
    _In_ ULONG CallbackMask,
    _In_ ULONG ModuleCount
    );
