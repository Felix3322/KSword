#pragma once

#include "callback_internal.h"

EXTERN_C_START

VOID
KswordArkCallbackExtendedAddSelfBugcheckCallbacks(
    _Inout_ KSWORD_ARK_CALLBACK_ENUM_BUILDER* Builder
    );

VOID
KswordArkCallbackExtendedAddBugcheckCallbacks(
    _Inout_ KSWORD_ARK_CALLBACK_ENUM_BUILDER* Builder
    );

VOID
KswordArkCallbackExtendedAddObjectCallbacks(
    _Inout_ KSWORD_ARK_CALLBACK_ENUM_BUILDER* Builder
    );

VOID
KswordArkCallbackExtendedAddSystemCallbacks(
    _Inout_ KSWORD_ARK_CALLBACK_ENUM_BUILDER* Builder
    );

VOID
KswordArkCallbackExtendedAddNmiCallbacks(
    _Inout_ KSWORD_ARK_CALLBACK_ENUM_BUILDER* Builder
    );

EXTERN_C_END
