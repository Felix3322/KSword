#pragma once

#include "dyndata_fallback_resolver.h"

EXTERN_C_START

VOID
KswordARKDriverResolveKernelCacheFallback(
    _In_ const KSW_DYN_MODULE_IDENTITY_PACKET* NtoskrnlIdentity,
    _Inout_ PKSW_RUNTIME_KERNEL_LAYOUT Layout
    );

EXTERN_C_END
