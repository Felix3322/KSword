#pragma once

#include "ark/ark_dyndata.h"

EXTERN_C_START

LONG
KswordARKDriverResolveShadowSsdtRva(
    _In_ const KSW_DYN_MODULE_IDENTITY_PACKET* NtoskrnlIdentity
    );

EXTERN_C_END
