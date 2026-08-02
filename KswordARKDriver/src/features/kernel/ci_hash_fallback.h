#pragma once

#include "../dyndata/dyndata_v4_internal.h"

EXTERN_C_START

NTSTATUS
KswordARKCiHashResolveRuntimeLayout(
    _Out_ KSW_DYN_V4_CI_KERNEL_HASH_LAYOUT* LayoutOut
    );

EXTERN_C_END
