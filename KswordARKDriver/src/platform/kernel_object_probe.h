#pragma once

#include <ntddk.h>

EXTERN_C_START

BOOLEAN
KswordARKKernelProbeResourceIsSystemResource(
    _In_ ULONG_PTR Address
    );

BOOLEAN
KswordARKKernelProbeListHeadIsSane(
    _In_ ULONG_PTR ListHeadAddress
    );

EXTERN_C_END
