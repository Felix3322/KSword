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

BOOLEAN
KswordARKKernelProbeRangeIsResident(
    _In_opt_ const volatile VOID* Address,
    _In_ SIZE_T Size
    );

EXTERN_C_END
