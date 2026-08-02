#pragma once

#include <ntifs.h>

EXTERN_C_START

LONG
KswordARKDriverResolveProcessTokenOffset(
    _In_ PEPROCESS Process,
    _In_ PACCESS_TOKEN Token
    );

VOID
KswordARKDriverResolveTokenLayoutOffsets(
    _In_ PACCESS_TOKEN Token,
    _Out_ LONG* UserAndGroupCountOffsetOut,
    _Out_ LONG* UserAndGroupsOffsetOut,
    _Out_ LONG* IntegrityLevelIndexOffsetOut,
    _Out_ LONG* MandatoryPolicyOffsetOut
    );

EXTERN_C_END
