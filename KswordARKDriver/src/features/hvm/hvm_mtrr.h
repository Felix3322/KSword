/*++

Module Name:

    hvm_mtrr.h

Abstract:

    Captures Intel MTRR state and resolves conservative EPT memory types.

Environment:

    Kernel-mode Driver Framework.

--*/

#pragma once

#include "hvm_internal.h"

EXTERN_C_START

/* Capture one immutable MTRR snapshot on the preparing processor. */
NTSTATUS
KswordARKHvmMtrrCapture(
    _Out_ KSW_HVM_MTRR_STATE* State
    );

/* Resolve one range to a uniform EPT memory type or conservative UC. */
UCHAR
KswordARKHvmMtrrResolveRangeType(
    _In_ const KSW_HVM_MTRR_STATE* State,
    _In_ ULONGLONG PhysicalAddress,
    _In_ ULONGLONG ByteCount
    );

EXTERN_C_END
