/*++

Module Name:

    hvm_nested_ept.h

Abstract:

    Defines fail-closed L1-on-L0 shadow-EPT composition state.

Environment:

    Kernel-mode Driver Framework.

--*/

#pragma once

#include "hvm_internal.h"

/* Preserve nested EPT identities and invalidation generations. */
typedef struct _KSW_HVM_SHADOW_EPT_STATE
{
    /* Record whether L1 supplied an EPT pointer. */
    BOOLEAN L1PointerValid;
    /* Record whether one composed shadow hierarchy is active. */
    BOOLEAN Active;
    /* Keep the structure explicitly initialized across architectures. */
    USHORT Reserved0;
    /* Preserve the shadow-EPT generation. */
    ULONG Generation;
    /* Preserve the last invalidated generation. */
    ULONG InvalidationGeneration;
    /* Preserve the L1-provided EPT pointer. */
    ULONGLONG L1EptPointer;
    /* Preserve KSword's L0 EPT pointer. */
    ULONGLONG L0EptPointer;
    /* Preserve a complete composed EPT pointer only when active. */
    ULONGLONG ComposedEptPointer;
    /* Preserve the last composition status. */
    NTSTATUS LastStatus;
    /* Keep explicit padding initialized for crash-dump inspection. */
    ULONG Reserved1;
} KSW_HVM_SHADOW_EPT_STATE;

EXTERN_C_START

/* Initialize explicit inactive shadow-EPT state. */
VOID
KswordARKHvmNestedEptInitialize(
    _Out_ KSW_HVM_SHADOW_EPT_STATE* Shadow,
    _In_ ULONGLONG L0EptPointer
    );

/* Record an L1 EPT pointer without claiming composition is active. */
NTSTATUS
KswordARKHvmNestedEptSetL1Pointer(
    _Inout_ KSW_HVM_SHADOW_EPT_STATE* Shadow,
    _In_ ULONGLONG L1EptPointer
    );

/* Invalidate all partial shadow state for one L1 request. */
VOID
KswordARKHvmNestedEptInvalidate(
    _Inout_ KSW_HVM_SHADOW_EPT_STATE* Shadow
    );

EXTERN_C_END
