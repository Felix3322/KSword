/*++

Module Name:

    hvm_nested_ept.c

Abstract:

    Tracks shadow-EPT inputs and invalidation without claiming incomplete
    two-dimensional page-table composition is active.

Environment:

    Kernel-mode Driver Framework.

--*/

#include "hvm_nested_ept.h"

VOID
KswordARKHvmNestedEptInitialize(
    _Out_ KSW_HVM_SHADOW_EPT_STATE* Shadow,
    _In_ ULONGLONG L0EptPointer
    )
{
    /* Reject a missing fixed shadow-EPT state. */
    if (Shadow == NULL) {
        /* Return without publishing partial state. */
        return;
    }
    /* Initialize every shadow-EPT identity and generation. */
    RtlZeroMemory(Shadow, sizeof(*Shadow));
    /* Preserve KSword's exact L0 EPT pointer. */
    Shadow->L0EptPointer = L0EptPointer;
    /* Publish explicit partial composition status. */
    Shadow->LastStatus = STATUS_NOT_IMPLEMENTED;
}

NTSTATUS
KswordARKHvmNestedEptSetL1Pointer(
    _Inout_ KSW_HVM_SHADOW_EPT_STATE* Shadow,
    _In_ ULONGLONG L1EptPointer
    )
{
    /* Require page alignment and nonzero L0/L1 EPT identities. */
    if (Shadow == NULL ||
        Shadow->L0EptPointer == 0ULL ||
        L1EptPointer == 0ULL ||
        (L1EptPointer &
            (KSW_HVM_PAGE_BYTES - 1ULL)) != 0ULL) {
        /* Return the exact EPT identity contract failure. */
        return STATUS_INVALID_PARAMETER;
    }
    /* Preserve the exact L1-provided EPT pointer. */
    Shadow->L1EptPointer = L1EptPointer;
    /* Publish a validated L1 EPT identity. */
    Shadow->L1PointerValid = TRUE;
    /* Advance the partial shadow-EPT generation. */
    Shadow->Generation += 1UL;
    /* Clear any stale composed EPT identity. */
    Shadow->ComposedEptPointer = 0ULL;
    /* Preserve explicit inactive state. */
    Shadow->Active = FALSE;
    /* Publish explicit partial composition status. */
    Shadow->LastStatus = STATUS_NOT_IMPLEMENTED;
    /* Return partial status without claiming composition is active. */
    return Shadow->LastStatus;
}

VOID
KswordARKHvmNestedEptInvalidate(
    _Inout_ KSW_HVM_SHADOW_EPT_STATE* Shadow
    )
{
    /* Reject a missing fixed shadow-EPT state. */
    if (Shadow == NULL) {
        /* Return without publishing partial state. */
        return;
    }
    /* Advance the invalidation generation monotonically. */
    Shadow->InvalidationGeneration += 1UL;
    /* Clear every stale composed EPT identity. */
    Shadow->ComposedEptPointer = 0ULL;
    /* Preserve explicit inactive state. */
    Shadow->Active = FALSE;
    /* Publish explicit partial composition status. */
    Shadow->LastStatus = STATUS_NOT_IMPLEMENTED;
}
