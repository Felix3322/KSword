/*++

Module Name:

    kernel_object_probe.c

Abstract:

    Identity probes for kernel objects recovered by heuristic scanning.  Shape
    checks over a candidate's fields can never prove what the candidate is:
    every self-consistent LIST_ENTRY inside a writable image section looks like
    an ERESOURCE, and passing a non-resource to the Ex resource API bugchecks
    immediately.  The probes here establish identity from properties the object
    cannot fake, using bounded fault-tolerant reads only.

Environment:

    Kernel mode, PASSIVE_LEVEL.

--*/

#include <ntifs.h>
#include "kernel_object_probe.h"
#include "runtime_signature_scan.h"

#define KSW_KERNEL_PROBE_MAX_RESOURCE_LIST_STEPS 0x40000UL

static BOOLEAN
KswordARKKernelProbeIsKernelPointer(
    _In_ ULONG_PTR Address
    )
{
#if defined(_M_AMD64) || defined(_M_X64)
    return Address >= (ULONG_PTR)MmSystemRangeStart &&
        (Address >> 48U) == 0xFFFFU;
#else
    return Address >= (ULONG_PTR)MmSystemRangeStart;
#endif
}

BOOLEAN
KswordARKKernelProbeResourceIsSystemResource(
    _In_ ULONG_PTR Address
    )
/*++

Routine Description:

    Prove that a candidate address really is a live ERESOURCE before any Ex
    resource API touches it.  ExInitializeResourceLite links every resource
    onto one global list, so a driver-owned resource supplies an anchor and no
    ntoskrnl global has to be guessed.  The walk uses bounded fault-tolerant
    reads and gives up rather than trusting a torn or hostile link.

Arguments:

    Address - Candidate ERESOURCE address; SystemResourcesList sits at zero
        offset, so the list node and the resource share this address.

Return Value:

    TRUE only when the candidate is present on the global resource list.

--*/
{
    ERESOURCE anchor;
    LIST_ENTRY node;
    ULONG_PTR anchorHead = 0U;
    ULONG_PTR current = 0U;
    ULONG steps = 0UL;
    BOOLEAN found = FALSE;

    if (Address == 0U || (Address & (sizeof(PVOID) - 1U)) != 0U ||
        !KswordARKKernelProbeIsKernelPointer(Address) ||
        KeGetCurrentIrql() != PASSIVE_LEVEL) {
        return FALSE;
    }
    RtlZeroMemory(&anchor, sizeof(anchor));
    if (!NT_SUCCESS(ExInitializeResourceLite(&anchor))) {
        return FALSE;
    }
    anchorHead = (ULONG_PTR)&anchor.SystemResourcesList;
    current = (ULONG_PTR)anchor.SystemResourcesList.Flink;
    for (steps = 0UL;
         steps < KSW_KERNEL_PROBE_MAX_RESOURCE_LIST_STEPS;
         ++steps) {
        if (current == anchorHead) {
            break;
        }
        if (current == Address) {
            found = TRUE;
            break;
        }
        if ((current & (sizeof(PVOID) - 1U)) != 0U ||
            !KswordARKKernelProbeIsKernelPointer(current)) {
            break;
        }
        RtlZeroMemory(&node, sizeof(node));
        if (!KswordARKRuntimeReadMemory((const VOID*)current, &node, sizeof(node))) {
            break;
        }
        current = (ULONG_PTR)node.Flink;
    }
    ExDeleteResourceLite(&anchor);
    return found;
}

BOOLEAN
KswordARKKernelProbeRangeIsResident(
    _In_opt_ const volatile VOID* Address,
    _In_ SIZE_T Size
    )
/*++

Routine Description:

    Confirm that every page of a kernel range is resident.  Callers use this
    when IRQL is already at DISPATCH_LEVEL, where MmCopyMemory is unavailable
    and a fault would bugcheck rather than raise.  Probing only the first and
    last byte is not equivalent: a range spanning three or more pages can have
    a non-resident page in the middle, and an unaligned range shorter than a
    pointer can still straddle a page boundary.

Arguments:

    Address - Range start.
    Size - Range length in bytes.

Return Value:

    TRUE when the whole range is resident and safe to dereference.

--*/
{
    ULONG_PTR current = (ULONG_PTR)Address;
    ULONG_PTR end = 0U;

    if (Address == NULL || Size == 0U ||
        !KswordARKKernelProbeIsKernelPointer(current) ||
        current > MAXULONG_PTR - Size) {
        return FALSE;
    }
    end = current + Size - 1U;
    for (;;) {
        if (!MmIsAddressValid((PVOID)current)) {
            return FALSE;
        }
        if ((current & ~(ULONG_PTR)(PAGE_SIZE - 1U)) ==
            (end & ~(ULONG_PTR)(PAGE_SIZE - 1U))) {
            break;
        }
        current = (current & ~(ULONG_PTR)(PAGE_SIZE - 1U)) + PAGE_SIZE;
    }
    return TRUE;
}

BOOLEAN
KswordARKKernelProbeListHeadIsSane(
    _In_ ULONG_PTR ListHeadAddress
    )
/*++

Routine Description:

    Validate a list head and its immediate neighbours through fault-tolerant
    reads.  Callers use this before raising IRQL, because once a spin lock is
    held neither MmCopyMemory nor structured exception handling can contain an
    invalid kernel dereference.

Return Value:

    TRUE when the head and both neighbours link back consistently.

--*/
{
    LIST_ENTRY head;
    LIST_ENTRY forward;
    LIST_ENTRY backward;

    if (ListHeadAddress == 0U ||
        (ListHeadAddress & (sizeof(PVOID) - 1U)) != 0U ||
        !KswordARKKernelProbeIsKernelPointer(ListHeadAddress)) {
        return FALSE;
    }
    RtlZeroMemory(&head, sizeof(head));
    RtlZeroMemory(&forward, sizeof(forward));
    RtlZeroMemory(&backward, sizeof(backward));
    if (!KswordARKRuntimeReadMemory(
            (const VOID*)ListHeadAddress,
            &head,
            sizeof(head)) ||
        !KswordARKKernelProbeIsKernelPointer((ULONG_PTR)head.Flink) ||
        !KswordARKKernelProbeIsKernelPointer((ULONG_PTR)head.Blink) ||
        (((ULONG_PTR)head.Flink | (ULONG_PTR)head.Blink) &
         (sizeof(PVOID) - 1U)) != 0U ||
        !KswordARKRuntimeReadMemory(head.Flink, &forward, sizeof(forward)) ||
        !KswordARKRuntimeReadMemory(head.Blink, &backward, sizeof(backward)) ||
        forward.Blink != (PLIST_ENTRY)ListHeadAddress ||
        backward.Flink != (PLIST_ENTRY)ListHeadAddress) {
        return FALSE;
    }
    return TRUE;
}
