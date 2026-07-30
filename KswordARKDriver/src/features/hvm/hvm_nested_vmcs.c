/*++

Module Name:

    hvm_nested_vmcs.c

Abstract:

    Implements bounded vmcs12 field storage and fail-closed vmcs02 validation.

Environment:

    Kernel-mode Driver Framework.

--*/

#include "hvm_nested_vmcs.h"

/* Name Intel VM-entry invalid-control-fields error seven. */
#define KSW_HVM_VMX_ERROR_INVALID_CONTROL_FIELDS 7UL

VOID
KswordARKHvmNestedVmcsInitialize(
    _Out_ KSW_HVM_VMCS12_STATE* Vmcs12,
    _Out_ KSW_HVM_VMCS02_STATE* Vmcs02
    )
{
    /* Initialize a supplied vmcs12 state. */
    if (Vmcs12 != NULL) {
        /* Clear every bounded vmcs12 field and identity. */
        RtlZeroMemory(Vmcs12, sizeof(*Vmcs12));
    }
    /* Initialize a supplied vmcs02 merge state. */
    if (Vmcs02 != NULL) {
        /* Clear every merge and active-state marker. */
        RtlZeroMemory(Vmcs02, sizeof(*Vmcs02));
        /* Publish explicit partial implementation status. */
        Vmcs02->LastStatus = STATUS_NOT_IMPLEMENTED;
    }
}

NTSTATUS
KswordARKHvmNestedVmcs12Write(
    _Inout_ KSW_HVM_VMCS12_STATE* Vmcs12,
    _In_ ULONG Encoding,
    _In_ ULONGLONG Value
    )
{
    ULONG index = 0UL;
    KSW_HVM_VMCS12_FIELD* freeSlot = NULL;

    /* Require one current vmcs12 and a nonzero field encoding. */
    if (Vmcs12 == NULL ||
        !Vmcs12->Current ||
        Encoding == 0UL) {
        /* Return the exact nested-state contract failure. */
        return STATUS_INVALID_DEVICE_STATE;
    }
    /* Replace an existing field or retain the first free slot. */
    for (index = 0UL;
         index < KSW_HVM_VMCS12_FIELD_CAPACITY;
         ++index) {
        KSW_HVM_VMCS12_FIELD* field =
            &Vmcs12->Fields[index];

        /* Replace the exact existing field encoding. */
        if (field->Active &&
            field->Encoding == Encoding) {
            /* Publish the new L1-provided field value. */
            field->Value = Value;
            /* Complete the bounded field replacement successfully. */
            return STATUS_SUCCESS;
        }
        /* Preserve only the first inactive field slot. */
        if (!field->Active &&
            freeSlot == NULL) {
            /* Retain the reusable bounded cache slot. */
            freeSlot = field;
        }
    }
    /* Report bounded vmcs12 field capacity exhaustion. */
    if (freeSlot == NULL) {
        /* Return the exact fixed-capacity failure. */
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    /* Publish the exact VMCS field encoding. */
    freeSlot->Encoding = Encoding;
    /* Publish the exact L1-provided field value. */
    freeSlot->Value = Value;
    /* Order field data before publishing the active marker. */
    KeMemoryBarrier();
    /* Publish the complete cached field. */
    freeSlot->Active = TRUE;
    /* Complete the bounded field insertion successfully. */
    return STATUS_SUCCESS;
}

NTSTATUS
KswordARKHvmNestedVmcs12Read(
    _In_ const KSW_HVM_VMCS12_STATE* Vmcs12,
    _In_ ULONG Encoding,
    _Out_ ULONGLONG* Value
    )
{
    ULONG index = 0UL;

    /* Require one current vmcs12 and a fixed output. */
    if (Vmcs12 == NULL ||
        Value == NULL ||
        !Vmcs12->Current ||
        Encoding == 0UL) {
        /* Return the exact nested-state contract failure. */
        return STATUS_INVALID_DEVICE_STATE;
    }
    /* Search the bounded vmcs12 field cache. */
    for (index = 0UL;
         index < KSW_HVM_VMCS12_FIELD_CAPACITY;
         ++index) {
        const KSW_HVM_VMCS12_FIELD* field =
            &Vmcs12->Fields[index];

        /* Match only the exact active field encoding. */
        if (field->Active &&
            field->Encoding == Encoding) {
            /* Publish the cached L1 field value. */
            *Value = field->Value;
            /* Complete the bounded field read successfully. */
            return STATUS_SUCCESS;
        }
    }
    /* Report an uncached vmcs12 field explicitly. */
    return STATUS_NOT_FOUND;
}

NTSTATUS
KswordARKHvmNestedVmcs02Prepare(
    _In_ const KSW_HVM_VMCS12_STATE* Vmcs12,
    _In_ ULONGLONG ComposedEptPointer,
    _Out_ KSW_HVM_VMCS02_STATE* Vmcs02
    )
{
    /* Validate fixed merge-state pointers. */
    if (Vmcs12 == NULL ||
        Vmcs02 == NULL) {
        /* Return the exact caller-contract failure. */
        return STATUS_INVALID_PARAMETER;
    }
    /* Clear stale merge state before evaluating prerequisites. */
    RtlZeroMemory(Vmcs02, sizeof(*Vmcs02));
    /* Require one current vmcs12 before merge validation. */
    if (!Vmcs12->Current) {
        /* Publish the exact invalid nested state. */
        Vmcs02->LastStatus =
            STATUS_INVALID_DEVICE_STATE;
        /* Publish Intel invalid-control-fields evidence. */
        Vmcs02->InstructionError =
            KSW_HVM_VMX_ERROR_INVALID_CONTROL_FIELDS;
        /* Return the exact invalid nested state. */
        return Vmcs02->LastStatus;
    }
    /* Require a fully composed L1-on-L0 EPT pointer before L2 entry. */
    if (ComposedEptPointer == 0ULL) {
        /* Publish explicit partial shadow-EPT status. */
        Vmcs02->LastStatus = STATUS_NOT_IMPLEMENTED;
        /* Publish Intel invalid-control-fields evidence. */
        Vmcs02->InstructionError =
            KSW_HVM_VMX_ERROR_INVALID_CONTROL_FIELDS;
        /* Return without claiming vmcs02 readiness. */
        return Vmcs02->LastStatus;
    }
    /*
     * Control/guest merge and exit reflection remain deliberately incomplete.
     * Preserve the composed EPT identity but do not publish an active vmcs02.
     */
    Vmcs02->EptPointer = ComposedEptPointer;
    /* Publish explicit partial merge status. */
    Vmcs02->LastStatus = STATUS_NOT_IMPLEMENTED;
    /* Publish Intel invalid-control-fields evidence. */
    Vmcs02->InstructionError =
        KSW_HVM_VMX_ERROR_INVALID_CONTROL_FIELDS;
    /* Return without claiming L2 active state. */
    return Vmcs02->LastStatus;
}
