/*++

Module Name:

    hvm_nested_vmcs.h

Abstract:

    Defines bounded vmcs12 storage and explicit partial vmcs02 merge state.

Environment:

    Kernel-mode Driver Framework.

--*/

#pragma once

#include "hvm_internal.h"

/* Bound vmcs12 field storage without VM-exit allocation. */
#define KSW_HVM_VMCS12_FIELD_CAPACITY 64UL

/* Preserve one cached vmcs12 field encoding and value. */
typedef struct _KSW_HVM_VMCS12_FIELD
{
    /* Record whether this cache slot contains a field. */
    BOOLEAN Active;
    /* Keep the structure explicitly initialized across architectures. */
    UCHAR Reserved0[3];
    /* Preserve the Intel VMCS field encoding. */
    ULONG Encoding;
    /* Preserve the L1-provided field value. */
    ULONGLONG Value;
} KSW_HVM_VMCS12_FIELD;

/* Preserve bounded vmcs12 identity, launch state, and fields. */
typedef struct _KSW_HVM_VMCS12_STATE
{
    /* Record whether one vmcs12 pointer is current. */
    BOOLEAN Current;
    /* Record whether the current vmcs12 has launched. */
    BOOLEAN Launched;
    /* Keep the structure explicitly initialized across architectures. */
    USHORT Reserved0;
    /* Preserve the last VM-instruction error visible to L1. */
    ULONG InstructionError;
    /* Preserve the current vmcs12 physical address. */
    ULONGLONG PhysicalAddress;
    /* Preserve a bounded field cache. */
    KSW_HVM_VMCS12_FIELD Fields[KSW_HVM_VMCS12_FIELD_CAPACITY];
} KSW_HVM_VMCS12_STATE;

/* Preserve explicit vmcs02 merge maturity without claiming L2 active. */
typedef struct _KSW_HVM_VMCS02_STATE
{
    /* Record whether control merge validation completed. */
    BOOLEAN ControlsValidated;
    /* Record whether guest-state merge validation completed. */
    BOOLEAN GuestStateValidated;
    /* Record whether exit-reflection metadata is complete. */
    BOOLEAN ExitReflectionReady;
    /* Record whether a hardware vmcs02 is active. */
    BOOLEAN Active;
    /* Preserve the last merge status. */
    NTSTATUS LastStatus;
    /* Preserve the last Intel VM-instruction error. */
    ULONG InstructionError;
    /* Preserve the merged EPT pointer when available. */
    ULONGLONG EptPointer;
} KSW_HVM_VMCS02_STATE;

EXTERN_C_START

/* Initialize bounded vmcs12 and vmcs02 state. */
VOID
KswordARKHvmNestedVmcsInitialize(
    _Out_ KSW_HVM_VMCS12_STATE* Vmcs12,
    _Out_ KSW_HVM_VMCS02_STATE* Vmcs02
    );

/* Cache one vmcs12 field without dynamic allocation. */
NTSTATUS
KswordARKHvmNestedVmcs12Write(
    _Inout_ KSW_HVM_VMCS12_STATE* Vmcs12,
    _In_ ULONG Encoding,
    _In_ ULONGLONG Value
    );

/* Read one cached vmcs12 field. */
NTSTATUS
KswordARKHvmNestedVmcs12Read(
    _In_ const KSW_HVM_VMCS12_STATE* Vmcs12,
    _In_ ULONG Encoding,
    _Out_ ULONGLONG* Value
    );

/* Validate merge prerequisites while retaining explicit partial state. */
NTSTATUS
KswordARKHvmNestedVmcs02Prepare(
    _In_ const KSW_HVM_VMCS12_STATE* Vmcs12,
    _In_ ULONGLONG ComposedEptPointer,
    _Out_ KSW_HVM_VMCS02_STATE* Vmcs02
    );

EXTERN_C_END
