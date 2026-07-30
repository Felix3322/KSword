/*++

Module Name:

    hvm_ept.h

Abstract:

    Defines four-KiB EPT split, rule, and transient allow-once handling.

Environment:

    Kernel-mode Driver Framework.

--*/

#pragma once

#include "hvm_internal.h"

/* Preserve one temporary EPT permission grant until monitor-trap exit. */
typedef struct _KSW_HVM_EPT_TRANSIENT
{
    /* Record whether one permission restoration is pending. */
    BOOLEAN Armed;
    /* Keep the structure explicitly initialized across architectures. */
    UCHAR Reserved0[3];
    /* Preserve the rule identifier that caused the temporary grant. */
    ULONG RuleId;
    /* Preserve the writable target EPT entry. */
    volatile ULONGLONG* Entry;
    /* Preserve the restricted value restored on monitor-trap exit. */
    ULONGLONG RestrictedValue;
} KSW_HVM_EPT_TRANSIENT;

EXTERN_C_START

/* Build a continuous RAM-plus-MMIO identity window under the runtime lock. */
NTSTATUS
KswordARKHvmBuildEptLocked(
    _Inout_ KSW_HVM_RUNTIME* Runtime
    );

/* Reset EPT rules and restore split leaves before table pages are freed. */
VOID
KswordARKHvmEptResetLocked(
    _Inout_ KSW_HVM_RUNTIME* Runtime
    );

/* Execute one versioned EPT rule operation under the runtime lock. */
NTSTATUS
KswordARKHvmEptRuleControlLocked(
    _Inout_ KSW_HVM_RUNTIME* Runtime,
    _In_ const KSWORD_ARK_HVM_EPT_RULE_REQUEST* Request,
    _Out_ KSWORD_ARK_HVM_EPT_RULE_RESPONSE* Response
    );

/* Handle one EPT violation without allocating or waiting in VMX root. */
BOOLEAN
KswordARKHvmEptHandleViolation(
    _Inout_ KSW_HVM_RUNTIME* Runtime,
    _In_ ULONGLONG GuestPhysicalAddress,
    _In_ ULONG Access,
    _Out_ KSW_HVM_EPT_TRANSIENT* Transient,
    _Out_ ULONG* RuleId
    );

/* Restore and invalidate one armed allow-once permission set. */
BOOLEAN
KswordARKHvmEptRestoreTransient(
    _Inout_ KSW_HVM_RUNTIME* Runtime,
    _Inout_ KSW_HVM_EPT_TRANSIENT* Transient
    );

/* Restore one allow-once permission set on monitor-trap exit. */
BOOLEAN
KswordARKHvmEptHandleMonitorTrap(
    _Inout_ KSW_HVM_RUNTIME* Runtime,
    _Inout_ KSW_HVM_EPT_TRANSIENT* Transient
    );

/* Execute single-context INVEPT for the current VMX root. */
UCHAR
KswordARKHvmAsmInveptSingle(
    _In_ ULONGLONG EptPointer
    );

EXTERN_C_END
