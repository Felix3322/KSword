/*++

Module Name:

    hvm_exit.h

Abstract:

    Defines the resident VM-exit register frame and dispatcher contract.

Environment:

    Kernel-mode Driver Framework.

--*/

#pragma once

#include "hvm_internal.h"

/* Preserve guest GPRs in the exact order emitted by hvm_entry.asm. */
typedef struct _KSW_HVM_GPR_FRAME
{
    /* Preserve guest RAX. */
    ULONGLONG Rax;
    /* Preserve guest RCX. */
    ULONGLONG Rcx;
    /* Preserve guest RDX. */
    ULONGLONG Rdx;
    /* Preserve guest RBX. */
    ULONGLONG Rbx;
    /* Preserve guest RBP. */
    ULONGLONG Rbp;
    /* Preserve guest RSI. */
    ULONGLONG Rsi;
    /* Preserve guest RDI. */
    ULONGLONG Rdi;
    /* Preserve guest R8. */
    ULONGLONG R8;
    /* Preserve guest R9. */
    ULONGLONG R9;
    /* Preserve guest R10. */
    ULONGLONG R10;
    /* Preserve guest R11. */
    ULONGLONG R11;
    /* Preserve guest R12. */
    ULONGLONG R12;
    /* Preserve guest R13. */
    ULONGLONG R13;
    /* Preserve guest R14. */
    ULONGLONG R14;
    /* Preserve guest R15. */
    ULONGLONG R15;
} KSW_HVM_GPR_FRAME;

/* Forward-declare the per-processor resident context. */
struct _KSW_HVM_RESIDENT_VCPU;

/* Request VMRESUME after a fully handled exit. */
#define KSW_HVM_EXIT_ACTION_RESUME 0UL
/* Request devirtualization onto the captured guest continuation. */
#define KSW_HVM_EXIT_ACTION_DEVIRTUALIZE 1UL
/* Request a bounded fatal trap when no safe guest continuation exists. */
#define KSW_HVM_EXIT_ACTION_FATAL 2UL

EXTERN_C_START

/* Dispatch one resident VM exit without allocation or waiting. */
ULONG
KswordARKHvmResidentVmExitDispatch(
    _Inout_ KSW_HVM_GPR_FRAME* Frame,
    _Inout_ struct _KSW_HVM_RESIDENT_VCPU* Context
    );

/* Convert VMRESUME failure into a bounded devirtualization continuation. */
ULONG
KswordARKHvmResidentVmResumeFailure(
    _Inout_ struct _KSW_HVM_RESIDENT_VCPU* Context,
    _In_ UCHAR InstructionResult
    );

EXTERN_C_END
