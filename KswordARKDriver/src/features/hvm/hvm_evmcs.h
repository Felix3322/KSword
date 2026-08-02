/*++

Module Name:

    hvm_evmcs.h

Abstract:

    Defines TLFS feature discovery and explicit eVMCS v1 implementation state.

Environment:

    Kernel-mode Driver Framework.

--*/

#pragma once

#include "hvm_internal.h"

EXTERN_C_START

/* Discover Hyper-V eVMCS support from TLFS CPUID leaves only. */
VOID
KswordARKHvmEvmcsDiscover(
    _Inout_ KSW_HVM_RUNTIME* Runtime
    );

/* Validate whether eVMCS v1 can be activated in the current partition. */
NTSTATUS
KswordARKHvmEvmcsValidate(
    _Inout_ KSW_HVM_RUNTIME* Runtime
    );

EXTERN_C_END
