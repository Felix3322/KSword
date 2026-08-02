#pragma once

#include "ark/ark_driver.h"

EXTERN_C_START

typedef struct _KSW_ALPC_RUNTIME_BASIC_INFO
{
    ULONG Flags;
    ULONG SequenceNo;
    PVOID PortContext;
} KSW_ALPC_RUNTIME_BASIC_INFO, *PKSW_ALPC_RUNTIME_BASIC_INFO;

NTSTATUS
KswordARKAlpcQueryRuntimeBasicInfo(
    _In_ PEPROCESS ProcessObject,
    _In_ ULONG64 HandleValue,
    _Out_ KSW_ALPC_RUNTIME_BASIC_INFO* BasicInfoOut
    );

EXTERN_C_END
