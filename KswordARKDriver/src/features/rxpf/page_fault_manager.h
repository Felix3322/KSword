#pragma once

#include <ntddk.h>

#include "page_state_table.h"
#include "x64_instruction_emulator.h"

EXTERN_C_START

#define KSW_RXPF_DISPATCH_CHAIN 0ULL
#define KSW_RXPF_DISPATCH_HANDLED 1ULL

NTSTATUS
KswRxpfPageFaultManagerInitialize(
    _In_ PKSW_RXPF_PAGE_TABLE PageTable,
    _In_ ULONG MaximumProcessorCount
    );

VOID
KswRxpfPageFaultManagerUninitialize(
    VOID
    );

NTSTATUS
KswRxpfPageFaultInstall(
    VOID
    );

NTSTATUS
KswRxpfPageFaultRestore(
    VOID
    );

BOOLEAN
KswRxpfPageFaultIsInstalled(
    VOID
    );

ULONG
KswRxpfPageFaultProcessorCount(
    VOID
    );

ULONGLONG
NTAPI
KswRxpfPageFaultDispatch(
    _Inout_ PKSW_RXPF_TRAP_FRAME Frame,
    _Out_ PVOID* TransferTargetOut,
    _Out_ ULONGLONG* ResumeRspOut,
    _Out_ PKSW_RXPF_TRAP_FRAME ResumeFrameOut
    );

VOID
KswRxpfPageFaultStub(
    VOID
    );

EXTERN_C_END
