#pragma once

#include <ntddk.h>

#include "driver/KswordArkRxPfIoctl.h"

EXTERN_C_START

#define KSW_RXPF_X64_MAX_INSTRUCTION_BYTES 15UL

/*
 * This layout exactly matches the register pushes in page_fault_stub.asm.
 * HardwareRsp/HardwareSs exist only for a privilege transition; kernel faults
 * calculate logical RSP from the address of HardwareRsp instead of reading it.
 */
typedef struct _KSW_RXPF_TRAP_FRAME
{
    ULONGLONG R15;
    ULONGLONG R14;
    ULONGLONG R13;
    ULONGLONG R12;
    ULONGLONG R11;
    ULONGLONG R10;
    ULONGLONG R9;
    ULONGLONG R8;
    ULONGLONG Rdi;
    ULONGLONG Rsi;
    ULONGLONG Rbp;
    ULONGLONG Rbx;
    ULONGLONG Rdx;
    ULONGLONG Rcx;
    ULONGLONG Rax;
    ULONGLONG ErrorCode;
    ULONGLONG Rip;
    ULONGLONG Cs;
    ULONGLONG Rflags;
    ULONGLONG HardwareRsp;
    ULONGLONG HardwareSs;
} KSW_RXPF_TRAP_FRAME, *PKSW_RXPF_TRAP_FRAME;

typedef struct _KSW_RXPF_EMULATION_CONTEXT
{
    PKSW_RXPF_TRAP_FRAME Frame;
    ULONGLONG LogicalRsp;
    ULONGLONG StackLow;
    ULONGLONG StackHigh;
    ULONG AvailableBytes;
    ULONG DecodedInstruction;
    ULONG EmulationResult;
    ULONG InstructionLength;
    NTSTATUS Status;
    UCHAR Instruction[KSW_RXPF_X64_MAX_INSTRUCTION_BYTES];
} KSW_RXPF_EMULATION_CONTEXT, *PKSW_RXPF_EMULATION_CONTEXT;

_Must_inspect_result_
NTSTATUS
KswRxpfX64EmulateOne(
    _Inout_ PKSW_RXPF_EMULATION_CONTEXT Context
    );

_Must_inspect_result_
NTSTATUS
KswRxpfX64RunUnitTests(
    VOID
    );

EXTERN_C_END
