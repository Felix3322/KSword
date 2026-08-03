/*++

Module Name:

    x64_instruction_emulator_tests.c

Abstract:

    Load-time, allocation-free smoke tests for the RXPF scalar whitelist.

Environment:

    Kernel mode, PASSIVE_LEVEL during RXPF runtime initialization.

--*/

#include "x64_instruction_emulator.h"

#define KSW_TEST_EFLAGS_ZF 0x0000000000000040ULL
#define KSW_TEST_EFLAGS_OF 0x0000000000000800ULL

static VOID
KswRxpfInitializeTestContext(
    _Out_ PKSW_RXPF_EMULATION_CONTEXT Context,
    _Out_ PKSW_RXPF_TRAP_FRAME Frame,
    _In_reads_bytes_(Length) const UCHAR* Instruction,
    _In_ ULONG Length
    )
{
    ULONG_PTR stackLow = 0U;
    ULONG_PTR stackHigh = 0U;

    RtlZeroMemory(Context, sizeof(*Context));
    RtlZeroMemory(Frame, sizeof(*Frame));
    Frame->Rip = (ULONGLONG)(ULONG_PTR)KswRxpfX64RunUnitTests;
    Frame->Rflags = 2ULL;
    Context->Frame = Frame;
    Context->AvailableBytes = Length;
    IoGetStackLimits(&stackLow, &stackHigh);
    Context->StackLow = (ULONGLONG)stackLow;
    Context->StackHigh = (ULONGLONG)stackHigh;
    Context->LogicalRsp = (ULONGLONG)stackHigh;
    RtlCopyMemory(Context->Instruction, Instruction, Length);
}

NTSTATUS
KswRxpfX64RunUnitTests(
    VOID
    )
{
    static const UCHAR movRaxImmediate[] = {
        0x48U, 0xB8U, 0x88U, 0x77U, 0x66U, 0x55U,
        0x44U, 0x33U, 0x22U, 0x11U
    };
    static const UCHAR movEaxImmediate[] = {
        0xB8U, 0xEFU, 0xCDU, 0xABU, 0x89U
    };
    static const UCHAR addRaxOne[] = {
        0x48U, 0x83U, 0xC0U, 0x01U
    };
    static const UCHAR leaRipRelative[] = {
        0x48U, 0x8DU, 0x05U, 0x10U, 0x00U, 0x00U, 0x00U
    };
    static const UCHAR jumpIfZero[] = { 0x74U, 0x02U };
    static const UCHAR pushRax[] = { 0x50U };
    static const UCHAR popRax[] = { 0x58U };
    static const UCHAR callNext[] = {
        0xE8U, 0x00U, 0x00U, 0x00U, 0x00U
    };
    static const UCHAR returnNear[] = { 0xC3U };
    static const UCHAR lockNop[] = { 0xF0U, 0x90U };
    static const UCHAR duplicatePrefix[] = { 0x66U, 0x66U, 0x90U };
    static const UCHAR movRspImmediate[] = {
        0x48U, 0xBCU, 0x00U, 0x10U, 0x00U, 0x00U,
        0x00U, 0x00U, 0x00U, 0x00U
    };
    static const UCHAR popRsp[] = { 0x5CU };
    KSW_RXPF_EMULATION_CONTEXT context;
    KSW_RXPF_TRAP_FRAME frame;
    ULONGLONG stackSlots[16];
    ULONGLONG startRip = 0ULL;
    ULONGLONG startRsp = 0ULL;
    NTSTATUS status = STATUS_SUCCESS;

    KswRxpfInitializeTestContext(
        &context,
        &frame,
        movRaxImmediate,
        sizeof(movRaxImmediate));
    startRip = frame.Rip;
    status = KswRxpfX64EmulateOne(&context);
    if (!NT_SUCCESS(status) ||
        frame.Rax != 0x1122334455667788ULL ||
        frame.Rip != startRip + sizeof(movRaxImmediate)) {
        return STATUS_DATA_ERROR;
    }

    KswRxpfInitializeTestContext(
        &context,
        &frame,
        movEaxImmediate,
        sizeof(movEaxImmediate));
    frame.Rax = MAXULONGLONG;
    status = KswRxpfX64EmulateOne(&context);
    if (!NT_SUCCESS(status) || frame.Rax != 0x0000000089ABCDEFULL) {
        return STATUS_DATA_ERROR;
    }

    KswRxpfInitializeTestContext(
        &context,
        &frame,
        addRaxOne,
        sizeof(addRaxOne));
    frame.Rax = 0x7FFFFFFFFFFFFFFFULL;
    status = KswRxpfX64EmulateOne(&context);
    if (!NT_SUCCESS(status) || frame.Rax != 0x8000000000000000ULL ||
        (frame.Rflags & KSW_TEST_EFLAGS_OF) == 0ULL) {
        return STATUS_DATA_ERROR;
    }

    KswRxpfInitializeTestContext(
        &context,
        &frame,
        leaRipRelative,
        sizeof(leaRipRelative));
    startRip = frame.Rip;
    status = KswRxpfX64EmulateOne(&context);
    if (!NT_SUCCESS(status) ||
        frame.Rax != startRip + sizeof(leaRipRelative) + 0x10ULL) {
        return STATUS_DATA_ERROR;
    }

    KswRxpfInitializeTestContext(
        &context,
        &frame,
        jumpIfZero,
        sizeof(jumpIfZero));
    startRip = frame.Rip;
    frame.Rflags |= KSW_TEST_EFLAGS_ZF;
    status = KswRxpfX64EmulateOne(&context);
    if (!NT_SUCCESS(status) ||
        frame.Rip != startRip + sizeof(jumpIfZero) + 2ULL) {
        return STATUS_DATA_ERROR;
    }

    RtlZeroMemory(stackSlots, sizeof(stackSlots));
    KswRxpfInitializeTestContext(
        &context,
        &frame,
        pushRax,
        sizeof(pushRax));
    frame.Rax = 0x123456789ABCDEF0ULL;
    startRsp = (ULONGLONG)(ULONG_PTR)&stackSlots[12];
    context.LogicalRsp = startRsp;
    status = KswRxpfX64EmulateOne(&context);
    if (!NT_SUCCESS(status) || context.LogicalRsp != startRsp - 8ULL ||
        stackSlots[11] != frame.Rax) {
        return STATUS_DATA_ERROR;
    }

    KswRxpfInitializeTestContext(
        &context,
        &frame,
        popRax,
        sizeof(popRax));
    stackSlots[12] = 0x0FEDCBA987654321ULL;
    startRsp = (ULONGLONG)(ULONG_PTR)&stackSlots[12];
    context.LogicalRsp = startRsp;
    status = KswRxpfX64EmulateOne(&context);
    if (!NT_SUCCESS(status) || frame.Rax != stackSlots[12] ||
        context.LogicalRsp != startRsp + 8ULL) {
        return STATUS_DATA_ERROR;
    }

    KswRxpfInitializeTestContext(
        &context,
        &frame,
        callNext,
        sizeof(callNext));
    startRip = frame.Rip;
    startRsp = (ULONGLONG)(ULONG_PTR)&stackSlots[12];
    context.LogicalRsp = startRsp;
    status = KswRxpfX64EmulateOne(&context);
    if (!NT_SUCCESS(status) ||
        frame.Rip != startRip + sizeof(callNext) ||
        context.LogicalRsp != startRsp - 8ULL ||
        stackSlots[11] != startRip + sizeof(callNext)) {
        return STATUS_DATA_ERROR;
    }

    KswRxpfInitializeTestContext(
        &context,
        &frame,
        returnNear,
        sizeof(returnNear));
    startRsp = (ULONGLONG)(ULONG_PTR)&stackSlots[12];
    stackSlots[12] = frame.Rip + 0x40ULL;
    context.LogicalRsp = startRsp;
    status = KswRxpfX64EmulateOne(&context);
    if (!NT_SUCCESS(status) || frame.Rip != stackSlots[12] ||
        context.LogicalRsp != startRsp + 8ULL) {
        return STATUS_DATA_ERROR;
    }

    KswRxpfInitializeTestContext(
        &context,
        &frame,
        lockNop,
        sizeof(lockNop));
    startRip = frame.Rip;
    frame.Rax = 0x55AAULL;
    status = KswRxpfX64EmulateOne(&context);
    if (status != STATUS_NOT_SUPPORTED || frame.Rip != startRip ||
        frame.Rax != 0x55AAULL) {
        return STATUS_DATA_ERROR;
    }

    KswRxpfInitializeTestContext(
        &context,
        &frame,
        duplicatePrefix,
        sizeof(duplicatePrefix));
    startRip = frame.Rip;
    status = KswRxpfX64EmulateOne(&context);
    if (status != STATUS_NOT_SUPPORTED || frame.Rip != startRip) {
        return STATUS_DATA_ERROR;
    }

    KswRxpfInitializeTestContext(
        &context,
        &frame,
        movRspImmediate,
        sizeof(movRspImmediate));
    startRip = frame.Rip;
    startRsp = context.LogicalRsp;
    status = KswRxpfX64EmulateOne(&context);
    if (NT_SUCCESS(status) || frame.Rip != startRip ||
        context.LogicalRsp != startRsp) {
        return STATUS_DATA_ERROR;
    }

    KswRxpfInitializeTestContext(
        &context,
        &frame,
        popRsp,
        sizeof(popRsp));
    startRip = frame.Rip;
    startRsp = (ULONGLONG)(ULONG_PTR)&stackSlots[12];
    context.LogicalRsp = startRsp;
    status = KswRxpfX64EmulateOne(&context);
    if (status != STATUS_NOT_SUPPORTED || frame.Rip != startRip ||
        context.LogicalRsp != startRsp) {
        return STATUS_DATA_ERROR;
    }

    return STATUS_SUCCESS;
}
