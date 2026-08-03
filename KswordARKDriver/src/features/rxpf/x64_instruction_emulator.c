/*++

Module Name:

    x64_instruction_emulator.c

Abstract:

    Allocation-free x86-64 whitelist decoder and one-instruction emulator.

Environment:

    Kernel mode, nonpaged vector-14 path.  Memory operands are rejected except
    for validated accesses to the current kernel stack by PUSH/POP/CALL/RET.

--*/

#include "x64_instruction_emulator.h"

#define KSW_EFLAGS_CF 0x0000000000000001ULL
#define KSW_EFLAGS_PF 0x0000000000000004ULL
#define KSW_EFLAGS_AF 0x0000000000000010ULL
#define KSW_EFLAGS_ZF 0x0000000000000040ULL
#define KSW_EFLAGS_SF 0x0000000000000080ULL
#define KSW_EFLAGS_OF 0x0000000000000800ULL
#define KSW_EFLAGS_ARITHMETIC_MASK \
    (KSW_EFLAGS_CF | KSW_EFLAGS_PF | KSW_EFLAGS_AF | \
     KSW_EFLAGS_ZF | KSW_EFLAGS_SF | KSW_EFLAGS_OF)

typedef struct _KSW_RXPF_DECODER
{
    PKSW_RXPF_EMULATION_CONTEXT Context;
    ULONG Cursor;
    UCHAR Rex;
    BOOLEAN OperandSize16;
    BOOLEAN RexPresent;
} KSW_RXPF_DECODER, *PKSW_RXPF_DECODER;

static BOOLEAN
KswRxpfIsCanonical(
    _In_ ULONGLONG Address
    )
{
    /* Bit 47, not merely the high word, selects canonical sign extension. */
    return Address <= 0x00007FFFFFFFFFFFULL ||
        Address >= 0xFFFF800000000000ULL;
}

static BOOLEAN
KswRxpfIsCanonicalKernelTarget(
    _In_ ULONGLONG Address
    )
{
    /* Emulated kernel control flow never transfers into the user half. */
    return KswRxpfIsCanonical(Address) &&
        Address >= (ULONGLONG)(ULONG_PTR)MmSystemRangeStart;
}

static ULONGLONG
KswRxpfWidthMask(
    _In_ ULONG Width
    )
{
    /* Avoid an undefined shift by 64 while producing an operand mask. */
    return Width == 64UL ? MAXULONGLONG : ((1ULL << Width) - 1ULL);
}

static ULONGLONG
KswRxpfSignBit(
    _In_ ULONG Width
    )
{
    /* Width is validated to one of the architectural scalar sizes. */
    return 1ULL << (Width - 1UL);
}

static ULONGLONG
KswRxpfSignExtend(
    _In_ ULONGLONG Value,
    _In_ ULONG SourceWidth
    )
{
    ULONGLONG mask = KswRxpfWidthMask(SourceWidth);
    ULONGLONG sign = KswRxpfSignBit(SourceWidth);

    /* Extend only the selected source width into the 64-bit result. */
    Value &= mask;
    if ((Value & sign) != 0ULL) {
        Value |= ~mask;
    }
    return Value;
}

static BOOLEAN
KswRxpfEvenParity(
    _In_ UCHAR Value
    )
{
    UCHAR folded = Value;

    /* Fold eight input bits and use the inverted low bit for even parity. */
    folded ^= (UCHAR)(folded >> 4);
    folded ^= (UCHAR)(folded >> 2);
    folded ^= (UCHAR)(folded >> 1);
    return (folded & 1U) == 0U;
}

static PULONGLONG
KswRxpfRegisterStorage(
    _Inout_ PKSW_RXPF_EMULATION_CONTEXT Context,
    _In_ ULONG RegisterIndex
    )
{
    /* Map architectural register codes to the assembly-saved frame slots. */
    switch (RegisterIndex) {
    case 0UL: return &Context->Frame->Rax;
    case 1UL: return &Context->Frame->Rcx;
    case 2UL: return &Context->Frame->Rdx;
    case 3UL: return &Context->Frame->Rbx;
    case 5UL: return &Context->Frame->Rbp;
    case 6UL: return &Context->Frame->Rsi;
    case 7UL: return &Context->Frame->Rdi;
    case 8UL: return &Context->Frame->R8;
    case 9UL: return &Context->Frame->R9;
    case 10UL: return &Context->Frame->R10;
    case 11UL: return &Context->Frame->R11;
    case 12UL: return &Context->Frame->R12;
    case 13UL: return &Context->Frame->R13;
    case 14UL: return &Context->Frame->R14;
    case 15UL: return &Context->Frame->R15;
    default: return NULL;
    }
}

static ULONGLONG
KswRxpfReadRegister(
    _Inout_ PKSW_RXPF_EMULATION_CONTEXT Context,
    _In_ ULONG RegisterCode,
    _In_ ULONG Width,
    _In_ BOOLEAN RexPresent
    )
{
    PULONGLONG storage = NULL;
    ULONGLONG value = 0ULL;

    /* AH/CH/DH/BH are selected by byte codes 4..7 only without REX. */
    if (Width == 8UL && !RexPresent &&
        RegisterCode >= 4UL && RegisterCode <= 7UL) {
        storage = KswRxpfRegisterStorage(Context, RegisterCode - 4UL);
        return (*storage >> 8) & 0xFFULL;
    }
    /* Register code four represents the logical interrupted RSP. */
    if (RegisterCode == 4UL) {
        value = Context->LogicalRsp;
    } else {
        storage = KswRxpfRegisterStorage(Context, RegisterCode);
        if (storage == NULL) {
            return 0ULL;
        }
        value = *storage;
    }
    return value & KswRxpfWidthMask(Width);
}

static BOOLEAN
KswRxpfWriteRegister(
    _Inout_ PKSW_RXPF_EMULATION_CONTEXT Context,
    _In_ ULONG RegisterCode,
    _In_ ULONG Width,
    _In_ BOOLEAN RexPresent,
    _In_ ULONGLONG Value
    )
{
    PULONGLONG storage = NULL;
    ULONGLONG current = 0ULL;
    ULONGLONG mask = KswRxpfWidthMask(Width);

    /* Update legacy high-byte registers without disturbing other bits. */
    if (Width == 8UL && !RexPresent &&
        RegisterCode >= 4UL && RegisterCode <= 7UL) {
        storage = KswRxpfRegisterStorage(Context, RegisterCode - 4UL);
        current = *storage;
        current &= ~0xFF00ULL;
        current |= (Value & 0xFFULL) << 8;
        *storage = current;
        return TRUE;
    }
    /* Only explicit PUSH/POP/CALL/RET paths may change logical RSP. */
    if (RegisterCode == 4UL) {
        return FALSE;
    }
    storage = KswRxpfRegisterStorage(Context, RegisterCode);
    if (storage == NULL) {
        return FALSE;
    }
    current = *storage;
    if (Width == 64UL) {
        *storage = Value;
    } else if (Width == 32UL) {
        /* x86-64 zero-extends every 32-bit general-register write. */
        *storage = Value & 0xFFFFFFFFULL;
    } else {
        *storage = (current & ~mask) | (Value & mask);
    }
    return TRUE;
}

static BOOLEAN
KswRxpfReadByte(
    _Inout_ PKSW_RXPF_DECODER Decoder,
    _Out_ UCHAR* ValueOut
    )
{
    /* A truncated instruction at the managed-page boundary is unsupported. */
    if (Decoder->Cursor >= Decoder->Context->AvailableBytes ||
        Decoder->Cursor >= KSW_RXPF_X64_MAX_INSTRUCTION_BYTES) {
        return FALSE;
    }
    *ValueOut = Decoder->Context->Instruction[Decoder->Cursor];
    Decoder->Cursor += 1UL;
    return TRUE;
}

static BOOLEAN
KswRxpfReadImmediate(
    _Inout_ PKSW_RXPF_DECODER Decoder,
    _In_ ULONG ByteCount,
    _Out_ ULONGLONG* ValueOut
    )
{
    ULONGLONG value = 0ULL;

    /* Copy little-endian scalar bytes only from the pre-copied instruction. */
    if (ByteCount == 0UL || ByteCount > sizeof(value) ||
        Decoder->Cursor > Decoder->Context->AvailableBytes ||
        ByteCount > Decoder->Context->AvailableBytes - Decoder->Cursor ||
        Decoder->Cursor > KSW_RXPF_X64_MAX_INSTRUCTION_BYTES ||
        ByteCount > KSW_RXPF_X64_MAX_INSTRUCTION_BYTES - Decoder->Cursor) {
        return FALSE;
    }
    RtlCopyMemory(
        &value,
        &Decoder->Context->Instruction[Decoder->Cursor],
        ByteCount);
    Decoder->Cursor += ByteCount;
    *ValueOut = value;
    return TRUE;
}

static ULONG
KswRxpfOperandWidth(
    _In_ const KSW_RXPF_DECODER* Decoder,
    _In_ BOOLEAN ByteOperation
    )
{
    /* Scalar width follows byte opcode, REX.W, 66h, then x64 default 32. */
    if (ByteOperation) {
        return 8UL;
    }
    if ((Decoder->Rex & 0x08U) != 0U) {
        return 64UL;
    }
    if (Decoder->OperandSize16) {
        return 16UL;
    }
    return 32UL;
}

static VOID
KswRxpfUpdateLogicFlags(
    _Inout_ PKSW_RXPF_EMULATION_CONTEXT Context,
    _In_ ULONGLONG Result,
    _In_ ULONG Width
    )
{
    ULONGLONG masked = Result & KswRxpfWidthMask(Width);
    ULONGLONG flags = Context->Frame->Rflags &
        ~KSW_EFLAGS_ARITHMETIC_MASK;

    /* Logical operations clear CF/OF and derive SF/ZF/PF from the result. */
    if (masked == 0ULL) {
        flags |= KSW_EFLAGS_ZF;
    }
    if ((masked & KswRxpfSignBit(Width)) != 0ULL) {
        flags |= KSW_EFLAGS_SF;
    }
    if (KswRxpfEvenParity((UCHAR)masked)) {
        flags |= KSW_EFLAGS_PF;
    }
    Context->Frame->Rflags = flags;
}

static VOID
KswRxpfUpdateAddFlags(
    _Inout_ PKSW_RXPF_EMULATION_CONTEXT Context,
    _In_ ULONGLONG Left,
    _In_ ULONGLONG Right,
    _In_ ULONGLONG Result,
    _In_ ULONG Width
    )
{
    ULONGLONG mask = KswRxpfWidthMask(Width);
    ULONGLONG sign = KswRxpfSignBit(Width);
    ULONGLONG left = Left & mask;
    ULONGLONG right = Right & mask;
    ULONGLONG result = Result & mask;
    ULONGLONG flags = Context->Frame->Rflags &
        ~KSW_EFLAGS_ARITHMETIC_MASK;

    /* Compute the six arithmetic status flags for an addition. */
    if (result < left) flags |= KSW_EFLAGS_CF;
    if (((~(left ^ right)) & (left ^ result) & sign) != 0ULL) flags |= KSW_EFLAGS_OF;
    if (((left ^ right ^ result) & 0x10ULL) != 0ULL) flags |= KSW_EFLAGS_AF;
    if (result == 0ULL) flags |= KSW_EFLAGS_ZF;
    if ((result & sign) != 0ULL) flags |= KSW_EFLAGS_SF;
    if (KswRxpfEvenParity((UCHAR)result)) flags |= KSW_EFLAGS_PF;
    Context->Frame->Rflags = flags;
}

static VOID
KswRxpfUpdateSubFlags(
    _Inout_ PKSW_RXPF_EMULATION_CONTEXT Context,
    _In_ ULONGLONG Left,
    _In_ ULONGLONG Right,
    _In_ ULONGLONG Result,
    _In_ ULONG Width
    )
{
    ULONGLONG mask = KswRxpfWidthMask(Width);
    ULONGLONG sign = KswRxpfSignBit(Width);
    ULONGLONG left = Left & mask;
    ULONGLONG right = Right & mask;
    ULONGLONG result = Result & mask;
    ULONGLONG flags = Context->Frame->Rflags &
        ~KSW_EFLAGS_ARITHMETIC_MASK;

    /* Compute the six arithmetic status flags for subtraction/comparison. */
    if (left < right) flags |= KSW_EFLAGS_CF;
    if ((((left ^ right) & (left ^ result)) & sign) != 0ULL) flags |= KSW_EFLAGS_OF;
    if (((left ^ right ^ result) & 0x10ULL) != 0ULL) flags |= KSW_EFLAGS_AF;
    if (result == 0ULL) flags |= KSW_EFLAGS_ZF;
    if ((result & sign) != 0ULL) flags |= KSW_EFLAGS_SF;
    if (KswRxpfEvenParity((UCHAR)result)) flags |= KSW_EFLAGS_PF;
    Context->Frame->Rflags = flags;
}

static BOOLEAN
KswRxpfStackRangeValid(
    _In_ const KSW_RXPF_EMULATION_CONTEXT* Context,
    _In_ ULONGLONG Address,
    _In_ ULONG ByteCount
    )
{
    ULONGLONG end = Address + ByteCount;

    /* Require a non-wrapping range wholly inside the current kernel stack. */
    if (ByteCount == 0UL || end < Address ||
        Address < Context->StackLow || end > Context->StackHigh) {
        return FALSE;
    }
    /* Stack pages must already be resident; the emulator never pages them in. */
    return MmIsAddressValid((PVOID)(ULONG_PTR)Address) &&
        MmIsAddressValid((PVOID)(ULONG_PTR)(end - 1ULL));
}

static BOOLEAN
KswRxpfResumeScratchValid(
    _In_ const KSW_RXPF_EMULATION_CONTEXT* Context,
    _In_ ULONGLONG ResumeRsp
    )
{
    /* The assembly return path needs four resident qwords below resume RSP. */
    if (ResumeRsp < 32ULL) {
        return FALSE;
    }
    return KswRxpfStackRangeValid(Context, ResumeRsp - 32ULL, 32UL);
}

static BOOLEAN
KswRxpfStackRead(
    _In_ const KSW_RXPF_EMULATION_CONTEXT* Context,
    _In_ ULONGLONG Address,
    _Out_writes_bytes_(ByteCount) PVOID Buffer,
    _In_ ULONG ByteCount
    )
{
    /* Refuse every memory read outside the resident current kernel stack. */
    if (!KswRxpfStackRangeValid(Context, Address, ByteCount)) {
        return FALSE;
    }
    __try {
        RtlCopyMemory(Buffer, (const VOID*)(ULONG_PTR)Address, ByteCount);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return FALSE;
    }
    return TRUE;
}

static BOOLEAN
KswRxpfStackWrite(
    _In_ const KSW_RXPF_EMULATION_CONTEXT* Context,
    _In_ ULONGLONG Address,
    _In_reads_bytes_(ByteCount) const VOID* Buffer,
    _In_ ULONG ByteCount
    )
{
    /* Refuse every memory write outside the resident current kernel stack. */
    if (!KswRxpfStackRangeValid(Context, Address, ByteCount)) {
        return FALSE;
    }
    __try {
        RtlCopyMemory((VOID*)(ULONG_PTR)Address, Buffer, ByteCount);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return FALSE;
    }
    return TRUE;
}

static NTSTATUS
KswRxpfApplyBinary(
    _Inout_ PKSW_RXPF_EMULATION_CONTEXT Context,
    _In_ ULONG Operation,
    _In_ ULONG DestinationRegister,
    _In_ ULONG Width,
    _In_ BOOLEAN RexPresent,
    _In_ ULONGLONG Left,
    _In_ ULONGLONG Right
    )
{
    ULONGLONG mask = KswRxpfWidthMask(Width);
    ULONGLONG result = 0ULL;
    BOOLEAN writeResult = TRUE;

    /* Execute only the explicitly enumerated scalar ALU operations. */
    switch (Operation) {
    case KSWORD_ARK_RXPF_DECODE_ADD:
        result = (Left + Right) & mask;
        KswRxpfUpdateAddFlags(Context, Left, Right, result, Width);
        break;
    case KSWORD_ARK_RXPF_DECODE_SUB:
    case KSWORD_ARK_RXPF_DECODE_CMP:
        result = (Left - Right) & mask;
        KswRxpfUpdateSubFlags(Context, Left, Right, result, Width);
        writeResult = Operation != KSWORD_ARK_RXPF_DECODE_CMP;
        break;
    case KSWORD_ARK_RXPF_DECODE_XOR:
        result = (Left ^ Right) & mask;
        KswRxpfUpdateLogicFlags(Context, result, Width);
        break;
    case KSWORD_ARK_RXPF_DECODE_AND:
    case KSWORD_ARK_RXPF_DECODE_TEST:
        result = (Left & Right) & mask;
        KswRxpfUpdateLogicFlags(Context, result, Width);
        writeResult = Operation != KSWORD_ARK_RXPF_DECODE_TEST;
        break;
    case KSWORD_ARK_RXPF_DECODE_OR:
        result = (Left | Right) & mask;
        KswRxpfUpdateLogicFlags(Context, result, Width);
        break;
    default:
        return STATUS_NOT_SUPPORTED;
    }
    if (writeResult &&
        !KswRxpfWriteRegister(
            Context,
            DestinationRegister,
            Width,
            RexPresent,
            result)) {
        return STATUS_INVALID_PARAMETER;
    }
    return STATUS_SUCCESS;
}

static BOOLEAN
KswRxpfConditionTrue(
    _In_ UCHAR Condition,
    _In_ ULONGLONG Flags
    )
{
    BOOLEAN cf = (Flags & KSW_EFLAGS_CF) != 0ULL;
    BOOLEAN pf = (Flags & KSW_EFLAGS_PF) != 0ULL;
    BOOLEAN zf = (Flags & KSW_EFLAGS_ZF) != 0ULL;
    BOOLEAN sf = (Flags & KSW_EFLAGS_SF) != 0ULL;
    BOOLEAN of = (Flags & KSW_EFLAGS_OF) != 0ULL;

    /* Evaluate all sixteen architectural Jcc condition encodings. */
    switch (Condition & 0x0FU) {
    case 0x0U: return of;
    case 0x1U: return !of;
    case 0x2U: return cf;
    case 0x3U: return !cf;
    case 0x4U: return zf;
    case 0x5U: return !zf;
    case 0x6U: return cf || zf;
    case 0x7U: return !cf && !zf;
    case 0x8U: return sf;
    case 0x9U: return !sf;
    case 0xAU: return pf;
    case 0xBU: return !pf;
    case 0xCU: return sf != of;
    case 0xDU: return sf == of;
    case 0xEU: return zf || (sf != of);
    default: return !zf && (sf == of);
    }
}

static NTSTATUS
KswRxpfDecodeLea(
    _Inout_ PKSW_RXPF_DECODER Decoder,
    _In_ UCHAR ModRm
    )
{
    PKSW_RXPF_EMULATION_CONTEXT context = Decoder->Context;
    ULONG mod = (ModRm >> 6) & 3U;
    ULONG destination = ((ModRm >> 3) & 7U) |
        (((Decoder->Rex >> 2) & 1U) << 3);
    ULONG rm = ModRm & 7U;
    ULONG width = KswRxpfOperandWidth(Decoder, FALSE);
    ULONGLONG base = 0ULL;
    ULONGLONG index = 0ULL;
    ULONGLONG displacementRaw = 0ULL;
    LONGLONG displacement = 0LL;
    ULONG scale = 1UL;
    BOOLEAN ripRelative = FALSE;
    BOOLEAN basePresent = TRUE;

    /* LEA requires a memory encoding but never dereferences the address. */
    if (mod == 3UL) {
        return STATUS_NOT_SUPPORTED;
    }
    if (rm == 4UL) {
        UCHAR sib = 0U;
        ULONG sibIndex = 0UL;
        ULONG sibBase = 0UL;

        if (!KswRxpfReadByte(Decoder, &sib)) {
            return STATUS_BUFFER_TOO_SMALL;
        }
        scale = 1UL << ((sib >> 6) & 3U);
        sibIndex = ((sib >> 3) & 7U) |
            (((Decoder->Rex >> 1) & 1U) << 3);
        sibBase = (sib & 7U) | ((Decoder->Rex & 1U) << 3);
        if (((sib >> 3) & 7U) != 4U ||
            ((Decoder->Rex >> 1) & 1U) != 0U) {
            index = KswRxpfReadRegister(context, sibIndex, 64UL, TRUE);
        }
        if (mod == 0UL && (sib & 7U) == 5U) {
            basePresent = FALSE;
        } else {
            base = KswRxpfReadRegister(context, sibBase, 64UL, TRUE);
        }
    } else if (mod == 0UL && rm == 5UL) {
        ripRelative = TRUE;
        basePresent = FALSE;
    } else {
        ULONG baseRegister = rm | ((Decoder->Rex & 1U) << 3);

        base = KswRxpfReadRegister(context, baseRegister, 64UL, TRUE);
    }

    /* Consume the displacement selected by ModRM/SIB addressing. */
    if (mod == 1UL) {
        if (!KswRxpfReadImmediate(Decoder, 1UL, &displacementRaw)) {
            return STATUS_BUFFER_TOO_SMALL;
        }
        displacement = (LONGLONG)KswRxpfSignExtend(displacementRaw, 8UL);
    } else if (mod == 2UL || ripRelative || !basePresent) {
        if (!KswRxpfReadImmediate(Decoder, 4UL, &displacementRaw)) {
            return STATUS_BUFFER_TOO_SMALL;
        }
        displacement = (LONGLONG)KswRxpfSignExtend(displacementRaw, 32UL);
    }
    if (ripRelative) {
        base = context->Frame->Rip + Decoder->Cursor;
    }
    base = base + (index * scale) + (ULONGLONG)displacement;
    if (!KswRxpfIsCanonical(base) ||
        !KswRxpfWriteRegister(
            context,
            destination,
            width,
            Decoder->RexPresent,
            base)) {
        return STATUS_ACCESS_VIOLATION;
    }
    context->DecodedInstruction = KSWORD_ARK_RXPF_DECODE_LEA;
    return STATUS_SUCCESS;
}

static NTSTATUS
KswRxpfDecodeRegisterBinary(
    _Inout_ PKSW_RXPF_DECODER Decoder,
    _In_ UCHAR Opcode,
    _In_ ULONG Operation,
    _In_ BOOLEAN ByteOperation,
    _In_ BOOLEAN ReverseOperands
    )
{
    UCHAR modRm = 0U;
    ULONG mod = 0UL;
    ULONG reg = 0UL;
    ULONG rm = 0UL;
    ULONG destination = 0UL;
    ULONG source = 0UL;
    ULONG width = KswRxpfOperandWidth(Decoder, ByteOperation);
    ULONGLONG left = 0ULL;
    ULONGLONG right = 0ULL;

    UNREFERENCED_PARAMETER(Opcode);
    if (!KswRxpfReadByte(Decoder, &modRm)) {
        return STATUS_BUFFER_TOO_SMALL;
    }
    mod = (modRm >> 6) & 3U;
    reg = ((modRm >> 3) & 7U) |
        (((Decoder->Rex >> 2) & 1U) << 3);
    rm = (modRm & 7U) | ((Decoder->Rex & 1U) << 3);
    if (mod != 3UL) {
        return STATUS_NOT_SUPPORTED;
    }
    destination = ReverseOperands ? reg : rm;
    source = ReverseOperands ? rm : reg;
    left = KswRxpfReadRegister(
        Decoder->Context,
        destination,
        width,
        Decoder->RexPresent);
    right = KswRxpfReadRegister(
        Decoder->Context,
        source,
        width,
        Decoder->RexPresent);
    Decoder->Context->DecodedInstruction = Operation;
    return KswRxpfApplyBinary(
        Decoder->Context,
        Operation,
        destination,
        width,
        Decoder->RexPresent,
        left,
        right);
}

static NTSTATUS
KswRxpfDecodeImmediateGroup(
    _Inout_ PKSW_RXPF_DECODER Decoder,
    _In_ UCHAR Opcode
    )
{
    UCHAR modRm = 0U;
    ULONG extension = 0UL;
    ULONG destination = 0UL;
    ULONG width = KswRxpfOperandWidth(Decoder, Opcode == 0x80U);
    ULONG operation = KSWORD_ARK_RXPF_DECODE_NONE;
    ULONG immediateBytes = 0UL;
    ULONGLONG immediate = 0ULL;
    ULONGLONG left = 0ULL;

    if (!KswRxpfReadByte(Decoder, &modRm)) {
        return STATUS_BUFFER_TOO_SMALL;
    }
    if (((modRm >> 6) & 3U) != 3U) {
        return STATUS_NOT_SUPPORTED;
    }
    extension = (modRm >> 3) & 7U;
    destination = (modRm & 7U) | ((Decoder->Rex & 1U) << 3);
    switch (extension) {
    case 0UL: operation = KSWORD_ARK_RXPF_DECODE_ADD; break;
    case 1UL: operation = KSWORD_ARK_RXPF_DECODE_OR; break;
    case 4UL: operation = KSWORD_ARK_RXPF_DECODE_AND; break;
    case 5UL: operation = KSWORD_ARK_RXPF_DECODE_SUB; break;
    case 6UL: operation = KSWORD_ARK_RXPF_DECODE_XOR; break;
    case 7UL: operation = KSWORD_ARK_RXPF_DECODE_CMP; break;
    default: return STATUS_NOT_SUPPORTED;
    }
    immediateBytes = Opcode == 0x81U
        ? (width == 16UL ? 2UL : 4UL)
        : 1UL;
    if (!KswRxpfReadImmediate(Decoder, immediateBytes, &immediate)) {
        return STATUS_BUFFER_TOO_SMALL;
    }
    if (Opcode == 0x83U || (Opcode == 0x81U && width == 64UL)) {
        immediate = KswRxpfSignExtend(
            immediate,
            Opcode == 0x83U ? 8UL : 32UL);
    }
    left = KswRxpfReadRegister(
        Decoder->Context,
        destination,
        width,
        Decoder->RexPresent);
    Decoder->Context->DecodedInstruction = operation;
    return KswRxpfApplyBinary(
        Decoder->Context,
        operation,
        destination,
        width,
        Decoder->RexPresent,
        left,
        immediate);
}

static NTSTATUS
KswRxpfDecodeMovModRm(
    _Inout_ PKSW_RXPF_DECODER Decoder,
    _In_ UCHAR Opcode
    )
{
    UCHAR modRm = 0U;
    ULONG reg = 0UL;
    ULONG rm = 0UL;
    ULONG destination = 0UL;
    ULONG source = 0UL;
    ULONG width = KswRxpfOperandWidth(
        Decoder,
        Opcode == 0x88U || Opcode == 0x8AU);
    ULONGLONG value = 0ULL;

    if (!KswRxpfReadByte(Decoder, &modRm)) {
        return STATUS_BUFFER_TOO_SMALL;
    }
    if (((modRm >> 6) & 3U) != 3U) {
        return STATUS_NOT_SUPPORTED;
    }
    reg = ((modRm >> 3) & 7U) |
        (((Decoder->Rex >> 2) & 1U) << 3);
    rm = (modRm & 7U) | ((Decoder->Rex & 1U) << 3);
    destination = (Opcode == 0x8BU || Opcode == 0x8AU) ? reg : rm;
    source = (Opcode == 0x8BU || Opcode == 0x8AU) ? rm : reg;
    value = KswRxpfReadRegister(
        Decoder->Context,
        source,
        width,
        Decoder->RexPresent);
    if (!KswRxpfWriteRegister(
            Decoder->Context,
            destination,
            width,
            Decoder->RexPresent,
            value)) {
        return STATUS_INVALID_PARAMETER;
    }
    Decoder->Context->DecodedInstruction = KSWORD_ARK_RXPF_DECODE_MOV;
    return STATUS_SUCCESS;
}

static NTSTATUS
KswRxpfDecodeMovImmediateModRm(
    _Inout_ PKSW_RXPF_DECODER Decoder,
    _In_ UCHAR Opcode
    )
{
    UCHAR modRm = 0U;
    ULONG destination = 0UL;
    ULONG width = KswRxpfOperandWidth(Decoder, Opcode == 0xC6U);
    ULONG immediateBytes = width == 8UL ? 1UL :
        (width == 16UL ? 2UL : 4UL);
    ULONGLONG immediate = 0ULL;

    if (!KswRxpfReadByte(Decoder, &modRm) ||
        ((modRm >> 6) & 3U) != 3U ||
        ((modRm >> 3) & 7U) != 0U) {
        return STATUS_NOT_SUPPORTED;
    }
    destination = (modRm & 7U) | ((Decoder->Rex & 1U) << 3);
    if (!KswRxpfReadImmediate(Decoder, immediateBytes, &immediate)) {
        return STATUS_BUFFER_TOO_SMALL;
    }
    if (width == 64UL) {
        immediate = KswRxpfSignExtend(immediate, 32UL);
    }
    if (!KswRxpfWriteRegister(
            Decoder->Context,
            destination,
            width,
            Decoder->RexPresent,
            immediate)) {
        return STATUS_INVALID_PARAMETER;
    }
    Decoder->Context->DecodedInstruction = KSWORD_ARK_RXPF_DECODE_MOV;
    return STATUS_SUCCESS;
}

static NTSTATUS
KswRxpfDecodeTestImmediate(
    _Inout_ PKSW_RXPF_DECODER Decoder,
    _In_ UCHAR Opcode
    )
{
    UCHAR modRm = 0U;
    ULONG source = 0UL;
    ULONG width = KswRxpfOperandWidth(Decoder, Opcode == 0xF6U);
    ULONG immediateBytes = width == 8UL ? 1UL :
        (width == 16UL ? 2UL : 4UL);
    ULONGLONG immediate = 0ULL;
    ULONGLONG left = 0ULL;

    if (!KswRxpfReadByte(Decoder, &modRm) ||
        ((modRm >> 6) & 3U) != 3U ||
        ((modRm >> 3) & 7U) != 0U) {
        return STATUS_NOT_SUPPORTED;
    }
    source = (modRm & 7U) | ((Decoder->Rex & 1U) << 3);
    if (!KswRxpfReadImmediate(Decoder, immediateBytes, &immediate)) {
        return STATUS_BUFFER_TOO_SMALL;
    }
    if (width == 64UL) {
        immediate = KswRxpfSignExtend(immediate, 32UL);
    }
    left = KswRxpfReadRegister(
        Decoder->Context,
        source,
        width,
        Decoder->RexPresent);
    Decoder->Context->DecodedInstruction = KSWORD_ARK_RXPF_DECODE_TEST;
    return KswRxpfApplyBinary(
        Decoder->Context,
        KSWORD_ARK_RXPF_DECODE_TEST,
        source,
        width,
        Decoder->RexPresent,
        left,
        immediate);
}

static NTSTATUS
KswRxpfDecodeControlFlow(
    _Inout_ PKSW_RXPF_DECODER Decoder,
    _In_ UCHAR Opcode,
    _In_ BOOLEAN TwoByteOpcode,
    _In_ UCHAR SecondOpcode
    )
{
    PKSW_RXPF_EMULATION_CONTEXT context = Decoder->Context;
    ULONGLONG immediate = 0ULL;
    ULONGLONG nextRip = 0ULL;
    ULONGLONG target = 0ULL;
    LONGLONG displacement = 0LL;

    /* Decode relative JMP/CALL/Jcc displacements before calculating next RIP. */
    if (Opcode == 0xEBU ||
        (!TwoByteOpcode && Opcode >= 0x70U && Opcode <= 0x7FU)) {
        if (!KswRxpfReadImmediate(Decoder, 1UL, &immediate)) {
            return STATUS_BUFFER_TOO_SMALL;
        }
        displacement = (LONGLONG)KswRxpfSignExtend(immediate, 8UL);
    } else {
        if (!KswRxpfReadImmediate(Decoder, 4UL, &immediate)) {
            return STATUS_BUFFER_TOO_SMALL;
        }
        displacement = (LONGLONG)KswRxpfSignExtend(immediate, 32UL);
    }
    nextRip = context->Frame->Rip + Decoder->Cursor;
    target = nextRip + (ULONGLONG)displacement;
    if (!KswRxpfIsCanonicalKernelTarget(target)) {
        return STATUS_ACCESS_VIOLATION;
    }

    /* CALL first writes the architectural return address to the kernel stack. */
    if (Opcode == 0xE8U) {
        ULONGLONG newRsp = context->LogicalRsp - sizeof(ULONGLONG);

        if (newRsp > context->LogicalRsp ||
            !KswRxpfResumeScratchValid(context, newRsp) ||
            !KswRxpfStackWrite(
                context,
                newRsp,
                &nextRip,
                sizeof(nextRip))) {
            return STATUS_STACK_OVERFLOW;
        }
        context->LogicalRsp = newRsp;
        context->Frame->Rip = target;
        context->DecodedInstruction = KSWORD_ARK_RXPF_DECODE_CALL;
        return STATUS_SUCCESS;
    }
    if (TwoByteOpcode || (Opcode >= 0x70U && Opcode <= 0x7FU)) {
        UCHAR condition = TwoByteOpcode
            ? (UCHAR)(SecondOpcode & 0x0FU)
            : (UCHAR)(Opcode & 0x0FU);

        context->Frame->Rip = KswRxpfConditionTrue(
            condition,
            context->Frame->Rflags) ? target : nextRip;
        context->DecodedInstruction = KSWORD_ARK_RXPF_DECODE_JCC;
        return STATUS_SUCCESS;
    }
    context->Frame->Rip = target;
    context->DecodedInstruction = KSWORD_ARK_RXPF_DECODE_JMP;
    return STATUS_SUCCESS;
}

static NTSTATUS
KswRxpfDecodeStackRegister(
    _Inout_ PKSW_RXPF_DECODER Decoder,
    _In_ UCHAR Opcode
    )
{
    PKSW_RXPF_EMULATION_CONTEXT context = Decoder->Context;
    ULONG registerCode = (Opcode & 7U) |
        ((Decoder->Rex & 1U) << 3);
    ULONG width = Decoder->OperandSize16 ? 16UL : 64UL;
    ULONG byteCount = width / 8UL;
    ULONGLONG value = 0ULL;

    /* PUSH writes before publishing the decremented logical RSP. */
    if (Opcode >= 0x50U && Opcode <= 0x57U) {
        ULONGLONG newRsp = context->LogicalRsp - byteCount;

        value = KswRxpfReadRegister(
            context,
            registerCode,
            width,
            Decoder->RexPresent);
        if (newRsp > context->LogicalRsp ||
            !KswRxpfResumeScratchValid(context, newRsp) ||
            !KswRxpfStackWrite(context, newRsp, &value, byteCount)) {
            return STATUS_STACK_OVERFLOW;
        }
        context->LogicalRsp = newRsp;
        context->DecodedInstruction = KSWORD_ARK_RXPF_DECODE_PUSH;
        return STATUS_SUCCESS;
    }

    /* POP SP/ESP/RSP can select an arbitrary handler-overlapping stack. */
    if (registerCode == 4UL) {
        return STATUS_NOT_SUPPORTED;
    }

    /* POP reads from old RSP, increments it, then applies the register write. */
    if (!KswRxpfStackRead(
            context,
            context->LogicalRsp,
            &value,
            byteCount)) {
        return STATUS_ACCESS_VIOLATION;
    }
    context->LogicalRsp += byteCount;
    if (!KswRxpfWriteRegister(
            context,
            registerCode,
            width,
            Decoder->RexPresent,
            value)) {
        return STATUS_INVALID_PARAMETER;
    }
    context->DecodedInstruction = KSWORD_ARK_RXPF_DECODE_POP;
    return STATUS_SUCCESS;
}

static NTSTATUS
KswRxpfDecodePushImmediate(
    _Inout_ PKSW_RXPF_DECODER Decoder,
    _In_ UCHAR Opcode
    )
{
    PKSW_RXPF_EMULATION_CONTEXT context = Decoder->Context;
    ULONG width = Decoder->OperandSize16 ? 16UL : 64UL;
    ULONG byteCount = width / 8UL;
    ULONG immediateBytes = Opcode == 0x6AU ? 1UL :
        (Decoder->OperandSize16 ? 2UL : 4UL);
    ULONGLONG immediate = 0ULL;
    ULONGLONG newRsp = 0ULL;

    if (!KswRxpfReadImmediate(Decoder, immediateBytes, &immediate)) {
        return STATUS_BUFFER_TOO_SMALL;
    }
    immediate = KswRxpfSignExtend(
        immediate,
        immediateBytes * 8UL);
    newRsp = context->LogicalRsp - byteCount;
    if (newRsp > context->LogicalRsp ||
        !KswRxpfResumeScratchValid(context, newRsp) ||
        !KswRxpfStackWrite(context, newRsp, &immediate, byteCount)) {
        return STATUS_STACK_OVERFLOW;
    }
    context->LogicalRsp = newRsp;
    context->DecodedInstruction = KSWORD_ARK_RXPF_DECODE_PUSH;
    return STATUS_SUCCESS;
}

static NTSTATUS
KswRxpfDecodeRet(
    _Inout_ PKSW_RXPF_DECODER Decoder,
    _In_ UCHAR Opcode
    )
{
    PKSW_RXPF_EMULATION_CONTEXT context = Decoder->Context;
    ULONGLONG target = 0ULL;
    ULONGLONG stackAdjustment = sizeof(ULONGLONG);
    ULONGLONG immediate = 0ULL;

    /* RET C2 adds an unsigned 16-bit caller-pop adjustment after the target. */
    if (Opcode == 0xC2U) {
        if (!KswRxpfReadImmediate(Decoder, 2UL, &immediate)) {
            return STATUS_BUFFER_TOO_SMALL;
        }
        stackAdjustment += immediate & 0xFFFFULL;
    }
    if (!KswRxpfStackRead(
            context,
            context->LogicalRsp,
            &target,
            sizeof(target)) ||
        !KswRxpfIsCanonicalKernelTarget(target) ||
        context->LogicalRsp + stackAdjustment < context->LogicalRsp ||
        context->LogicalRsp + stackAdjustment > context->StackHigh) {
        return STATUS_ACCESS_VIOLATION;
    }
    context->LogicalRsp += stackAdjustment;
    context->Frame->Rip = target;
    context->DecodedInstruction = KSWORD_ARK_RXPF_DECODE_RET;
    return STATUS_SUCCESS;
}

NTSTATUS
KswRxpfX64EmulateOne(
    _Inout_ PKSW_RXPF_EMULATION_CONTEXT Context
    )
{
    KSW_RXPF_DECODER decoder;
    UCHAR opcode = 0U;
    NTSTATUS status = STATUS_NOT_SUPPORTED;
    BOOLEAN ripWasAssigned = FALSE;

    /* Validate fixed, pre-copied instruction and trap-frame inputs. */
    if (Context == NULL || Context->Frame == NULL ||
        Context->AvailableBytes == 0UL ||
        Context->AvailableBytes > KSW_RXPF_X64_MAX_INSTRUCTION_BYTES) {
        return STATUS_INVALID_PARAMETER;
    }
    Context->DecodedInstruction = KSWORD_ARK_RXPF_DECODE_NONE;
    Context->EmulationResult =
        KSWORD_ARK_RXPF_EMULATION_UNSUPPORTED_INSTRUCTION;
    Context->InstructionLength = 0UL;
    Context->Status = STATUS_NOT_SUPPORTED;
    RtlZeroMemory(&decoder, sizeof(decoder));
    decoder.Context = Context;

    /* Accept only operand-size and one final REX prefix; reject risky classes. */
    for (;;) {
        UCHAR prefix = 0U;

        if (!KswRxpfReadByte(&decoder, &prefix)) {
            status = STATUS_BUFFER_TOO_SMALL;
            goto Exit;
        }
        if (prefix == 0x66U) {
            if (decoder.OperandSize16 || decoder.RexPresent) {
                status = STATUS_NOT_SUPPORTED;
                goto Exit;
            }
            decoder.OperandSize16 = TRUE;
            continue;
        }
        if (prefix >= 0x40U && prefix <= 0x4FU) {
            if (decoder.RexPresent) {
                status = STATUS_NOT_SUPPORTED;
                goto Exit;
            }
            decoder.Rex = prefix;
            decoder.RexPresent = TRUE;
            continue;
        }
        if (prefix == 0xF0U || prefix == 0xF2U || prefix == 0xF3U ||
            prefix == 0x67U || prefix == 0x2EU || prefix == 0x36U ||
            prefix == 0x3EU || prefix == 0x26U || prefix == 0x64U ||
            prefix == 0x65U) {
            status = STATUS_NOT_SUPPORTED;
            goto Exit;
        }
        opcode = prefix;
        break;
    }

    /* Decode the bounded scalar whitelist without treating failures as NOPs. */
    if (opcode == 0x90U && !decoder.RexPresent) {
        Context->DecodedInstruction = KSWORD_ARK_RXPF_DECODE_NOP;
        status = STATUS_SUCCESS;
    } else if (opcode >= 0xB8U && opcode <= 0xBFU) {
        ULONG registerCode = (opcode & 7U) |
            ((decoder.Rex & 1U) << 3);
        ULONG width = KswRxpfOperandWidth(&decoder, FALSE);
        ULONG immediateBytes = width == 64UL ? 8UL :
            (width == 16UL ? 2UL : 4UL);
        ULONGLONG immediate = 0ULL;

        if (!KswRxpfReadImmediate(&decoder, immediateBytes, &immediate)) {
            status = STATUS_BUFFER_TOO_SMALL;
        } else if (!KswRxpfWriteRegister(
                Context,
                registerCode,
                width,
                decoder.RexPresent,
                immediate)) {
            status = STATUS_INVALID_PARAMETER;
        } else {
            Context->DecodedInstruction = KSWORD_ARK_RXPF_DECODE_MOV;
            status = STATUS_SUCCESS;
        }
    } else if (opcode >= 0xB0U && opcode <= 0xB7U) {
        ULONG registerCode = (opcode & 7U) |
            ((decoder.Rex & 1U) << 3);
        ULONGLONG immediate = 0ULL;

        if (!KswRxpfReadImmediate(&decoder, 1UL, &immediate)) {
            status = STATUS_BUFFER_TOO_SMALL;
        } else if (!KswRxpfWriteRegister(
                Context,
                registerCode,
                8UL,
                decoder.RexPresent,
                immediate)) {
            status = STATUS_INVALID_PARAMETER;
        } else {
            Context->DecodedInstruction = KSWORD_ARK_RXPF_DECODE_MOV;
            status = STATUS_SUCCESS;
        }
    } else if (opcode == 0x89U || opcode == 0x8BU ||
               opcode == 0x88U || opcode == 0x8AU) {
        status = KswRxpfDecodeMovModRm(&decoder, opcode);
    } else if (opcode == 0xC6U || opcode == 0xC7U) {
        status = KswRxpfDecodeMovImmediateModRm(&decoder, opcode);
    } else if (opcode == 0x8DU) {
        UCHAR modRm = 0U;

        if (!KswRxpfReadByte(&decoder, &modRm)) {
            status = STATUS_BUFFER_TOO_SMALL;
        } else {
            status = KswRxpfDecodeLea(&decoder, modRm);
        }
    } else if (opcode == 0x01U || opcode == 0x03U ||
               opcode == 0x00U || opcode == 0x02U) {
        status = KswRxpfDecodeRegisterBinary(
            &decoder,
            opcode,
            KSWORD_ARK_RXPF_DECODE_ADD,
            opcode == 0x00U || opcode == 0x02U,
            opcode == 0x03U || opcode == 0x02U);
    } else if (opcode == 0x29U || opcode == 0x2BU ||
               opcode == 0x28U || opcode == 0x2AU) {
        status = KswRxpfDecodeRegisterBinary(
            &decoder,
            opcode,
            KSWORD_ARK_RXPF_DECODE_SUB,
            opcode == 0x28U || opcode == 0x2AU,
            opcode == 0x2BU || opcode == 0x2AU);
    } else if (opcode == 0x31U || opcode == 0x33U ||
               opcode == 0x30U || opcode == 0x32U) {
        status = KswRxpfDecodeRegisterBinary(
            &decoder,
            opcode,
            KSWORD_ARK_RXPF_DECODE_XOR,
            opcode == 0x30U || opcode == 0x32U,
            opcode == 0x33U || opcode == 0x32U);
    } else if (opcode == 0x21U || opcode == 0x23U ||
               opcode == 0x20U || opcode == 0x22U) {
        status = KswRxpfDecodeRegisterBinary(
            &decoder,
            opcode,
            KSWORD_ARK_RXPF_DECODE_AND,
            opcode == 0x20U || opcode == 0x22U,
            opcode == 0x23U || opcode == 0x22U);
    } else if (opcode == 0x09U || opcode == 0x0BU ||
               opcode == 0x08U || opcode == 0x0AU) {
        status = KswRxpfDecodeRegisterBinary(
            &decoder,
            opcode,
            KSWORD_ARK_RXPF_DECODE_OR,
            opcode == 0x08U || opcode == 0x0AU,
            opcode == 0x0BU || opcode == 0x0AU);
    } else if (opcode == 0x39U || opcode == 0x3BU ||
               opcode == 0x38U || opcode == 0x3AU) {
        status = KswRxpfDecodeRegisterBinary(
            &decoder,
            opcode,
            KSWORD_ARK_RXPF_DECODE_CMP,
            opcode == 0x38U || opcode == 0x3AU,
            opcode == 0x3BU || opcode == 0x3AU);
    } else if (opcode == 0x85U || opcode == 0x84U) {
        status = KswRxpfDecodeRegisterBinary(
            &decoder,
            opcode,
            KSWORD_ARK_RXPF_DECODE_TEST,
            opcode == 0x84U,
            FALSE);
    } else if (opcode == 0x80U || opcode == 0x81U || opcode == 0x83U) {
        status = KswRxpfDecodeImmediateGroup(&decoder, opcode);
    } else if (opcode == 0xF6U || opcode == 0xF7U) {
        status = KswRxpfDecodeTestImmediate(&decoder, opcode);
    } else if (opcode >= 0x50U && opcode <= 0x5FU) {
        status = KswRxpfDecodeStackRegister(&decoder, opcode);
    } else if (opcode == 0x68U || opcode == 0x6AU) {
        status = KswRxpfDecodePushImmediate(&decoder, opcode);
    } else if (opcode == 0xE8U || opcode == 0xE9U ||
               opcode == 0xEBU ||
               (opcode >= 0x70U && opcode <= 0x7FU)) {
        status = KswRxpfDecodeControlFlow(
            &decoder,
            opcode,
            FALSE,
            0U);
        ripWasAssigned = NT_SUCCESS(status);
    } else if (opcode == 0x0FU) {
        UCHAR secondOpcode = 0U;

        if (!KswRxpfReadByte(&decoder, &secondOpcode)) {
            status = STATUS_BUFFER_TOO_SMALL;
        } else if (secondOpcode >= 0x80U && secondOpcode <= 0x8FU) {
            status = KswRxpfDecodeControlFlow(
                &decoder,
                opcode,
                TRUE,
                secondOpcode);
            ripWasAssigned = NT_SUCCESS(status);
        } else {
            status = STATUS_NOT_SUPPORTED;
        }
    } else if (opcode == 0xC3U || opcode == 0xC2U) {
        status = KswRxpfDecodeRet(&decoder, opcode);
        ripWasAssigned = NT_SUCCESS(status);
    } else {
        status = STATUS_NOT_SUPPORTED;
    }

Exit:
    /* Never advance RIP on unsupported, truncated, or invalid instructions. */
    if (NT_SUCCESS(status)) {
        if (!ripWasAssigned) {
            Context->Frame->Rip += decoder.Cursor;
        }
        Context->InstructionLength = decoder.Cursor;
        Context->EmulationResult = KSWORD_ARK_RXPF_EMULATION_SUCCESS;
    } else if (status == STATUS_BUFFER_TOO_SMALL) {
        Context->EmulationResult = KSWORD_ARK_RXPF_EMULATION_CROSS_PAGE;
    } else if (status == STATUS_STACK_OVERFLOW ||
               status == STATUS_ACCESS_VIOLATION) {
        Context->EmulationResult = KSWORD_ARK_RXPF_EMULATION_STACK_RANGE;
    } else {
        Context->EmulationResult =
            KSWORD_ARK_RXPF_EMULATION_UNSUPPORTED_INSTRUCTION;
    }
    Context->Status = status;
    return status;
}
