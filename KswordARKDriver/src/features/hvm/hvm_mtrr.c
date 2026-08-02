/*++

Module Name:

    hvm_mtrr.c

Abstract:

    Implements Intel SDM MTRR snapshot and overlap precedence for EPT leaves.

Environment:

    Kernel-mode Driver Framework.

--*/

#include "hvm_mtrr.h"

#if defined(_M_AMD64)
#include <intrin.h>

/* Name the MTRR capability model-specific register. */
#define KSW_IA32_MTRRCAP 0xFEUL
/* Name the MTRR default-type model-specific register. */
#define KSW_IA32_MTRR_DEF_TYPE 0x2FFUL
/* Name the first fixed 64-KiB MTRR model-specific register. */
#define KSW_IA32_MTRR_FIX64K_00000 0x250UL
/* Name the first fixed 16-KiB MTRR model-specific register. */
#define KSW_IA32_MTRR_FIX16K_80000 0x258UL
/* Name the second fixed 16-KiB MTRR model-specific register. */
#define KSW_IA32_MTRR_FIX16K_A0000 0x259UL
/* Name the first fixed four-KiB MTRR model-specific register. */
#define KSW_IA32_MTRR_FIX4K_C0000 0x268UL
/* Name the first variable MTRR base model-specific register. */
#define KSW_IA32_MTRR_PHYSBASE0 0x200UL
/* Name the first variable MTRR mask model-specific register. */
#define KSW_IA32_MTRR_PHYSMASK0 0x201UL

/* Identify the globally enabled bit in IA32_MTRR_DEF_TYPE. */
#define KSW_MTRR_DEF_ENABLE (1ULL << 11)
/* Identify the fixed-range enabled bit in IA32_MTRR_DEF_TYPE. */
#define KSW_MTRR_DEF_FIXED_ENABLE (1ULL << 10)
/* Identify the valid bit in a variable MTRR mask. */
#define KSW_MTRR_MASK_VALID (1ULL << 11)

/* Name the Intel uncacheable memory type. */
#define KSW_MTRR_TYPE_UC 0U
/* Name the Intel write-through memory type. */
#define KSW_MTRR_TYPE_WT 4U
/* Name the Intel write-protected memory type. */
#define KSW_MTRR_TYPE_WP 5U
/* Name the Intel write-back memory type. */
#define KSW_MTRR_TYPE_WB 6U

/* Resolve one fixed-range type byte below one MiB. */
static UCHAR
KswordARKHvmMtrrResolveFixed(
    _In_ const KSW_HVM_MTRR_STATE* State,
    _In_ ULONGLONG PhysicalAddress
    )
{
    ULONG index = 0UL;

    /* Select one of the eight fixed 64-KiB records below 512 KiB. */
    if (PhysicalAddress < 0x80000ULL) {
        /* Convert the address to the fixed-type array index. */
        index = (ULONG)(PhysicalAddress >> 16);
    /* Select one of the sixteen fixed 16-KiB records below 768 KiB. */
    } else if (PhysicalAddress < 0xC0000ULL) {
        /* Convert the address to the fixed-type array index. */
        index = 8UL +
            (ULONG)((PhysicalAddress - 0x80000ULL) >> 14);
    /* Select one of the sixty-four fixed four-KiB records below one MiB. */
    } else {
        /* Convert the address to the fixed-type array index. */
        index = 24UL +
            (ULONG)((PhysicalAddress - 0xC0000ULL) >> 12);
    }
    /* Return the byte captured from the corresponding fixed-range MSR. */
    return State->FixedTypes[index];
}

/* Resolve Intel overlap precedence for two simultaneous memory types. */
static UCHAR
KswordARKHvmMtrrCombineTypes(
    _In_ UCHAR First,
    _In_ UCHAR Second
    )
{
    /* Preserve identical memory types without degradation. */
    if (First == Second) {
        /* Return the common memory type. */
        return First;
    }
    /* Uncacheable takes precedence over every other memory type. */
    if (First == KSW_MTRR_TYPE_UC ||
        Second == KSW_MTRR_TYPE_UC) {
        /* Return the architecturally dominant uncacheable type. */
        return KSW_MTRR_TYPE_UC;
    }
    /* The architecturally defined WB plus WT overlap resolves to WT. */
    if ((First == KSW_MTRR_TYPE_WB &&
         Second == KSW_MTRR_TYPE_WT) ||
        (First == KSW_MTRR_TYPE_WT &&
         Second == KSW_MTRR_TYPE_WB)) {
        /* Return the defined write-through overlap result. */
        return KSW_MTRR_TYPE_WT;
    }
    /* Conservatively degrade every undefined overlap to uncacheable. */
    return KSW_MTRR_TYPE_UC;
}

/* Resolve the effective MTRR type at one physical address. */
static UCHAR
KswordARKHvmMtrrResolveAddress(
    _In_ const KSW_HVM_MTRR_STATE* State,
    _In_ ULONGLONG PhysicalAddress
    )
{
    ULONG index = 0UL;
    UCHAR resolvedType = KSW_MTRR_TYPE_UC;
    BOOLEAN matched = FALSE;

    /* Disabled MTRRs require conservative uncacheable EPT mappings. */
    if (!State->Enabled) {
        /* Return uncacheable without consulting stale range registers. */
        return KSW_MTRR_TYPE_UC;
    }
    /* Fixed ranges override variable ranges below one MiB when enabled. */
    if (State->FixedEnabled &&
        PhysicalAddress < 0x100000ULL) {
        /* Return the exact fixed-range type. */
        return KswordARKHvmMtrrResolveFixed(
            State,
            PhysicalAddress);
    }
    /* Combine every variable MTRR that contains the target address. */
    for (index = 0UL;
         index < State->VariableCount;
         ++index) {
        const KSW_HVM_MTRR_RANGE* range =
            &State->Variable[index];

        /* Skip disabled variable MTRR records. */
        if (range->Valid == 0U) {
            /* Continue to the next captured variable range. */
            continue;
        }
        /* Skip ranges that do not contain the target address. */
        if (PhysicalAddress < range->Base ||
            PhysicalAddress >= range->End) {
            /* Continue to the next captured variable range. */
            continue;
        }
        /* Initialize the overlap accumulator from the first matching range. */
        if (!matched) {
            /* Preserve the first matching memory type. */
            resolvedType = range->Type;
            /* Publish that later matches require precedence combination. */
            matched = TRUE;
        } else {
            /* Apply Intel overlap precedence to the accumulated type. */
            resolvedType = KswordARKHvmMtrrCombineTypes(
                resolvedType,
                range->Type);
        }
    }
    /* Use the default type when no variable range matched. */
    if (!matched) {
        /* Return the default memory type captured from IA32_MTRR_DEF_TYPE. */
        return State->DefaultType;
    }
    /* Return the combined variable-range result. */
    return resolvedType;
}

/* Capture fixed-range MTRR bytes in physical-address order. */
static VOID
KswordARKHvmMtrrCaptureFixed(
    _Out_writes_(88) UCHAR* FixedTypes
    )
{
    ULONGLONG value = 0ULL;
    ULONG byteIndex = 0UL;
    ULONG registerIndex = 0UL;

    /* Capture the eight 64-KiB type bytes below 512 KiB. */
    value = __readmsr(KSW_IA32_MTRR_FIX64K_00000);
    /* Copy each fixed type byte in ascending physical order. */
    for (byteIndex = 0UL; byteIndex < 8UL; ++byteIndex) {
        /* Extract one fixed-range memory type. */
        FixedTypes[byteIndex] =
            (UCHAR)(value >> (byteIndex * 8UL));
    }
    /* Capture the first eight 16-KiB type bytes. */
    value = __readmsr(KSW_IA32_MTRR_FIX16K_80000);
    /* Copy each fixed type byte in ascending physical order. */
    for (byteIndex = 0UL; byteIndex < 8UL; ++byteIndex) {
        /* Extract one fixed-range memory type. */
        FixedTypes[8UL + byteIndex] =
            (UCHAR)(value >> (byteIndex * 8UL));
    }
    /* Capture the second eight 16-KiB type bytes. */
    value = __readmsr(KSW_IA32_MTRR_FIX16K_A0000);
    /* Copy each fixed type byte in ascending physical order. */
    for (byteIndex = 0UL; byteIndex < 8UL; ++byteIndex) {
        /* Extract one fixed-range memory type. */
        FixedTypes[16UL + byteIndex] =
            (UCHAR)(value >> (byteIndex * 8UL));
    }
    /* Capture the eight fixed four-KiB registers covering 768 KiB to one MiB. */
    for (registerIndex = 0UL;
         registerIndex < 8UL;
         ++registerIndex) {
        /* Read one fixed four-KiB MTRR register. */
        value = __readmsr(
            KSW_IA32_MTRR_FIX4K_C0000 + registerIndex);
        /* Copy its eight type bytes in ascending physical order. */
        for (byteIndex = 0UL; byteIndex < 8UL; ++byteIndex) {
            /* Extract one fixed-range memory type. */
            FixedTypes[24UL +
                (registerIndex * 8UL) +
                byteIndex] =
                (UCHAR)(value >> (byteIndex * 8UL));
        }
    }
}

NTSTATUS
KswordARKHvmMtrrCapture(
    _Out_ KSW_HVM_MTRR_STATE* State
    )
{
    int registers[4] = { 0 };
    ULONGLONG capability = 0ULL;
    ULONGLONG defaultType = 0ULL;
    ULONGLONG physicalMask = 0ULL;
    ULONG physicalBits = 0UL;
    ULONG variableCount = 0UL;
    ULONG index = 0UL;

    /* Reject a missing output before reading privileged processor state. */
    if (State == NULL) {
        /* Return an exact caller-contract failure. */
        return STATUS_INVALID_PARAMETER;
    }
    /* Initialize the complete snapshot before privileged reads begin. */
    RtlZeroMemory(State, sizeof(*State));
    /* Protect every MTRR read from virtual-CPU faults. */
    __try {
        /* Read MTRR count and fixed-range capability. */
        capability = __readmsr(KSW_IA32_MTRRCAP);
        /* Read global enable, fixed enable, and default type. */
        defaultType = __readmsr(KSW_IA32_MTRR_DEF_TYPE);
        /* Read the physical-address width used to decode variable masks. */
        __cpuid(registers, (int)0x80000008UL);
        /* Extract the physical-address width from CPUID. */
        physicalBits = (ULONG)registers[0] & 0xFFUL;
        /* Reject nonsensical widths before shifting a 64-bit mask. */
        if (physicalBits < 36UL ||
            physicalBits > 52UL) {
            /* Return an explicit processor-capability failure. */
            return STATUS_NOT_SUPPORTED;
        }
        /* Build the page-aligned physical-address mask. */
        physicalMask =
            ((1ULL << physicalBits) - 1ULL) &
            KSW_EPT_PHYSICAL_MASK;
        /* Publish the global MTRR enable state. */
        State->Enabled =
            (BOOLEAN)(
                (defaultType & KSW_MTRR_DEF_ENABLE) != 0ULL);
        /* Publish fixed-range enable only when the CPU advertises fixed MTRRs. */
        State->FixedEnabled =
            (BOOLEAN)(
                State->Enabled &&
                (capability & (1ULL << 8)) != 0ULL &&
                (defaultType &
                    KSW_MTRR_DEF_FIXED_ENABLE) != 0ULL);
        /* Preserve the default memory-type encoding. */
        State->DefaultType = (UCHAR)(defaultType & 0xFFULL);
        /* Bound the low-byte variable-range count to local storage. */
        variableCount = (ULONG)(capability & 0xFFULL);
        /* Clamp malicious or future counts to the fixed runtime capacity. */
        if (variableCount > KSW_HVM_MAX_VARIABLE_MTRRS) {
            /* Retain only the locally representable variable ranges. */
            variableCount = KSW_HVM_MAX_VARIABLE_MTRRS;
        }
        /* Publish the bounded variable MTRR count. */
        State->VariableCount = (UCHAR)variableCount;
        /* Capture fixed-range bytes only when their enable state is active. */
        if (State->FixedEnabled) {
            /* Read all eleven fixed-range MTRR registers. */
            KswordARKHvmMtrrCaptureFixed(State->FixedTypes);
        }
        /* Decode every variable range into a bounded base and end. */
        for (index = 0UL; index < variableCount; ++index) {
            ULONGLONG baseValue = 0ULL;
            ULONGLONG maskValue = 0ULL;
            ULONGLONG rangeMask = 0ULL;
            ULONGLONG byteCount = 0ULL;
            KSW_HVM_MTRR_RANGE* range =
                &State->Variable[index];

            /* Read one variable-range base register. */
            baseValue = __readmsr(
                KSW_IA32_MTRR_PHYSBASE0 +
                (index * 2UL));
            /* Read the paired variable-range mask register. */
            maskValue = __readmsr(
                KSW_IA32_MTRR_PHYSMASK0 +
                (index * 2UL));
            /* Skip address arithmetic for a disabled range. */
            if ((maskValue & KSW_MTRR_MASK_VALID) == 0ULL) {
                /* Leave the zeroed record explicitly disabled. */
                continue;
            }
            /* Isolate the physical-address mask bits. */
            rangeMask = maskValue & physicalMask;
            /* Derive the power-of-two range size from the address mask. */
            byteCount =
                ((~rangeMask) & physicalMask) +
                KSW_HVM_PAGE_BYTES;
            /* Reject wrapped or sub-page variable ranges conservatively. */
            if (byteCount < KSW_HVM_PAGE_BYTES) {
                /* Leave the zeroed record explicitly disabled. */
                continue;
            }
            /* Decode the range base under its own mask. */
            range->Base =
                (baseValue & physicalMask) &
                rangeMask;
            /* Saturate an impossible wrapped end at the supported physical mask. */
            if (range->Base > MAXULONGLONG - byteCount) {
                /* Publish the exclusive architectural physical limit. */
                range->End = physicalMask +
                    KSW_HVM_PAGE_BYTES;
            } else {
                /* Publish the ordinary exclusive range end. */
                range->End = range->Base + byteCount;
            }
            /* Preserve the low-byte Intel memory-type encoding. */
            range->Type = (UCHAR)(baseValue & 0xFFULL);
            /* Publish the successfully decoded range. */
            range->Valid = 1U;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        /* Return the exact privileged-instruction exception. */
        return GetExceptionCode();
    }
    /* Publish a complete immutable MTRR snapshot. */
    return STATUS_SUCCESS;
}

UCHAR
KswordARKHvmMtrrResolveRangeType(
    _In_ const KSW_HVM_MTRR_STATE* State,
    _In_ ULONGLONG PhysicalAddress,
    _In_ ULONGLONG ByteCount
    )
{
    UCHAR resolvedType = KSW_MTRR_TYPE_UC;
    ULONGLONG rangeEnd = 0ULL;
    ULONG index = 0UL;

    /* Reject invalid or overflowing ranges as uncacheable. */
    if (State == NULL ||
        ByteCount == 0ULL ||
        PhysicalAddress > MAXULONGLONG - ByteCount) {
        /* Return the fail-closed uncacheable type. */
        return KSW_MTRR_TYPE_UC;
    }
    /* Resolve the first byte as the candidate uniform type. */
    resolvedType = KswordARKHvmMtrrResolveAddress(
        State,
        PhysicalAddress);
    /* Compute the exclusive range end after overflow validation. */
    rangeEnd = PhysicalAddress + ByteCount;
    /* Require the last byte to have the same effective type. */
    if (KswordARKHvmMtrrResolveAddress(
            State,
            rangeEnd - 1ULL) != resolvedType) {
        /* Degrade a nonuniform range to uncacheable. */
        return KSW_MTRR_TYPE_UC;
    }
    /* Check every fixed-range boundary that intersects the target range. */
    if (State->FixedEnabled &&
        PhysicalAddress < 0x100000ULL) {
        ULONGLONG boundary = 0ULL;

        /* Start at the next four-KiB boundary within the fixed region. */
        boundary =
            (PhysicalAddress + KSW_HVM_PAGE_BYTES) &
            ~(KSW_HVM_PAGE_BYTES - 1ULL);
        /* Compare every fixed-range boundary without reading MSRs again. */
        while (boundary < rangeEnd &&
               boundary < 0x100000ULL) {
            /* Degrade the full leaf when either side changes type. */
            if (KswordARKHvmMtrrResolveAddress(
                    State,
                    boundary) != resolvedType) {
                /* Return the conservative uncacheable type. */
                return KSW_MTRR_TYPE_UC;
            }
            /* Advance to the next fixed four-KiB boundary. */
            boundary += KSW_HVM_PAGE_BYTES;
        }
    }
    /* Check both sides of every variable MTRR boundary inside the range. */
    for (index = 0UL;
         index < State->VariableCount;
         ++index) {
        const KSW_HVM_MTRR_RANGE* variable =
            &State->Variable[index];

        /* Skip disabled variable records. */
        if (variable->Valid == 0U) {
            /* Continue to the next captured variable range. */
            continue;
        }
        /* Check a variable-range start boundary inside the target range. */
        if (variable->Base > PhysicalAddress &&
            variable->Base < rangeEnd &&
            KswordARKHvmMtrrResolveAddress(
                State,
                variable->Base) != resolvedType) {
            /* Return the conservative uncacheable type. */
            return KSW_MTRR_TYPE_UC;
        }
        /* Check the first byte after a variable-range end boundary. */
        if (variable->End > PhysicalAddress &&
            variable->End < rangeEnd &&
            KswordARKHvmMtrrResolveAddress(
                State,
                variable->End) != resolvedType) {
            /* Return the conservative uncacheable type. */
            return KSW_MTRR_TYPE_UC;
        }
    }
    /* EPT does not encode Intel reserved types two and three. */
    if (resolvedType == 2U ||
        resolvedType == 3U ||
        resolvedType > KSW_MTRR_TYPE_WB) {
        /* Return the conservative uncacheable type. */
        return KSW_MTRR_TYPE_UC;
    }
    /* Return the uniform EPT-compatible memory type. */
    return resolvedType;
}

#else

NTSTATUS
KswordARKHvmMtrrCapture(
    _Out_ KSW_HVM_MTRR_STATE* State
    )
{
    /* Clear a supplied snapshot before returning the architecture boundary. */
    if (State != NULL) {
        /* Initialize the complete unsupported snapshot. */
        RtlZeroMemory(State, sizeof(*State));
    }
    /* Return the explicit non-x64 architecture boundary. */
    return STATUS_NOT_SUPPORTED;
}

UCHAR
KswordARKHvmMtrrResolveRangeType(
    _In_ const KSW_HVM_MTRR_STATE* State,
    _In_ ULONGLONG PhysicalAddress,
    _In_ ULONGLONG ByteCount
    )
{
    /* Keep the non-x64 build warning-free. */
    UNREFERENCED_PARAMETER(State);
    /* Keep the non-x64 build warning-free. */
    UNREFERENCED_PARAMETER(PhysicalAddress);
    /* Keep the non-x64 build warning-free. */
    UNREFERENCED_PARAMETER(ByteCount);
    /* Return conservative uncacheable on unsupported architectures. */
    return 0U;
}

#endif
