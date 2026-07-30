/*++

Module Name:

    hvm_runtime.c

Abstract:

    Owns the VT-x capability snapshot, per-processor VMX regions, a RAM-only
    EPT identity map, VMXON/VMXOFF validation, and the serialized lifecycle for
    an explicitly confirmed one-shot VMCALL guest.

Environment:

    Kernel-mode Driver Framework.

--*/

#include "hvm_runtime.h"
#include "hvm_guest.h"

#if defined(_M_AMD64)
#include <intrin.h>
#endif

#define KSW_HVM_PAGE_BYTES 0x1000ULL
#define KSW_HVM_LARGE_PAGE_BYTES 0x200000ULL
#define KSW_HVM_ONE_GIB 0x40000000ULL
#define KSW_HVM_ONE_512_GIB 0x8000000000ULL
#define KSW_HVM_MAX_PML4_ENTRIES 16UL
#define KSW_HVM_MAX_EPT_PAGES \
    (1UL + KSW_HVM_MAX_PML4_ENTRIES + \
        (KSW_HVM_MAX_PML4_ENTRIES * 512UL))
#define KSW_HVM_MAX_MAPPED_PHYSICAL \
    (KSW_HVM_ONE_512_GIB * KSW_HVM_MAX_PML4_ENTRIES)

#define KSW_IA32_FEATURE_CONTROL 0x3AUL
#define KSW_IA32_VMX_BASIC 0x480UL
#define KSW_IA32_VMX_CR0_FIXED0 0x486UL
#define KSW_IA32_VMX_CR0_FIXED1 0x487UL
#define KSW_IA32_VMX_CR4_FIXED0 0x488UL
#define KSW_IA32_VMX_CR4_FIXED1 0x489UL
#define KSW_IA32_VMX_PROCBASED_CTLS2 0x48BUL
#define KSW_IA32_VMX_EPT_VPID_CAP 0x48CUL

#define KSW_CR4_VMXE (1ULL << 13)

#define KSW_EPT_READ 0x1ULL
#define KSW_EPT_WRITE 0x2ULL
#define KSW_EPT_EXECUTE 0x4ULL
#define KSW_EPT_MEMORY_TYPE_WB (6ULL << 3)
#define KSW_EPT_LARGE_PAGE (1ULL << 7)
#define KSW_EPT_PHYSICAL_MASK 0x000FFFFFFFFFF000ULL

#define KSW_EPT_CAP_PAGE_WALK_4 (1ULL << 6)
#define KSW_EPT_CAP_WB (1ULL << 14)
#define KSW_EPT_CAP_2MB (1ULL << 16)
#define KSW_EPT_CAP_INVEPT (1ULL << 20)
#define KSW_EPT_CAP_AD (1ULL << 21)
#define KSW_EPT_CAP_INVEPT_SINGLE (1ULL << 25)
#define KSW_EPT_CAP_INVEPT_ALL (1ULL << 26)
#define KSW_EPT_CAP_VPID (1ULL << 32)

typedef struct _KSW_HVM_CPU_RESOURCE
{
    KSWORD_ARK_HVM_CPU_ROW Row;
    PVOID VmxonVirtual;
    PHYSICAL_ADDRESS VmxonPhysical;
    PVOID VmcsVirtual;
    PHYSICAL_ADDRESS VmcsPhysical;
} KSW_HVM_CPU_RESOURCE;

typedef struct _KSW_HVM_EPT_PAGE
{
    PVOID VirtualAddress;
    PHYSICAL_ADDRESS PhysicalAddress;
} KSW_HVM_EPT_PAGE;

typedef struct _KSW_HVM_RUNTIME
{
    EX_PUSH_LOCK Lock;
    BOOLEAN Initialized;
    BOOLEAN Busy;
    ULONG StateFlags;
    ULONG Generation;
    ULONG QueryStatus;
    NTSTATUS LastStatus;
    ULONG ProcessorCount;
    ULONG PreparedProcessorCount;
    ULONG SelfTestPassedProcessorCount;
    ULONG EptPageCount;
    ULONG EptPml4Entries;
    ULONG EptPdptEntries;
    ULONG EptLargePageEntries;
    ULONGLONG FeatureFlags;
    ULONGLONG VmxBasic;
    ULONGLONG VmxEptVpidCapabilities;
    ULONGLONG FeatureControl;
    ULONGLONG Cr0Fixed0;
    ULONGLONG Cr0Fixed1;
    ULONGLONG Cr4Fixed0;
    ULONGLONG Cr4Fixed1;
    ULONGLONG EptPointer;
    ULONGLONG MappedRamBytes;
    ULONGLONG HighestMappedPhysicalAddress;
    ULONGLONG VmExitCount;
    ULONGLONG LastExitQualification;
    ULONGLONG LastGuestRip;
    ULONGLONG LastGuestRsp;
    ULONG LastExitReason;
    ULONG LastExitInstructionLength;
    ULONG LastVmInstructionError;
    USHORT LastLaunchProcessorGroup;
    UCHAR LastLaunchProcessorNumber;
    UCHAR LastLaunchWasNested;
    CHAR CpuVendor[KSWORD_ARK_HVM_VENDOR_CHARS];
    CHAR HypervisorVendor[KSWORD_ARK_HVM_HYPERVISOR_VENDOR_CHARS];
    KSW_HVM_CPU_RESOURCE Processors[KSWORD_ARK_HVM_MAX_PROCESSORS];
    KSW_HVM_EPT_PAGE EptPages[KSW_HVM_MAX_EPT_PAGES];
    PVOID EptPml4;
    PVOID EptPdpt[KSW_HVM_MAX_PML4_ENTRIES];
    PVOID EptPd[KSW_HVM_MAX_PML4_ENTRIES][512];
} KSW_HVM_RUNTIME;

static KSW_HVM_RUNTIME g_KswordHvm;

static VOID
KswordARKHvmCopyAscii(
    _Out_writes_(DestinationChars) CHAR* Destination,
    _In_ ULONG DestinationChars,
    _In_reads_bytes_(SourceBytes) const CHAR* Source,
    _In_ ULONG SourceBytes
    )
{
    ULONG copyBytes = 0UL;

    /* Keep every protocol string bounded and NUL terminated. */
    if (Destination == NULL || DestinationChars == 0UL) {
        return;
    }
    RtlZeroMemory(Destination, DestinationChars);
    if (Source == NULL || SourceBytes == 0UL) {
        return;
    }
    copyBytes = SourceBytes < (DestinationChars - 1UL)
        ? SourceBytes
        : (DestinationChars - 1UL);
    RtlCopyMemory(Destination, Source, copyBytes);
}

#if defined(_M_AMD64)
static BOOLEAN
KswordARKHvmReadCapabilities(
    _Inout_ KSW_HVM_RUNTIME* Runtime
    )
{
    int registers[4] = { 0 };
    CHAR vendor[13] = { 0 };
    CHAR hypervisorVendor[13] = { 0 };
    ULONG leaf1Ecx = 0UL;
    ULONGLONG secondaryControls = 0ULL;

    /* CPUID leaf zero provides an exact CPU vendor identity. */
    __cpuid(registers, 0);
    RtlCopyMemory(vendor + 0, &registers[1], sizeof(ULONG));
    RtlCopyMemory(vendor + 4, &registers[3], sizeof(ULONG));
    RtlCopyMemory(vendor + 8, &registers[2], sizeof(ULONG));
    KswordARKHvmCopyAscii(
        Runtime->CpuVendor,
        RTL_NUMBER_OF(Runtime->CpuVendor),
        vendor,
        12UL);
    if (RtlCompareMemory(vendor, "GenuineIntel", 12UL) != 12UL) {
        Runtime->QueryStatus =
            KSWORD_ARK_HVM_QUERY_STATUS_UNSUPPORTED_CPU;
        Runtime->LastStatus = STATUS_NOT_SUPPORTED;
        return FALSE;
    }
    Runtime->FeatureFlags |= KSWORD_ARK_HVM_FEATURE_INTEL;

    /* Leaf one exposes both VMX and an already-active hypervisor. */
    __cpuid(registers, 1);
    leaf1Ecx = (ULONG)registers[2];
    if ((leaf1Ecx & (1UL << 5)) != 0UL) {
        Runtime->FeatureFlags |= KSWORD_ARK_HVM_FEATURE_VMX;
    }
    if ((leaf1Ecx & (1UL << 31)) != 0UL) {
        Runtime->FeatureFlags |=
            KSWORD_ARK_HVM_FEATURE_HYPERVISOR_PRESENT;
        __cpuid(registers, (int)0x40000000UL);
        RtlCopyMemory(hypervisorVendor + 0, &registers[1], sizeof(ULONG));
        RtlCopyMemory(hypervisorVendor + 4, &registers[2], sizeof(ULONG));
        RtlCopyMemory(hypervisorVendor + 8, &registers[3], sizeof(ULONG));
        KswordARKHvmCopyAscii(
            Runtime->HypervisorVendor,
            RTL_NUMBER_OF(Runtime->HypervisorVendor),
            hypervisorVendor,
            12UL);
    }

    /* Stop before VMX MSR access when CPUID does not advertise VMX. */
    if ((Runtime->FeatureFlags & KSWORD_ARK_HVM_FEATURE_VMX) == 0ULL) {
        Runtime->QueryStatus =
            KSWORD_ARK_HVM_QUERY_STATUS_UNSUPPORTED_CPU;
        Runtime->LastStatus = STATUS_NOT_SUPPORTED;
        return FALSE;
    }

    /* VMX-specific MSRs are read under SEH to fail closed on a virtual CPU. */
    __try {
        Runtime->FeatureControl = __readmsr(KSW_IA32_FEATURE_CONTROL);
        Runtime->VmxBasic = __readmsr(KSW_IA32_VMX_BASIC);
        Runtime->Cr0Fixed0 = __readmsr(KSW_IA32_VMX_CR0_FIXED0);
        Runtime->Cr0Fixed1 = __readmsr(KSW_IA32_VMX_CR0_FIXED1);
        Runtime->Cr4Fixed0 = __readmsr(KSW_IA32_VMX_CR4_FIXED0);
        Runtime->Cr4Fixed1 = __readmsr(KSW_IA32_VMX_CR4_FIXED1);
        secondaryControls =
            __readmsr(KSW_IA32_VMX_PROCBASED_CTLS2);
        Runtime->VmxEptVpidCapabilities =
            __readmsr(KSW_IA32_VMX_EPT_VPID_CAP);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        Runtime->QueryStatus =
            KSWORD_ARK_HVM_QUERY_STATUS_UNSUPPORTED_CPU;
        Runtime->LastStatus = GetExceptionCode();
        return FALSE;
    }

    /* Decode the firmware gate without changing IA32_FEATURE_CONTROL. */
    if ((Runtime->FeatureControl & 0x1ULL) != 0ULL) {
        Runtime->FeatureFlags |=
            KSWORD_ARK_HVM_FEATURE_FEATURE_CONTROL_LOCKED;
    }
    if ((Runtime->FeatureControl & 0x4ULL) != 0ULL) {
        Runtime->FeatureFlags |=
            KSWORD_ARK_HVM_FEATURE_VMX_OUTSIDE_SMX;
    }
    if ((Runtime->VmxBasic & (1ULL << 55)) != 0ULL) {
        Runtime->FeatureFlags |=
            KSWORD_ARK_HVM_FEATURE_TRUE_CONTROLS;
    }

    /* The high dword of each control MSR is its allowed-one mask. */
    if ((((secondaryControls >> 32) & (1ULL << 1)) != 0ULL) &&
        ((Runtime->VmxEptVpidCapabilities &
            KSW_EPT_CAP_PAGE_WALK_4) != 0ULL)) {
        Runtime->FeatureFlags |= KSWORD_ARK_HVM_FEATURE_EPT;
    }
    if ((Runtime->VmxEptVpidCapabilities & KSW_EPT_CAP_WB) != 0ULL) {
        Runtime->FeatureFlags |= KSWORD_ARK_HVM_FEATURE_EPT_WB;
    }
    if ((Runtime->VmxEptVpidCapabilities &
            KSW_EPT_CAP_PAGE_WALK_4) != 0ULL) {
        Runtime->FeatureFlags |= KSWORD_ARK_HVM_FEATURE_EPT_4_LEVEL;
    }
    if ((Runtime->VmxEptVpidCapabilities & KSW_EPT_CAP_2MB) != 0ULL) {
        Runtime->FeatureFlags |= KSWORD_ARK_HVM_FEATURE_EPT_2MB;
    }
    if ((Runtime->VmxEptVpidCapabilities & KSW_EPT_CAP_AD) != 0ULL) {
        Runtime->FeatureFlags |= KSWORD_ARK_HVM_FEATURE_EPT_AD;
    }
    if ((Runtime->VmxEptVpidCapabilities & KSW_EPT_CAP_INVEPT) != 0ULL) {
        Runtime->FeatureFlags |= KSWORD_ARK_HVM_FEATURE_INVEPT;
    }
    if ((Runtime->VmxEptVpidCapabilities &
            KSW_EPT_CAP_INVEPT_SINGLE) != 0ULL) {
        Runtime->FeatureFlags |=
            KSWORD_ARK_HVM_FEATURE_INVEPT_SINGLE;
    }
    if ((Runtime->VmxEptVpidCapabilities &
            KSW_EPT_CAP_INVEPT_ALL) != 0ULL) {
        Runtime->FeatureFlags |= KSWORD_ARK_HVM_FEATURE_INVEPT_ALL;
    }
    if ((Runtime->VmxEptVpidCapabilities & KSW_EPT_CAP_VPID) != 0ULL) {
        Runtime->FeatureFlags |= KSWORD_ARK_HVM_FEATURE_VPID;
    }

    /*
     * A virtual CPU that exposes VMX while setting the hypervisor-present bit
     * is a nested-capable candidate.  The later self-test remains opt-in and
     * is the authoritative proof.
     */
    if ((Runtime->FeatureFlags &
            KSWORD_ARK_HVM_FEATURE_HYPERVISOR_PRESENT) != 0ULL &&
        (Runtime->FeatureFlags & KSWORD_ARK_HVM_FEATURE_VMX) != 0ULL) {
        Runtime->FeatureFlags |=
            KSWORD_ARK_HVM_FEATURE_NESTED_VMX_EXPOSED;
    }

    /* Firmware-disabled VMX is reported distinctly from unsupported silicon. */
    if ((Runtime->FeatureFlags &
            KSWORD_ARK_HVM_FEATURE_VMX_OUTSIDE_SMX) == 0ULL) {
        Runtime->QueryStatus =
            KSWORD_ARK_HVM_QUERY_STATUS_FIRMWARE_DISABLED;
        Runtime->LastStatus = STATUS_HV_FEATURE_UNAVAILABLE;
        return FALSE;
    }

    /* Advertise the bounded guest only when its complete EPT baseline exists. */
    if ((Runtime->FeatureFlags &
            (KSWORD_ARK_HVM_FEATURE_EPT |
             KSWORD_ARK_HVM_FEATURE_EPT_WB |
             KSWORD_ARK_HVM_FEATURE_EPT_4_LEVEL |
             KSWORD_ARK_HVM_FEATURE_EPT_2MB)) ==
        (KSWORD_ARK_HVM_FEATURE_EPT |
         KSWORD_ARK_HVM_FEATURE_EPT_WB |
         KSWORD_ARK_HVM_FEATURE_EPT_4_LEVEL |
         KSWORD_ARK_HVM_FEATURE_EPT_2MB)) {
        Runtime->FeatureFlags |=
            KSWORD_ARK_HVM_FEATURE_ONE_SHOT_GUEST |
            KSWORD_ARK_HVM_FEATURE_VMEXIT_TELEMETRY;
    }

    /* A usable capability snapshot is now available. */
    Runtime->QueryStatus = KSWORD_ARK_HVM_QUERY_STATUS_OK;
    Runtime->LastStatus = STATUS_SUCCESS;
    return TRUE;
}
#endif

static VOID
KswordARKHvmFreeResourcesLocked(
    _Inout_ KSW_HVM_RUNTIME* Runtime
    )
{
    ULONG index = 0UL;

    /* Free per-processor VMXON and VMCS pages symmetrically. */
    for (index = 0UL; index < Runtime->ProcessorCount; ++index) {
        if (Runtime->Processors[index].VmxonVirtual != NULL) {
            MmFreeContiguousMemory(
                Runtime->Processors[index].VmxonVirtual);
        }
        if (Runtime->Processors[index].VmcsVirtual != NULL) {
            MmFreeContiguousMemory(
                Runtime->Processors[index].VmcsVirtual);
        }
        RtlZeroMemory(
            &Runtime->Processors[index],
            sizeof(Runtime->Processors[index]));
    }

    /* Every EPT table page is tracked exactly once in the allocation ledger. */
    for (index = 0UL; index < Runtime->EptPageCount; ++index) {
        if (Runtime->EptPages[index].VirtualAddress != NULL) {
            MmFreeContiguousMemory(
                Runtime->EptPages[index].VirtualAddress);
        }
    }

    /* Clear all resource-derived state while preserving capability evidence. */
    RtlZeroMemory(Runtime->Processors, sizeof(Runtime->Processors));
    RtlZeroMemory(Runtime->EptPages, sizeof(Runtime->EptPages));
    RtlZeroMemory(Runtime->EptPdpt, sizeof(Runtime->EptPdpt));
    RtlZeroMemory(Runtime->EptPd, sizeof(Runtime->EptPd));
    Runtime->EptPml4 = NULL;
    Runtime->ProcessorCount = 0UL;
    Runtime->PreparedProcessorCount = 0UL;
    Runtime->SelfTestPassedProcessorCount = 0UL;
    Runtime->EptPageCount = 0UL;
    Runtime->EptPml4Entries = 0UL;
    Runtime->EptPdptEntries = 0UL;
    Runtime->EptLargePageEntries = 0UL;
    Runtime->EptPointer = 0ULL;
    Runtime->MappedRamBytes = 0ULL;
    Runtime->HighestMappedPhysicalAddress = 0ULL;
    Runtime->VmExitCount = 0ULL;
    Runtime->LastExitQualification = 0ULL;
    Runtime->LastGuestRip = 0ULL;
    Runtime->LastGuestRsp = 0ULL;
    Runtime->LastExitReason = KSWORD_ARK_HVM_EXIT_REASON_NONE;
    Runtime->LastExitInstructionLength = 0UL;
    Runtime->LastVmInstructionError = 0UL;
    Runtime->LastLaunchProcessorGroup = 0xFFFFU;
    Runtime->LastLaunchProcessorNumber = 0xFFU;
    Runtime->LastLaunchWasNested = 0U;
    Runtime->StateFlags &=
        ~(KSWORD_ARK_HVM_STATE_RESOURCES_READY |
          KSWORD_ARK_HVM_STATE_EPT_READY |
          KSWORD_ARK_HVM_STATE_SELF_TESTED |
          KSWORD_ARK_HVM_STATE_SELF_TEST_PASSED |
          KSWORD_ARK_HVM_STATE_EPT_TRUNCATED |
          KSWORD_ARK_HVM_STATE_GUEST_READY |
          KSWORD_ARK_HVM_STATE_GUEST_RUNNING |
          KSWORD_ARK_HVM_STATE_GUEST_EXITED |
          KSWORD_ARK_HVM_STATE_NESTED_ACTIVE |
          KSWORD_ARK_HVM_STATE_NESTED_VALIDATED);
}

static PVOID
KswordARKHvmAllocatePageLocked(
    _Inout_ KSW_HVM_RUNTIME* Runtime,
    _Out_ PHYSICAL_ADDRESS* PhysicalAddress
    )
{
    PHYSICAL_ADDRESS lowest = { 0 };
    PHYSICAL_ADDRESS highest = { 0 };
    PHYSICAL_ADDRESS boundary = { 0 };
    PVOID page = NULL;

    /* Enforce a bounded allocation ledger before allocating nonpaged memory. */
    if (Runtime->EptPageCount >= KSW_HVM_MAX_EPT_PAGES ||
        PhysicalAddress == NULL) {
        return NULL;
    }
    highest.QuadPart = MAXLONGLONG;
    page = MmAllocateContiguousMemorySpecifyCache(
        (SIZE_T)KSW_HVM_PAGE_BYTES,
        lowest,
        highest,
        boundary,
        MmCached);
    if (page == NULL) {
        return NULL;
    }

    /* Zero table pages before exposing their physical address to EPT. */
    RtlZeroMemory(page, (SIZE_T)KSW_HVM_PAGE_BYTES);
    *PhysicalAddress = MmGetPhysicalAddress(page);
    Runtime->EptPages[Runtime->EptPageCount].VirtualAddress = page;
    Runtime->EptPages[Runtime->EptPageCount].PhysicalAddress =
        *PhysicalAddress;
    Runtime->EptPageCount += 1UL;
    return page;
}

static NTSTATUS
KswordARKHvmEnsureEptTablesLocked(
    _Inout_ KSW_HVM_RUNTIME* Runtime,
    _In_ ULONG Pml4Index,
    _In_ ULONG PdptIndex,
    _Outptr_ ULONGLONG** PdEntries
    )
{
    PHYSICAL_ADDRESS physicalAddress = { 0 };
    ULONGLONG* pml4 = NULL;
    ULONGLONG* pdpt = NULL;

    /* Reject GPAs outside this backend's explicit, documented mapping window. */
    if (Pml4Index >= KSW_HVM_MAX_PML4_ENTRIES ||
        PdptIndex >= 512UL ||
        PdEntries == NULL ||
        Runtime->EptPml4 == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    pml4 = (ULONGLONG*)Runtime->EptPml4;

    /* Allocate a PDPT lazily for each populated PML4 slot. */
    if (Runtime->EptPdpt[Pml4Index] == NULL) {
        Runtime->EptPdpt[Pml4Index] =
            KswordARKHvmAllocatePageLocked(
                Runtime,
                &physicalAddress);
        if (Runtime->EptPdpt[Pml4Index] == NULL) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        pml4[Pml4Index] =
            (physicalAddress.QuadPart & KSW_EPT_PHYSICAL_MASK) |
            KSW_EPT_READ | KSW_EPT_WRITE | KSW_EPT_EXECUTE;
        Runtime->EptPml4Entries += 1UL;
    }
    pdpt = (ULONGLONG*)Runtime->EptPdpt[Pml4Index];

    /* Allocate a page-directory lazily for each populated one-GiB window. */
    if (Runtime->EptPd[Pml4Index][PdptIndex] == NULL) {
        Runtime->EptPd[Pml4Index][PdptIndex] =
            KswordARKHvmAllocatePageLocked(
                Runtime,
                &physicalAddress);
        if (Runtime->EptPd[Pml4Index][PdptIndex] == NULL) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        pdpt[PdptIndex] =
            (physicalAddress.QuadPart & KSW_EPT_PHYSICAL_MASK) |
            KSW_EPT_READ | KSW_EPT_WRITE | KSW_EPT_EXECUTE;
        Runtime->EptPdptEntries += 1UL;
    }

    /* Return the writable 512-entry page-directory view. */
    *PdEntries =
        (ULONGLONG*)Runtime->EptPd[Pml4Index][PdptIndex];
    return STATUS_SUCCESS;
}

static NTSTATUS
KswordARKHvmBuildEptLocked(
    _Inout_ KSW_HVM_RUNTIME* Runtime
    )
{
    PHYSICAL_ADDRESS rootPhysical = { 0 };
    PPHYSICAL_MEMORY_RANGE ranges = NULL;
    ULONG rangeIndex = 0UL;
    NTSTATUS status = STATUS_SUCCESS;

    /* EPT setup requires four-level, WB, and two-MiB leaf support. */
    if ((Runtime->FeatureFlags &
            (KSWORD_ARK_HVM_FEATURE_EPT |
             KSWORD_ARK_HVM_FEATURE_EPT_WB |
             KSWORD_ARK_HVM_FEATURE_EPT_4_LEVEL |
             KSWORD_ARK_HVM_FEATURE_EPT_2MB)) !=
        (KSWORD_ARK_HVM_FEATURE_EPT |
         KSWORD_ARK_HVM_FEATURE_EPT_WB |
         KSWORD_ARK_HVM_FEATURE_EPT_4_LEVEL |
         KSWORD_ARK_HVM_FEATURE_EPT_2MB)) {
        return STATUS_NOT_SUPPORTED;
    }

    /* Allocate and record the root table before walking RAM ranges. */
    Runtime->EptPml4 =
        KswordARKHvmAllocatePageLocked(Runtime, &rootPhysical);
    if (Runtime->EptPml4 == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    /* MmGetPhysicalMemoryRanges returns a pool-backed, zero-terminated list. */
    ranges = MmGetPhysicalMemoryRanges();
    if (ranges == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    /* Map installed RAM with two-MiB identity leaves, allocating sparse tables. */
    for (rangeIndex = 0UL;
         ranges[rangeIndex].NumberOfBytes.QuadPart != 0;
         ++rangeIndex) {
        ULONGLONG rangeStart =
            (ULONGLONG)ranges[rangeIndex].BaseAddress.QuadPart;
        ULONGLONG rangeBytes =
            (ULONGLONG)ranges[rangeIndex].NumberOfBytes.QuadPart;
        ULONGLONG rangeEnd = 0ULL;
        ULONGLONG address = 0ULL;

        /* Guard the range addition before aligning the end upward. */
        if (rangeBytes > MAXULONGLONG - rangeStart) {
            status = STATUS_INTEGER_OVERFLOW;
            break;
        }
        rangeEnd = rangeStart + rangeBytes;
        address = rangeStart & ~(KSW_HVM_LARGE_PAGE_BYTES - 1ULL);
        if (rangeEnd > KSW_HVM_MAX_MAPPED_PHYSICAL) {
            rangeEnd = KSW_HVM_MAX_MAPPED_PHYSICAL;
            Runtime->StateFlags |=
                KSWORD_ARK_HVM_STATE_EPT_TRUNCATED;
        }

        /* Add one leaf for each large page intersecting installed RAM. */
        while (address < rangeEnd) {
            ULONG pml4Index =
                (ULONG)((address >> 39) & 0x1FFULL);
            ULONG pdptIndex =
                (ULONG)((address >> 30) & 0x1FFULL);
            ULONG pdIndex =
                (ULONG)((address >> 21) & 0x1FFULL);
            ULONGLONG* pdEntries = NULL;

            status = KswordARKHvmEnsureEptTablesLocked(
                Runtime,
                pml4Index,
                pdptIndex,
                &pdEntries);
            if (!NT_SUCCESS(status)) {
                break;
            }
            if (pdEntries[pdIndex] == 0ULL) {
                pdEntries[pdIndex] =
                    (address & KSW_EPT_PHYSICAL_MASK) |
                    KSW_EPT_READ | KSW_EPT_WRITE |
                    KSW_EPT_EXECUTE |
                    KSW_EPT_MEMORY_TYPE_WB |
                    KSW_EPT_LARGE_PAGE;
                Runtime->EptLargePageEntries += 1UL;
                Runtime->MappedRamBytes +=
                    KSW_HVM_LARGE_PAGE_BYTES;
            }
            if (address + KSW_HVM_LARGE_PAGE_BYTES >
                Runtime->HighestMappedPhysicalAddress) {
                Runtime->HighestMappedPhysicalAddress =
                    address + KSW_HVM_LARGE_PAGE_BYTES;
            }
            address += KSW_HVM_LARGE_PAGE_BYTES;
        }
        if (!NT_SUCCESS(status) ||
            rangeEnd == KSW_HVM_MAX_MAPPED_PHYSICAL) {
            break;
        }
    }
    ExFreePool(ranges);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    /* EPTP encodes WB memory, a four-level walk, and optional A/D tracking. */
    Runtime->EptPointer =
        (rootPhysical.QuadPart & KSW_EPT_PHYSICAL_MASK) |
        6ULL |
        (3ULL << 3);
    if ((Runtime->FeatureFlags &
            KSWORD_ARK_HVM_FEATURE_EPT_AD) != 0ULL) {
        Runtime->EptPointer |= (1ULL << 6);
    }
    Runtime->StateFlags |= KSWORD_ARK_HVM_STATE_EPT_READY;
    return STATUS_SUCCESS;
}

static NTSTATUS
KswordARKHvmAllocateProcessorResourcesLocked(
    _Inout_ KSW_HVM_RUNTIME* Runtime
    )
{
#if defined(_M_AMD64)
    PHYSICAL_ADDRESS lowest = { 0 };
    PHYSICAL_ADDRESS highest = { 0 };
    PHYSICAL_ADDRESS boundary = { 0 };
    USHORT groupCount = 0U;
    USHORT group = 0U;
    ULONG processorIndex = 0UL;
    ULONG revision = (ULONG)(Runtime->VmxBasic & 0x7FFFFFFFULL);

    /* Enumerate every active group without exceeding the stable protocol cap. */
    highest.QuadPart = MAXLONGLONG;
    groupCount = KeQueryActiveGroupCount();
    for (group = 0U;
         group < groupCount &&
            processorIndex < KSWORD_ARK_HVM_MAX_PROCESSORS;
         ++group) {
        /* Query the exact active mask for this processor group. */
        KAFFINITY activeMask = KeQueryGroupAffinity(group);
        UCHAR processorNumber = 0U;

        /* Group masks are at most 64 bits on supported Windows targets. */
        for (processorNumber = 0U;
             processorNumber < (UCHAR)(sizeof(KAFFINITY) * 8U) &&
                processorIndex < KSWORD_ARK_HVM_MAX_PROCESSORS;
             ++processorNumber) {
            KSW_HVM_CPU_RESOURCE* cpu = NULL;

            /* Skip offline and absent logical processors. */
            if ((activeMask &
                    (((KAFFINITY)1) << processorNumber)) == 0) {
                continue;
            }
            cpu = &Runtime->Processors[processorIndex];
            cpu->Row.processorGroup = group;
            cpu->Row.processorNumber = processorNumber;
            cpu->Row.vmxInstructionResult = 0xFFU;
            cpu->Row.lastExitReason =
                KSWORD_ARK_HVM_EXIT_REASON_NONE;
            /*
             * Publish the in-progress slot to cleanup before either allocation;
             * this prevents a partial VMXON/VMCS pair from escaping rollback.
             */
            Runtime->ProcessorCount = processorIndex + 1UL;

            /* VMXON and VMCS regions are independent physical 4-KiB pages. */
            cpu->VmxonVirtual =
                MmAllocateContiguousMemorySpecifyCache(
                    (SIZE_T)KSW_HVM_PAGE_BYTES,
                    lowest,
                    highest,
                    boundary,
                    MmCached);
            cpu->VmcsVirtual =
                MmAllocateContiguousMemorySpecifyCache(
                    (SIZE_T)KSW_HVM_PAGE_BYTES,
                    lowest,
                    highest,
                    boundary,
                    MmCached);
            if (cpu->VmxonVirtual == NULL ||
                cpu->VmcsVirtual == NULL) {
                return STATUS_INSUFFICIENT_RESOURCES;
            }

            /* Both regions start with the CPU-advertised VMCS revision ID. */
            RtlZeroMemory(
                cpu->VmxonVirtual,
                (SIZE_T)KSW_HVM_PAGE_BYTES);
            RtlZeroMemory(
                cpu->VmcsVirtual,
                (SIZE_T)KSW_HVM_PAGE_BYTES);
            *(volatile ULONG*)cpu->VmxonVirtual = revision;
            *(volatile ULONG*)cpu->VmcsVirtual = revision;
            cpu->VmxonPhysical =
                MmGetPhysicalAddress(cpu->VmxonVirtual);
            cpu->VmcsPhysical =
                MmGetPhysicalAddress(cpu->VmcsVirtual);
            cpu->Row.stateFlags |=
                KSWORD_ARK_HVM_CPU_STATE_RESOURCE_READY;
            cpu->Row.lastStatus = STATUS_SUCCESS;
            Runtime->PreparedProcessorCount += 1UL;
            processorIndex += 1UL;
        }
    }
    Runtime->ProcessorCount = processorIndex;
    if (Runtime->ProcessorCount == 0UL) {
        return STATUS_NOT_FOUND;
    }
    return STATUS_SUCCESS;
#else
    UNREFERENCED_PARAMETER(Runtime);
    return STATUS_NOT_SUPPORTED;
#endif
}

static NTSTATUS
KswordARKHvmPrepareLocked(
    _Inout_ KSW_HVM_RUNTIME* Runtime,
    _In_ const KSWORD_ARK_CONTROL_HVM_REQUEST* Request
    )
{
    NTSTATUS status = STATUS_SUCCESS;

    /* Do not replace live resource state with a second allocation set. */
    if ((Runtime->StateFlags &
            KSWORD_ARK_HVM_STATE_RESOURCES_READY) != 0UL) {
        return STATUS_ALREADY_REGISTERED;
    }

    /* Nested preparation is accepted only when VMX is explicitly exposed. */
    if ((Runtime->FeatureFlags &
            KSWORD_ARK_HVM_FEATURE_HYPERVISOR_PRESENT) != 0ULL &&
        (((Request->flags &
              KSWORD_ARK_HVM_CONTROL_FLAG_ALLOW_NESTED) == 0UL) ||
         ((Runtime->FeatureFlags &
              KSWORD_ARK_HVM_FEATURE_NESTED_VMX_EXPOSED) == 0ULL))) {
        return STATUS_HV_FEATURE_UNAVAILABLE;
    }

    /* Allocate every per-CPU VMX pair before creating the EPT hierarchy. */
    status = KswordARKHvmAllocateProcessorResourcesLocked(Runtime);
    if (!NT_SUCCESS(status)) {
        KswordARKHvmFreeResourcesLocked(Runtime);
        return status;
    }
    status = KswordARKHvmBuildEptLocked(Runtime);
    if (!NT_SUCCESS(status)) {
        KswordARKHvmFreeResourcesLocked(Runtime);
        return status;
    }

    /* Resource readiness is published only after both allocation phases pass. */
    Runtime->StateFlags |=
        KSWORD_ARK_HVM_STATE_RESOURCES_READY;
    return STATUS_SUCCESS;
}

#if defined(_M_AMD64)
static NTSTATUS
KswordARKHvmSelfTestProcessor(
    _Inout_ KSW_HVM_RUNTIME* Runtime,
    _Inout_ KSW_HVM_CPU_RESOURCE* Cpu
    )
{
    GROUP_AFFINITY targetAffinity = { 0 };
    GROUP_AFFINITY oldAffinity = { 0 };
    KIRQL oldIrql = PASSIVE_LEVEL;
    ULONGLONG originalCr0 = 0ULL;
    ULONGLONG originalCr4 = 0ULL;
    ULONGLONG requiredCr0 = 0ULL;
    ULONGLONG requiredCr4 = 0ULL;
    unsigned __int64 vmxonPhysical = 0ULL;
    UCHAR vmxResult = 0xFFU;
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    BOOLEAN affinitySet = FALSE;
    BOOLEAN irqlRaised = FALSE;
    BOOLEAN cr4Changed = FALSE;

    /* Bind the current system thread to the exact resource-owning processor. */
    targetAffinity.Group = Cpu->Row.processorGroup;
    targetAffinity.Mask =
        ((KAFFINITY)1) << Cpu->Row.processorNumber;
    KeSetSystemGroupAffinityThread(
        &targetAffinity,
        &oldAffinity);
    affinitySet = TRUE;

    /* DPC level prevents migration during the local VMX transition. */
    oldIrql = KeRaiseIrqlToDpcLevel();
    irqlRaised = TRUE;
    __try {
        originalCr0 = __readcr0();
        originalCr4 = __readcr4();
        requiredCr0 =
            (originalCr0 | Runtime->Cr0Fixed0) &
            Runtime->Cr0Fixed1;
        requiredCr4 =
            ((originalCr4 | Runtime->Cr4Fixed0) &
                Runtime->Cr4Fixed1) |
            KSW_CR4_VMXE;

        /*
         * Never steal a VMX root already owned by another component, and never
         * alter CR0 or clear a live CR4 feature merely to make the test pass.
         */
        if ((originalCr4 & KSW_CR4_VMXE) != 0ULL ||
            requiredCr0 != originalCr0 ||
            (requiredCr4 & originalCr4) != originalCr4) {
            Cpu->Row.stateFlags |=
                KSWORD_ARK_HVM_CPU_STATE_CONFLICT;
            status = STATUS_CONFLICTING_ADDRESSES;
            __leave;
        }

        /* Enter VMX root briefly using the page assigned to this processor. */
        __writecr4(requiredCr4);
        cr4Changed = TRUE;
        vmxonPhysical =
            (unsigned __int64)Cpu->VmxonPhysical.QuadPart;
        vmxResult = __vmx_on(&vmxonPhysical);
        Cpu->Row.vmxInstructionResult = vmxResult;
        Cpu->Row.stateFlags |=
            KSWORD_ARK_HVM_CPU_STATE_SELF_TESTED;
        if (vmxResult != 0U) {
            status = STATUS_HV_OPERATION_FAILED;
            __leave;
        }

        /* A successful VMXON is immediately paired with VMXOFF. */
        (void)__vmx_off();
        Cpu->Row.stateFlags |=
            KSWORD_ARK_HVM_CPU_STATE_VMXON_SUCCEEDED;
        status = STATUS_SUCCESS;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        Cpu->Row.stateFlags |=
            KSWORD_ARK_HVM_CPU_STATE_SELF_TESTED |
            KSWORD_ARK_HVM_CPU_STATE_EXCEPTION;
        status = GetExceptionCode();
    }

    /* Restore the original control register before lowering IRQL. */
    if (cr4Changed) {
        __try {
            __writecr4(originalCr4);
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            status = GetExceptionCode();
            Cpu->Row.stateFlags |=
                KSWORD_ARK_HVM_CPU_STATE_EXCEPTION;
        }
    }
    if (irqlRaised) {
        KeLowerIrql(oldIrql);
    }
    if (affinitySet) {
        KeRevertToUserGroupAffinityThread(&oldAffinity);
    }
    Cpu->Row.lastStatus = status;
    return status;
}
#endif

static NTSTATUS
KswordARKHvmSelfTestLocked(
    _Inout_ KSW_HVM_RUNTIME* Runtime,
    _In_ const KSWORD_ARK_CONTROL_HVM_REQUEST* Request
    )
{
#if defined(_M_AMD64)
    ULONG index = 0UL;
    ULONG passed = 0UL;
    NTSTATUS firstFailure = STATUS_SUCCESS;

    /* The test operates only on a complete prepared resource set. */
    if ((Runtime->StateFlags &
            KSWORD_ARK_HVM_STATE_RESOURCES_READY) == 0UL) {
        return STATUS_DEVICE_NOT_READY;
    }

    /* Nested execution requires a second explicit opt-in at self-test time. */
    if ((Runtime->FeatureFlags &
            KSWORD_ARK_HVM_FEATURE_HYPERVISOR_PRESENT) != 0ULL &&
        (Request->flags &
            KSWORD_ARK_HVM_CONTROL_FLAG_ALLOW_NESTED) == 0UL) {
        return STATUS_HV_FEATURE_UNAVAILABLE;
    }

    /* Test each processor independently and retain every local result row. */
    for (index = 0UL; index < Runtime->ProcessorCount; ++index) {
        NTSTATUS status =
            KswordARKHvmSelfTestProcessor(
                Runtime,
                &Runtime->Processors[index]);
        if (NT_SUCCESS(status)) {
            passed += 1UL;
        } else if (NT_SUCCESS(firstFailure)) {
            firstFailure = status;
        }
    }
    Runtime->SelfTestPassedProcessorCount = passed;
    Runtime->StateFlags |= KSWORD_ARK_HVM_STATE_SELF_TESTED;
    if (passed == Runtime->ProcessorCount &&
        Runtime->ProcessorCount != 0UL) {
        Runtime->StateFlags |=
            KSWORD_ARK_HVM_STATE_SELF_TEST_PASSED |
            KSWORD_ARK_HVM_STATE_GUEST_READY;
        return STATUS_SUCCESS;
    }
    Runtime->StateFlags &=
        ~(KSWORD_ARK_HVM_STATE_SELF_TEST_PASSED |
          KSWORD_ARK_HVM_STATE_GUEST_READY);
    return NT_SUCCESS(firstFailure)
        ? STATUS_UNSUCCESSFUL
        : firstFailure;
#else
    UNREFERENCED_PARAMETER(Runtime);
    UNREFERENCED_PARAMETER(Request);
    return STATUS_NOT_SUPPORTED;
#endif
}

static NTSTATUS
KswordARKHvmLaunchGuestLocked(
    _Inout_ KSW_HVM_RUNTIME* Runtime,
    _In_ const KSWORD_ARK_CONTROL_HVM_REQUEST* Request
    )
{
#if defined(_M_AMD64)
    KSW_HVM_CPU_RESOURCE* cpu = NULL;
    KSW_HVM_GUEST_LAUNCH_INPUT launchInput = { 0 };
    KSW_HVM_GUEST_LAUNCH_RESULT launchResult = { 0 };
    ULONG index = 0UL;
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    BOOLEAN nestedLaunch = FALSE;

    /* Require a complete prepared and self-tested backend before VM entry. */
    if ((Runtime->StateFlags &
            (KSWORD_ARK_HVM_STATE_RESOURCES_READY |
             KSWORD_ARK_HVM_STATE_EPT_READY |
             KSWORD_ARK_HVM_STATE_SELF_TEST_PASSED |
             KSWORD_ARK_HVM_STATE_GUEST_READY)) !=
        (KSWORD_ARK_HVM_STATE_RESOURCES_READY |
         KSWORD_ARK_HVM_STATE_EPT_READY |
         KSWORD_ARK_HVM_STATE_SELF_TEST_PASSED |
         KSWORD_ARK_HVM_STATE_GUEST_READY)) {
        return STATUS_DEVICE_NOT_READY;
    }
    /* Require the one-shot semantic bit so the command cannot drift silently. */
    if ((Request->flags &
            KSWORD_ARK_HVM_CONTROL_FLAG_ONE_SHOT_GUEST) == 0UL) {
        return STATUS_INVALID_PARAMETER;
    }
    /* Detect whether this launch would execute as an explicitly nested guest. */
    nestedLaunch =
        (Runtime->FeatureFlags &
            KSWORD_ARK_HVM_FEATURE_HYPERVISOR_PRESENT) != 0ULL;
    /* Reject nested execution unless both exposure and explicit opt-in exist. */
    if (nestedLaunch &&
        (((Request->flags &
              KSWORD_ARK_HVM_CONTROL_FLAG_ALLOW_NESTED) == 0UL) ||
         ((Runtime->FeatureFlags &
              KSWORD_ARK_HVM_FEATURE_NESTED_VMX_EXPOSED) == 0ULL))) {
        return STATUS_HV_FEATURE_UNAVAILABLE;
    }

    /* Clear the previous launch's per-CPU evidence before selecting a target. */
    for (index = 0UL; index < Runtime->ProcessorCount; ++index) {
        Runtime->Processors[index].Row.stateFlags &=
            ~(KSWORD_ARK_HVM_CPU_STATE_VMCS_LOADED |
              KSWORD_ARK_HVM_CPU_STATE_GUEST_LAUNCHED |
              KSWORD_ARK_HVM_CPU_STATE_VMEXIT_HANDLED);
        Runtime->Processors[index].Row.lastExitReason =
            KSWORD_ARK_HVM_EXIT_REASON_NONE;
    }
    /* Select the first processor whose VMXON/VMXOFF self-test succeeded. */
    for (index = 0UL; index < Runtime->ProcessorCount; ++index) {
        if ((Runtime->Processors[index].Row.stateFlags &
                KSWORD_ARK_HVM_CPU_STATE_VMXON_SUCCEEDED) != 0UL) {
            cpu = &Runtime->Processors[index];
            break;
        }
    }
    /* Refuse VM entry when no processor retained a passing self-test. */
    if (cpu == NULL) {
        return STATUS_DEVICE_NOT_READY;
    }

    /* Copy the exact processor identity into the launch contract. */
    launchInput.ProcessorGroup = cpu->Row.processorGroup;
    /* Copy the group-relative processor number into the launch contract. */
    launchInput.ProcessorNumber = cpu->Row.processorNumber;
    /* Publish whether the launch is intentionally nested. */
    launchInput.NestedLaunch = nestedLaunch ? 1U : 0U;
    /* Reference the processor-owned VMXON physical page. */
    launchInput.VmxonPhysical = cpu->VmxonPhysical;
    /* Reference the processor-owned VMCS physical page. */
    launchInput.VmcsPhysical = cpu->VmcsPhysical;
    /* Copy the VMCS revision/control mode evidence. */
    launchInput.VmxBasic = Runtime->VmxBasic;
    /* Copy the CR0 required-one mask. */
    launchInput.Cr0Fixed0 = Runtime->Cr0Fixed0;
    /* Copy the CR0 allowed-one mask. */
    launchInput.Cr0Fixed1 = Runtime->Cr0Fixed1;
    /* Copy the CR4 required-one mask. */
    launchInput.Cr4Fixed0 = Runtime->Cr4Fixed0;
    /* Copy the CR4 allowed-one mask. */
    launchInput.Cr4Fixed1 = Runtime->Cr4Fixed1;
    /* Reference the prepared RAM identity-map EPT pointer. */
    launchInput.EptPointer = Runtime->EptPointer;

    /* Replace the previous one-shot state with an observable running state. */
    Runtime->StateFlags &=
        ~(KSWORD_ARK_HVM_STATE_GUEST_EXITED |
          KSWORD_ARK_HVM_STATE_NESTED_VALIDATED);
    /* Publish guest-running state before entering VMX root. */
    Runtime->StateFlags |= KSWORD_ARK_HVM_STATE_GUEST_RUNNING;
    /* Publish nested-active state only for an explicitly allowed nested launch. */
    if (nestedLaunch) {
        Runtime->StateFlags |= KSWORD_ARK_HVM_STATE_NESTED_ACTIVE;
    }
    /* Preserve the selected processor identity for both success and failure. */
    Runtime->LastLaunchProcessorGroup = cpu->Row.processorGroup;
    /* Preserve the selected group-relative processor number. */
    Runtime->LastLaunchProcessorNumber = cpu->Row.processorNumber;
    /* Preserve the launch environment as protocol-visible evidence. */
    Runtime->LastLaunchWasNested = nestedLaunch ? 1U : 0U;
    /* Execute the bounded guest and wait for its exit continuation. */
    status = KswordARKHvmLaunchControlledGuest(
        &launchInput,
        &launchResult);
    /* Clear transient active state after the launch function returns. */
    Runtime->StateFlags &=
        ~(KSWORD_ARK_HVM_STATE_GUEST_RUNNING |
          KSWORD_ARK_HVM_STATE_NESTED_ACTIVE);

    /* Preserve the exact final VMX instruction result on the selected CPU. */
    cpu->Row.vmxInstructionResult =
        launchResult.VmxInstructionResult;
    /* Preserve the launch status on the selected CPU row. */
    cpu->Row.lastStatus = status;
    /* Publish current-VMCS evidence when VMPTRLD completed. */
    if (launchResult.VmcsLoaded != 0U) {
        cpu->Row.stateFlags |=
            KSWORD_ARK_HVM_CPU_STATE_VMCS_LOADED;
    }
    /* Publish successful VM-entry evidence only when a host exit occurred. */
    if (launchResult.GuestLaunched != 0U) {
        cpu->Row.stateFlags |=
            KSWORD_ARK_HVM_CPU_STATE_GUEST_LAUNCHED;
    }
    /* Publish VM-exit dispatch evidence and increment its monotonic counter. */
    if (launchResult.VmExitHandled != 0U) {
        cpu->Row.stateFlags |=
            KSWORD_ARK_HVM_CPU_STATE_VMEXIT_HANDLED;
        Runtime->VmExitCount += 1ULL;
        Runtime->StateFlags |=
            KSWORD_ARK_HVM_STATE_GUEST_EXITED;
        Runtime->LastExitReason =
            launchResult.Exit.Reason &
            KSW_HVM_VMEXIT_REASON_BASIC_MASK;
        cpu->Row.lastExitReason =
            Runtime->LastExitReason;
    } else {
        Runtime->LastExitReason =
            KSWORD_ARK_HVM_EXIT_REASON_NONE;
    }
    /* Preserve exit qualification even when the exit was unexpected. */
    Runtime->LastExitQualification =
        launchResult.Exit.Qualification;
    /* Preserve the guest instruction pointer at the exit boundary. */
    Runtime->LastGuestRip = launchResult.Exit.GuestRip;
    /* Preserve the guest stack pointer at the exit boundary. */
    Runtime->LastGuestRsp = launchResult.Exit.GuestRsp;
    /* Preserve the decoded VM-exit instruction length. */
    Runtime->LastExitInstructionLength =
        launchResult.Exit.InstructionLength;
    /* Prefer launch-time VMfail detail, then retain exit-time diagnostic state. */
    Runtime->LastVmInstructionError =
        launchResult.VmInstructionError != 0UL
        ? launchResult.VmInstructionError
        : launchResult.Exit.VmInstructionError;
    /* Record that nested VM entry and the expected VMCALL exit both completed. */
    if (NT_SUCCESS(status) && nestedLaunch) {
        Runtime->StateFlags |=
            KSWORD_ARK_HVM_STATE_NESTED_VALIDATED;
    }
    return status;
#else
    /* Keep non-x64 builds explicit and warning-free. */
    UNREFERENCED_PARAMETER(Runtime);
    /* Keep non-x64 builds explicit and warning-free. */
    UNREFERENCED_PARAMETER(Request);
    return STATUS_NOT_SUPPORTED;
#endif
}

static ULONG
KswordARKHvmControlStatusFromNtStatus(
    _In_ ULONG Command,
    _In_ NTSTATUS Status
    )
{
    /* Map backend failures to stable UI-facing protocol states. */
    if (NT_SUCCESS(Status)) {
        return KSWORD_ARK_HVM_CONTROL_STATUS_OK;
    }
    if (Status == STATUS_ALREADY_REGISTERED) {
        return KSWORD_ARK_HVM_CONTROL_STATUS_ALREADY_PREPARED;
    }
    if (Status == STATUS_DEVICE_NOT_READY) {
        return KSWORD_ARK_HVM_CONTROL_STATUS_NOT_PREPARED;
    }
    if (Status == STATUS_HV_FEATURE_UNAVAILABLE) {
        return KSWORD_ARK_HVM_CONTROL_STATUS_HYPERVISOR_CONFLICT;
    }
    if (Status == STATUS_NOT_SUPPORTED) {
        return KSWORD_ARK_HVM_CONTROL_STATUS_UNSUPPORTED_CPU;
    }
    if (Status == STATUS_INSUFFICIENT_RESOURCES) {
        return KSWORD_ARK_HVM_CONTROL_STATUS_RESOURCE_FAILED;
    }
    if (Command == KSWORD_ARK_HVM_CONTROL_LAUNCH_TEST_GUEST &&
        Status == STATUS_UNEXPECTED_IO_ERROR) {
        return KSWORD_ARK_HVM_CONTROL_STATUS_UNEXPECTED_VMEXIT;
    }
    if (Command == KSWORD_ARK_HVM_CONTROL_LAUNCH_TEST_GUEST) {
        return KSWORD_ARK_HVM_CONTROL_STATUS_GUEST_LAUNCH_FAILED;
    }
    if (Command == KSWORD_ARK_HVM_CONTROL_SELF_TEST) {
        return KSWORD_ARK_HVM_CONTROL_STATUS_SELF_TEST_FAILED;
    }
    return KSWORD_ARK_HVM_CONTROL_STATUS_RESOURCE_FAILED;
}

NTSTATUS
KswordARKHvmInitialize(
    VOID
    )
{
    /* Initialize the lock before publishing any observable runtime state. */
    RtlZeroMemory(&g_KswordHvm, sizeof(g_KswordHvm));
    ExInitializePushLock(&g_KswordHvm.Lock);
    g_KswordHvm.Initialized = TRUE;
    g_KswordHvm.StateFlags = KSWORD_ARK_HVM_STATE_INITIALIZED;
    g_KswordHvm.Generation = 1UL;
    g_KswordHvm.LastExitReason =
        KSWORD_ARK_HVM_EXIT_REASON_NONE;
    g_KswordHvm.LastLaunchProcessorGroup = 0xFFFFU;
    g_KswordHvm.LastLaunchProcessorNumber = 0xFFU;

#if defined(_M_AMD64)
    /* Capability failure disables HVM only; it does not fail driver startup. */
    (void)KswordARKHvmReadCapabilities(&g_KswordHvm);
#else
    g_KswordHvm.QueryStatus =
        KSWORD_ARK_HVM_QUERY_STATUS_UNSUPPORTED_CPU;
    g_KswordHvm.LastStatus = STATUS_NOT_SUPPORTED;
#endif
    return STATUS_SUCCESS;
}

VOID
KswordARKHvmUninitialize(
    VOID
    )
{
    /* Unload is serialized against query/control before releasing pages. */
    if (!g_KswordHvm.Initialized) {
        return;
    }
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&g_KswordHvm.Lock);
    KswordARKHvmFreeResourcesLocked(&g_KswordHvm);
    g_KswordHvm.Initialized = FALSE;
    ExReleasePushLockExclusive(&g_KswordHvm.Lock);
    KeLeaveCriticalRegion();
}

NTSTATUS
KswordARKHvmQuery(
    _Out_ KSWORD_ARK_QUERY_HVM_RESPONSE* Response
    )
{
    ULONG index = 0UL;

    /* A fixed response makes status queries deterministic across UI refreshes. */
    if (Response == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    RtlZeroMemory(Response, sizeof(*Response));
    if (!g_KswordHvm.Initialized) {
        return STATUS_DEVICE_NOT_READY;
    }

    /* Snapshot all state under a shared push lock. */
    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&g_KswordHvm.Lock);
    Response->version = KSWORD_ARK_HVM_PROTOCOL_VERSION;
    Response->size = sizeof(*Response);
    Response->queryStatus = g_KswordHvm.Busy
        ? KSWORD_ARK_HVM_QUERY_STATUS_BUSY
        : g_KswordHvm.QueryStatus;
    Response->stateFlags = g_KswordHvm.StateFlags |
        (g_KswordHvm.Busy ? KSWORD_ARK_HVM_STATE_BUSY : 0UL);
    Response->generation = g_KswordHvm.Generation;
    Response->processorCount = g_KswordHvm.ProcessorCount;
    Response->preparedProcessorCount =
        g_KswordHvm.PreparedProcessorCount;
    Response->selfTestPassedProcessorCount =
        g_KswordHvm.SelfTestPassedProcessorCount;
    Response->eptPageCount = g_KswordHvm.EptPageCount;
    Response->eptPml4Entries = g_KswordHvm.EptPml4Entries;
    Response->eptPdptEntries = g_KswordHvm.EptPdptEntries;
    Response->eptLargePageEntries =
        g_KswordHvm.EptLargePageEntries;
    Response->featureFlags = g_KswordHvm.FeatureFlags;
    Response->vmxBasic = g_KswordHvm.VmxBasic;
    Response->vmxEptVpidCapabilities =
        g_KswordHvm.VmxEptVpidCapabilities;
    Response->featureControl = g_KswordHvm.FeatureControl;
    Response->cr0Fixed0 = g_KswordHvm.Cr0Fixed0;
    Response->cr0Fixed1 = g_KswordHvm.Cr0Fixed1;
    Response->cr4Fixed0 = g_KswordHvm.Cr4Fixed0;
    Response->cr4Fixed1 = g_KswordHvm.Cr4Fixed1;
    Response->eptPointer = g_KswordHvm.EptPointer;
    Response->mappedRamBytes = g_KswordHvm.MappedRamBytes;
    Response->highestMappedPhysicalAddress =
        g_KswordHvm.HighestMappedPhysicalAddress;
    Response->vmExitCount = g_KswordHvm.VmExitCount;
    Response->lastExitQualification =
        g_KswordHvm.LastExitQualification;
    Response->lastGuestRip = g_KswordHvm.LastGuestRip;
    Response->lastGuestRsp = g_KswordHvm.LastGuestRsp;
    Response->lastExitReason = g_KswordHvm.LastExitReason;
    Response->lastExitInstructionLength =
        g_KswordHvm.LastExitInstructionLength;
    Response->lastVmInstructionError =
        g_KswordHvm.LastVmInstructionError;
    Response->lastLaunchProcessorGroup =
        g_KswordHvm.LastLaunchProcessorGroup;
    Response->lastLaunchProcessorNumber =
        g_KswordHvm.LastLaunchProcessorNumber;
    Response->lastLaunchWasNested =
        g_KswordHvm.LastLaunchWasNested;
    Response->lastStatus = g_KswordHvm.LastStatus;
    KswordARKHvmCopyAscii(
        Response->cpuVendor,
        RTL_NUMBER_OF(Response->cpuVendor),
        g_KswordHvm.CpuVendor,
        RTL_NUMBER_OF(g_KswordHvm.CpuVendor));
    KswordARKHvmCopyAscii(
        Response->hypervisorVendor,
        RTL_NUMBER_OF(Response->hypervisorVendor),
        g_KswordHvm.HypervisorVendor,
        RTL_NUMBER_OF(g_KswordHvm.HypervisorVendor));
    for (index = 0UL;
         index < g_KswordHvm.ProcessorCount &&
            index < KSWORD_ARK_HVM_MAX_PROCESSORS;
         ++index) {
        Response->processors[index] =
            g_KswordHvm.Processors[index].Row;
    }
    ExReleasePushLockShared(&g_KswordHvm.Lock);
    KeLeaveCriticalRegion();
    return STATUS_SUCCESS;
}

NTSTATUS
KswordARKHvmControl(
    _In_ const KSWORD_ARK_CONTROL_HVM_REQUEST* Request,
    _Out_ KSWORD_ARK_CONTROL_HVM_RESPONSE* Response
    )
{
    NTSTATUS status = STATUS_SUCCESS;
    ULONG oldStateFlags = 0UL;
    ULONG oldGeneration = 0UL;

    /* Validate the complete versioned request before acquiring the state lock. */
    if (Request == NULL || Response == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    RtlZeroMemory(Response, sizeof(*Response));
    Response->version = KSWORD_ARK_HVM_PROTOCOL_VERSION;
    Response->size = sizeof(*Response);
    if (Request->version != KSWORD_ARK_HVM_PROTOCOL_VERSION ||
        Request->size != sizeof(*Request) ||
        Request->confirmationToken !=
            KSWORD_ARK_HVM_CONTROL_CONFIRMATION_TOKEN ||
        (Request->flags &
            KSWORD_ARK_HVM_CONTROL_FLAG_UI_CONFIRMED) == 0UL ||
        (Request->command != KSWORD_ARK_HVM_CONTROL_PREPARE &&
         Request->command != KSWORD_ARK_HVM_CONTROL_SELF_TEST &&
         Request->command != KSWORD_ARK_HVM_CONTROL_TEARDOWN &&
         Request->command !=
            KSWORD_ARK_HVM_CONTROL_LAUNCH_TEST_GUEST)) {
        Response->status =
            KSWORD_ARK_HVM_CONTROL_STATUS_INVALID_REQUEST;
        Response->lastStatus = STATUS_INVALID_PARAMETER;
        return STATUS_SUCCESS;
    }
    if ((Request->command == KSWORD_ARK_HVM_CONTROL_SELF_TEST ||
         Request->command ==
            KSWORD_ARK_HVM_CONTROL_LAUNCH_TEST_GUEST) &&
        (Request->flags & KSWORD_ARK_HVM_CONTROL_FLAG_FORCE) == 0UL) {
        Response->status =
            KSWORD_ARK_HVM_CONTROL_STATUS_CONFIRMATION_REQUIRED;
        Response->lastStatus = STATUS_ACCESS_DENIED;
        return STATUS_SUCCESS;
    }
    if (Request->command ==
            KSWORD_ARK_HVM_CONTROL_LAUNCH_TEST_GUEST &&
        (Request->flags &
            KSWORD_ARK_HVM_CONTROL_FLAG_ONE_SHOT_GUEST) == 0UL) {
        Response->status =
            KSWORD_ARK_HVM_CONTROL_STATUS_INVALID_REQUEST;
        Response->lastStatus = STATUS_INVALID_PARAMETER;
        return STATUS_SUCCESS;
    }
    if (!g_KswordHvm.Initialized) {
        Response->status =
            KSWORD_ARK_HVM_CONTROL_STATUS_RESOURCE_FAILED;
        Response->lastStatus = STATUS_DEVICE_NOT_READY;
        return STATUS_SUCCESS;
    }

    /* Serialize all lifecycle changes and honor generation-bound requests. */
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&g_KswordHvm.Lock);
    oldStateFlags = g_KswordHvm.StateFlags;
    oldGeneration = g_KswordHvm.Generation;
    if (g_KswordHvm.Busy) {
        status = STATUS_DEVICE_BUSY;
        Response->status =
            KSWORD_ARK_HVM_CONTROL_STATUS_BUSY;
        goto Complete;
    }
    if (Request->expectedGeneration != 0UL &&
        Request->expectedGeneration != g_KswordHvm.Generation) {
        status = STATUS_REVISION_MISMATCH;
        Response->status =
            KSWORD_ARK_HVM_CONTROL_STATUS_VERIFY_FAILED;
        goto Complete;
    }
    if (g_KswordHvm.QueryStatus != KSWORD_ARK_HVM_QUERY_STATUS_OK) {
        status = g_KswordHvm.LastStatus;
        Response->status =
            g_KswordHvm.QueryStatus ==
                KSWORD_ARK_HVM_QUERY_STATUS_FIRMWARE_DISABLED
            ? KSWORD_ARK_HVM_CONTROL_STATUS_FIRMWARE_DISABLED
            : KSWORD_ARK_HVM_CONTROL_STATUS_UNSUPPORTED_CPU;
        goto Complete;
    }

    /* Publish busy state while the selected lifecycle command executes. */
    g_KswordHvm.Busy = TRUE;
    if (Request->command == KSWORD_ARK_HVM_CONTROL_PREPARE) {
        status = KswordARKHvmPrepareLocked(
            &g_KswordHvm,
            Request);
    } else if (Request->command ==
        KSWORD_ARK_HVM_CONTROL_SELF_TEST) {
        status = KswordARKHvmSelfTestLocked(
            &g_KswordHvm,
            Request);
    } else if (Request->command ==
        KSWORD_ARK_HVM_CONTROL_LAUNCH_TEST_GUEST) {
        status = KswordARKHvmLaunchGuestLocked(
            &g_KswordHvm,
            Request);
    } else {
        KswordARKHvmFreeResourcesLocked(&g_KswordHvm);
        status = STATUS_SUCCESS;
    }
    g_KswordHvm.Busy = FALSE;
    g_KswordHvm.LastStatus = status;
    if (!NT_SUCCESS(status)) {
        g_KswordHvm.StateFlags |= KSWORD_ARK_HVM_STATE_FAULTED;
    } else {
        g_KswordHvm.StateFlags &= ~KSWORD_ARK_HVM_STATE_FAULTED;
    }
    g_KswordHvm.Generation += 1UL;
    Response->status =
        KswordARKHvmControlStatusFromNtStatus(
            Request->command,
            status);

Complete:
    /* Always return a complete before/after lifecycle summary. */
    Response->oldStateFlags = oldStateFlags;
    Response->newStateFlags = g_KswordHvm.StateFlags;
    Response->oldGeneration = oldGeneration;
    Response->newGeneration = g_KswordHvm.Generation;
    Response->preparedProcessorCount =
        g_KswordHvm.PreparedProcessorCount;
    Response->selfTestPassedProcessorCount =
        g_KswordHvm.SelfTestPassedProcessorCount;
    Response->failedProcessorCount =
        g_KswordHvm.ProcessorCount >=
            g_KswordHvm.SelfTestPassedProcessorCount
        ? g_KswordHvm.ProcessorCount -
            g_KswordHvm.SelfTestPassedProcessorCount
        : 0UL;
    Response->eptPageCount = g_KswordHvm.EptPageCount;
    Response->eptPointer = g_KswordHvm.EptPointer;
    Response->mappedRamBytes = g_KswordHvm.MappedRamBytes;
    Response->vmExitCount = g_KswordHvm.VmExitCount;
    Response->lastExitQualification =
        g_KswordHvm.LastExitQualification;
    Response->lastGuestRip = g_KswordHvm.LastGuestRip;
    Response->lastGuestRsp = g_KswordHvm.LastGuestRsp;
    Response->lastExitReason = g_KswordHvm.LastExitReason;
    Response->lastExitInstructionLength =
        g_KswordHvm.LastExitInstructionLength;
    Response->lastVmInstructionError =
        g_KswordHvm.LastVmInstructionError;
    Response->launchProcessorGroup =
        g_KswordHvm.LastLaunchProcessorGroup;
    Response->launchProcessorNumber =
        g_KswordHvm.LastLaunchProcessorNumber;
    Response->launchWasNested =
        g_KswordHvm.LastLaunchWasNested;
    Response->lastStatus = status;
    ExReleasePushLockExclusive(&g_KswordHvm.Lock);
    KeLeaveCriticalRegion();
    return STATUS_SUCCESS;
}
