/*++

Module Name:

    slat_iommu_audit.c

Abstract:

    Read-only Intel EPT / AMD NPT cross-view probes and IOMMU firmware/runtime
    evidence.  A clean result is not proof that an outer hypervisor has no
    execute-only SLAT hook: the outer EPT/NPT tables are intentionally opaque
    to the guest.  The response keeps this boundary explicit.

--*/

#include <ntifs.h>
#include <acpitabl.h>
#include <intrin.h>

#include "ark/ark_driver.h"

/* ntddk also defines the member name as a HALDISPATCH macro wrapper. */
#ifdef HalGetCachedAcpiTable
#undef HalGetCachedAcpiTable
#endif

C_ASSERT(sizeof(KSWORD_ARK_SLAT_PROBE_ROW) == 96U);
C_ASSERT(sizeof(KSWORD_ARK_IOMMU_ROW) == 80U);
C_ASSERT(sizeof(KSWORD_ARK_QUERY_SLAT_IOMMU_AUDIT_REQUEST) == 16U);
C_ASSERT(sizeof(KSWORD_ARK_QUERY_SLAT_IOMMU_AUDIT_RESPONSE) == 6848U);

#define KSW_SLAT_PROBE_BYTES 32UL
#define KSW_SLAT_TIMING_SAMPLES 64UL
#define KSW_IA32_FEATURE_CONTROL 0x3AUL
#define KSW_IA32_VMX_PROCBASED_CTLS2 0x48BUL
#define KSW_IA32_VMX_EPT_VPID_CAP 0x48CUL
#define KSW_AMD_EFER 0xC0000080UL
#define KSW_AMD_VM_CR 0xC0010114UL
#define KSW_VTD_MMIO_BYTES 0x1000UL
#define KSW_AMD_IOMMU_MMIO_BYTES 0x3000UL

typedef NTSTATUS
(*KSW_IO_GET_IOMMU_INTERFACE_FN)(
    _In_ ULONG Version,
    _Out_ PDMA_IOMMU_INTERFACE InterfaceOut
    );

typedef NTSTATUS
(*KSW_IO_GET_IOMMU_INTERFACE_EX_FN)(
    _In_ ULONG Version,
    _In_ ULONGLONG Flags,
    _Out_ PDMA_IOMMU_INTERFACE_EX InterfaceOut
    );

typedef struct _KSW_SLAT_PROBE_TARGET
{
    PCWSTR WideName;
    PCSTR AnsiName;
} KSW_SLAT_PROBE_TARGET;

static const KSW_SLAT_PROBE_TARGET g_KswordSlatProbeTargets[] = {
    { L"KeBugCheckEx", "KeBugCheckEx" },
    { L"IoCreateDevice", "IoCreateDevice" },
    { L"PsLookupProcessByProcessId", "PsLookupProcessByProcessId" },
    { L"MmCopyMemory", "MmCopyMemory" },
    { L"MmMapIoSpace", "MmMapIoSpace" },
    { L"ObReferenceObjectByHandle", "ObReferenceObjectByHandle" },
    { L"ZwOpenFile", "ZwOpenFile" },
    { L"KeQueryPerformanceCounter", "KeQueryPerformanceCounter" }
};

static pHalGetAcpiTable
KswordARKSlatResolveAcpiGetter(
    VOID
    )
{
    UNICODE_STRING routineName;
    pHalGetAcpiTable routine = NULL;

    RtlInitUnicodeString(&routineName, L"HalGetCachedAcpiTable");
    routine = (pHalGetAcpiTable)MmGetSystemRoutineAddress(&routineName);
    if (routine != NULL) {
        return routine;
    }
    if (HALDISPATCH != NULL &&
        HALDISPATCH->Version >= HAL_DISPATCH_VERSION) {
        return HALDISPATCH->HalGetCachedAcpiTable;
    }
    return NULL;
}

static VOID
KswordARKSlatCopyAscii(
    _Out_writes_(DestinationChars) CHAR* Destination,
    _In_ ULONG DestinationChars,
    _In_reads_bytes_(SourceBytes) const CHAR* Source,
    _In_ ULONG SourceBytes
    )
{
    ULONG copyBytes = 0UL;

    if (Destination == NULL || DestinationChars == 0UL) {
        return;
    }
    RtlZeroMemory(Destination, DestinationChars);
    if (Source == NULL || SourceBytes == 0UL) {
        return;
    }
    copyBytes = min(SourceBytes, DestinationChars - 1UL);
    RtlCopyMemory(Destination, Source, copyBytes);
}

static ULONG
KswordARKSlatAsciiLength(
    _In_z_ const CHAR* Text
    )
{
    ULONG length = 0UL;

    if (Text == NULL) {
        return 0UL;
    }
    while (Text[length] != '\0' && length < 1024UL) {
        ++length;
    }
    return length;
}

static ULONGLONG
KswordARKSlatHashBytes(
    _In_reads_bytes_(Bytes) const UCHAR* Buffer,
    _In_ ULONG Bytes
    )
{
    ULONGLONG hash = 1469598103934665603ULL;
    ULONG index = 0UL;

    if (Buffer == NULL) {
        return 0ULL;
    }
    for (index = 0UL; index < Bytes; ++index) {
        hash ^= (ULONGLONG)Buffer[index];
        hash *= 1099511628211ULL;
    }
    return hash;
}

static BOOLEAN
KswordARKSlatBufferEqual(
    _In_reads_bytes_(Bytes) const UCHAR* Left,
    _In_reads_bytes_(Bytes) const UCHAR* Right,
    _In_ ULONG Bytes
    )
{
    return RtlCompareMemory(Left, Right, Bytes) == Bytes ? TRUE : FALSE;
}

static NTSTATUS
KswordARKSlatReadVirtual(
    _In_ const VOID* Address,
    _Out_writes_bytes_(Bytes) UCHAR* Buffer,
    _In_ ULONG Bytes
    )
{
    if (Address == NULL || Buffer == NULL || Bytes == 0UL) {
        return STATUS_INVALID_PARAMETER;
    }
    __try {
        RtlCopyMemory(Buffer, Address, Bytes);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return GetExceptionCode();
    }
    return STATUS_SUCCESS;
}

static NTSTATUS
KswordARKSlatReadPhysical(
    _In_ PHYSICAL_ADDRESS PhysicalAddress,
    _Out_writes_bytes_(Bytes) UCHAR* Buffer,
    _In_ ULONG Bytes
    )
{
    MM_COPY_ADDRESS source;
    SIZE_T copied = 0U;
    NTSTATUS status = STATUS_SUCCESS;

    if (Buffer == NULL || Bytes == 0UL) {
        return STATUS_INVALID_PARAMETER;
    }
    RtlZeroMemory(&source, sizeof(source));
    source.PhysicalAddress = PhysicalAddress;
    status = MmCopyMemory(
        Buffer,
        source,
        Bytes,
        MM_COPY_MEMORY_PHYSICAL,
        &copied);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    return copied == Bytes ? STATUS_SUCCESS : STATUS_PARTIAL_COPY;
}

static VOID
KswordARKSlatRunAliasProbes(
    _Inout_ KSWORD_ARK_QUERY_SLAT_IOMMU_AUDIT_RESPONSE* Response
    )
{
    ULONG targetIndex = 0UL;

    if (Response == NULL) {
        return;
    }
    Response->fieldFlags |= KSWORD_ARK_SLAT_IOMMU_FIELD_ALIAS_PROBES;
    for (targetIndex = 0UL;
         targetIndex < RTL_NUMBER_OF(g_KswordSlatProbeTargets) &&
         Response->probeCount < KSWORD_ARK_SLAT_IOMMU_MAX_PROBES;
         ++targetIndex) {
        const KSW_SLAT_PROBE_TARGET* target =
            &g_KswordSlatProbeTargets[targetIndex];
        KSWORD_ARK_SLAT_PROBE_ROW* row =
            &Response->probes[Response->probeCount++];
        UNICODE_STRING routineName;
        PVOID routineAddress = NULL;
        PHYSICAL_ADDRESS physicalAddress;
        UCHAR virtualFirst[KSW_SLAT_PROBE_BYTES] = { 0 };
        UCHAR virtualSecond[KSW_SLAT_PROBE_BYTES] = { 0 };
        UCHAR physicalFirst[KSW_SLAT_PROBE_BYTES] = { 0 };
        UCHAR physicalSecond[KSW_SLAT_PROBE_BYTES] = { 0 };
        ULONG bytes = KSW_SLAT_PROBE_BYTES;
        ULONG pageRemaining = 0UL;
        NTSTATUS virtualStatus = STATUS_SUCCESS;
        NTSTATUS physicalStatus = STATUS_SUCCESS;

        RtlZeroMemory(row, sizeof(*row));
        row->status = STATUS_NOT_FOUND;
        KswordARKSlatCopyAscii(
            row->name,
            RTL_NUMBER_OF(row->name),
            target->AnsiName,
            KswordARKSlatAsciiLength(target->AnsiName));
        RtlInitUnicodeString(&routineName, target->WideName);
        routineAddress = MmGetSystemRoutineAddress(&routineName);
        if (routineAddress == NULL) {
            continue;
        }
        row->virtualAddress = (ULONGLONG)(ULONG_PTR)routineAddress;
        pageRemaining = PAGE_SIZE -
            ((ULONG)(ULONG_PTR)routineAddress & (PAGE_SIZE - 1UL));
        if (bytes > pageRemaining) {
            bytes = pageRemaining;
            row->flags |= KSWORD_ARK_SLAT_PROBE_FLAG_PAGE_BOUNDARY;
        }
        if (bytes == 0UL) {
            row->status = STATUS_INVALID_ADDRESS;
            continue;
        }
        virtualStatus = KswordARKSlatReadVirtual(
            routineAddress,
            virtualFirst,
            bytes);
        if (!NT_SUCCESS(virtualStatus)) {
            row->status = virtualStatus;
            continue;
        }
        KeMemoryBarrier();
        virtualStatus = KswordARKSlatReadVirtual(
            routineAddress,
            virtualSecond,
            bytes);
        if (!NT_SUCCESS(virtualStatus)) {
            row->status = virtualStatus;
            continue;
        }
        row->flags |= KSWORD_ARK_SLAT_PROBE_FLAG_VIRTUAL_READ;
        if (!KswordARKSlatBufferEqual(virtualFirst, virtualSecond, bytes)) {
            row->flags |= KSWORD_ARK_SLAT_PROBE_FLAG_VIRTUAL_UNSTABLE;
            ++Response->unstableCount;
            Response->riskFlags |= KSWORD_ARK_SLAT_IOMMU_RISK_ALIAS_UNSTABLE;
        }

        physicalAddress = MmGetPhysicalAddress(routineAddress);
        row->physicalAddress = (ULONGLONG)physicalAddress.QuadPart;
        physicalStatus = KswordARKSlatReadPhysical(
            physicalAddress,
            physicalFirst,
            bytes);
        if (!NT_SUCCESS(physicalStatus)) {
            row->status = physicalStatus;
            row->virtualHash = KswordARKSlatHashBytes(virtualFirst, bytes);
            row->bytesCompared = bytes;
            continue;
        }
        KeMemoryBarrier();
        physicalStatus = KswordARKSlatReadPhysical(
            physicalAddress,
            physicalSecond,
            bytes);
        if (!NT_SUCCESS(physicalStatus)) {
            row->status = physicalStatus;
            row->virtualHash = KswordARKSlatHashBytes(virtualFirst, bytes);
            row->bytesCompared = bytes;
            continue;
        }
        row->flags |= KSWORD_ARK_SLAT_PROBE_FLAG_PHYSICAL_READ;
        Response->featureFlags |=
            KSWORD_ARK_SLAT_IOMMU_FEATURE_PHYSICAL_ALIAS;
        if (!KswordARKSlatBufferEqual(physicalFirst, physicalSecond, bytes)) {
            row->flags |= KSWORD_ARK_SLAT_PROBE_FLAG_PHYSICAL_UNSTABLE;
            ++Response->unstableCount;
            Response->riskFlags |= KSWORD_ARK_SLAT_IOMMU_RISK_ALIAS_UNSTABLE;
        }
        row->virtualHash = KswordARKSlatHashBytes(virtualSecond, bytes);
        row->physicalHash = KswordARKSlatHashBytes(physicalSecond, bytes);
        row->bytesCompared = bytes;
        if (KswordARKSlatBufferEqual(virtualSecond, physicalSecond, bytes)) {
            row->flags |= KSWORD_ARK_SLAT_PROBE_FLAG_HASH_MATCH;
        }
        else {
            row->flags |= KSWORD_ARK_SLAT_PROBE_FLAG_HASH_MISMATCH;
            ++Response->mismatchCount;
            Response->riskFlags |= KSWORD_ARK_SLAT_IOMMU_RISK_ALIAS_MISMATCH;
        }
        row->status = STATUS_SUCCESS;
    }
}

static VOID
KswordARKSlatSortTiming(
    _Inout_updates_(Count) ULONGLONG* Values,
    _In_ ULONG Count
    )
{
    ULONG index = 0UL;

    for (index = 1UL; index < Count; ++index) {
        ULONGLONG value = Values[index];
        ULONG cursor = index;
        while (cursor > 0UL && Values[cursor - 1UL] > value) {
            Values[cursor] = Values[cursor - 1UL];
            --cursor;
        }
        Values[cursor] = value;
    }
}

static VOID
KswordARKSlatMeasureCpuid(
    _Inout_ KSWORD_ARK_QUERY_SLAT_IOMMU_AUDIT_RESPONSE* Response
    )
{
#if defined(_M_AMD64) || defined(_M_IX86)
    ULONGLONG samples[KSW_SLAT_TIMING_SAMPLES] = { 0 };
    ULONG index = 0UL;
    int registers[4] = { 0 };

    if (Response == NULL) {
        return;
    }
    for (index = 0UL; index < KSW_SLAT_TIMING_SAMPLES; ++index) {
        ULONGLONG before = __rdtsc();
        __cpuidex(registers, 0, 0);
        samples[index] = __rdtsc() - before;
    }
    KswordARKSlatSortTiming(samples, KSW_SLAT_TIMING_SAMPLES);
    Response->cpuidCyclesMinimum = samples[0];
    Response->cpuidCyclesMedian = samples[KSW_SLAT_TIMING_SAMPLES / 2UL];
    Response->cpuidCyclesMaximum = samples[KSW_SLAT_TIMING_SAMPLES - 1UL];
    if (Response->cpuidCyclesMedian != 0ULL &&
        Response->cpuidCyclesMaximum >
            Response->cpuidCyclesMedian * 8ULL) {
        Response->riskFlags |= KSWORD_ARK_SLAT_IOMMU_RISK_TIMING_VARIANCE;
    }
#else
    UNREFERENCED_PARAMETER(Response);
#endif
}

static VOID
KswordARKSlatQueryCpu(
    _Inout_ KSWORD_ARK_QUERY_SLAT_IOMMU_AUDIT_RESPONSE* Response
    )
{
#if defined(_M_AMD64) || defined(_M_IX86)
    int registers[4] = { 0 };
    CHAR vendor[13] = { 0 };
    CHAR hypervisorVendor[13] = { 0 };
    ULONG leaf1Ecx = 0UL;

    if (Response == NULL) {
        return;
    }
    Response->fieldFlags |= KSWORD_ARK_SLAT_IOMMU_FIELD_CPUID;
    __cpuidex(registers, 0, 0);
    Response->cpuidMaxBasic = (ULONG)registers[0];
    RtlCopyMemory(vendor + 0, &registers[1], sizeof(ULONG));
    RtlCopyMemory(vendor + 4, &registers[3], sizeof(ULONG));
    RtlCopyMemory(vendor + 8, &registers[2], sizeof(ULONG));
    KswordARKSlatCopyAscii(
        Response->cpuVendor,
        RTL_NUMBER_OF(Response->cpuVendor),
        vendor,
        12UL);

    __cpuidex(registers, (int)0x80000000UL, 0);
    Response->cpuidMaxExtended = (ULONG)registers[0];
    __cpuidex(registers, 1, 0);
    leaf1Ecx = (ULONG)registers[2];
    if ((leaf1Ecx & (1UL << 31)) != 0UL) {
        Response->featureFlags |= KSWORD_ARK_SLAT_IOMMU_FEATURE_HYPERVISOR;
        Response->riskFlags |= KSWORD_ARK_SLAT_IOMMU_RISK_HYPERVISOR_OPAQUE;
        __cpuidex(registers, (int)0x40000000UL, 0);
        Response->cpuidMaxHypervisor = (ULONG)registers[0];
        RtlCopyMemory(hypervisorVendor + 0, &registers[1], sizeof(ULONG));
        RtlCopyMemory(hypervisorVendor + 4, &registers[2], sizeof(ULONG));
        RtlCopyMemory(hypervisorVendor + 8, &registers[3], sizeof(ULONG));
        KswordARKSlatCopyAscii(
            Response->hypervisorVendor,
            RTL_NUMBER_OF(Response->hypervisorVendor),
            hypervisorVendor,
            12UL);
        if (Response->cpuidMaxHypervisor < 0x40000000UL ||
            hypervisorVendor[0] == '\0') {
            Response->riskFlags |=
                KSWORD_ARK_SLAT_IOMMU_RISK_CPUID_INCONSISTENT;
        }
    }

    if (RtlCompareMemory(vendor, "GenuineIntel", 12UL) == 12UL) {
        ULONGLONG secondaryControls = 0ULL;
        Response->featureFlags |= KSWORD_ARK_SLAT_IOMMU_FEATURE_INTEL;
        if ((leaf1Ecx & (1UL << 5)) != 0UL) {
            Response->featureFlags |= KSWORD_ARK_SLAT_IOMMU_FEATURE_VMX;
            __try {
                Response->vmxFeatureControl =
                    __readmsr(KSW_IA32_FEATURE_CONTROL);
                secondaryControls =
                    __readmsr(KSW_IA32_VMX_PROCBASED_CTLS2);
                Response->vmxEptVpidCapabilities =
                    __readmsr(KSW_IA32_VMX_EPT_VPID_CAP);
                Response->fieldFlags |=
                    KSWORD_ARK_SLAT_IOMMU_FIELD_VIRTUALIZATION_MSR;
                if (((secondaryControls >> 32) & (1ULL << 1)) != 0ULL &&
                    (Response->vmxEptVpidCapabilities & (1ULL << 6)) != 0ULL) {
                    Response->featureFlags |=
                        KSWORD_ARK_SLAT_IOMMU_FEATURE_EPT;
                }
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {
                /* Nested or filtered VMX MSRs may be intentionally opaque. */
            }
        }
    }
    else if (RtlCompareMemory(vendor, "AuthenticAMD", 12UL) == 12UL) {
        Response->featureFlags |= KSWORD_ARK_SLAT_IOMMU_FEATURE_AMD;
        if (Response->cpuidMaxExtended >= 0x80000001UL) {
            __cpuidex(registers, (int)0x80000001UL, 0);
            if (((ULONG)registers[2] & (1UL << 2)) != 0UL) {
                Response->featureFlags |= KSWORD_ARK_SLAT_IOMMU_FEATURE_SVM;
            }
        }
        if (Response->cpuidMaxExtended >= 0x8000000AUL) {
            __cpuidex(registers, (int)0x8000000AUL, 0);
            if (((ULONG)registers[3] & 0x1UL) != 0UL) {
                Response->featureFlags |= KSWORD_ARK_SLAT_IOMMU_FEATURE_NPT;
            }
        }
        else if ((Response->featureFlags &
            KSWORD_ARK_SLAT_IOMMU_FEATURE_SVM) != 0ULL) {
            Response->riskFlags |=
                KSWORD_ARK_SLAT_IOMMU_RISK_CPUID_INCONSISTENT;
        }
        __try {
            Response->amdEfer = __readmsr(KSW_AMD_EFER);
            Response->amdVmCr = __readmsr(KSW_AMD_VM_CR);
            Response->fieldFlags |=
                KSWORD_ARK_SLAT_IOMMU_FIELD_VIRTUALIZATION_MSR;
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            /* A parent VMM may filter SVM MSRs while preserving CPUID data. */
        }
    }
    else {
        Response->riskFlags |= KSWORD_ARK_SLAT_IOMMU_RISK_CPUID_INCONSISTENT;
    }
    KswordARKSlatMeasureCpuid(Response);
#else
    UNREFERENCED_PARAMETER(Response);
#endif
}

static BOOLEAN
KswordARKSlatAcpiChecksumValid(
    _In_ const DESCRIPTION_HEADER* Header,
    _In_ ULONG MinimumLength
    )
{
    ULONG index = 0UL;
    UCHAR checksum = 0U;

    if (Header == NULL) {
        return FALSE;
    }
    __try {
        if (Header->Length < MinimumLength || Header->Length > (1024UL * 1024UL)) {
            return FALSE;
        }
        for (index = 0UL; index < Header->Length; ++index) {
            checksum = (UCHAR)(checksum + ((const UCHAR*)Header)[index]);
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return FALSE;
    }
    return checksum == 0U ? TRUE : FALSE;
}

static KSWORD_ARK_IOMMU_ROW*
KswordARKSlatAppendIommuRow(
    _Inout_ KSWORD_ARK_QUERY_SLAT_IOMMU_AUDIT_RESPONSE* Response
    )
{
    KSWORD_ARK_IOMMU_ROW* row = NULL;

    if (Response == NULL) {
        return NULL;
    }
    if (Response->iommuRowCount >= KSWORD_ARK_SLAT_IOMMU_MAX_ROWS) {
        Response->riskFlags |= KSWORD_ARK_SLAT_IOMMU_RISK_TRUNCATED;
        return NULL;
    }
    row = &Response->iommuRows[Response->iommuRowCount++];
    RtlZeroMemory(row, sizeof(*row));
    row->status = STATUS_SUCCESS;
    return row;
}

static ULONG
KswordARKSlatCountDeviceScopes(
    _In_reads_bytes_(Bytes) const UCHAR* Buffer,
    _In_ ULONG Bytes,
    _Out_ BOOLEAN* MalformedOut,
    _Out_opt_ ULONG* FirstDeviceIdOut
    )
{
    ULONG count = 0UL;
    ULONG offset = 0UL;

    if (MalformedOut == NULL) {
        return 0UL;
    }
    *MalformedOut = FALSE;
    if (FirstDeviceIdOut != NULL) {
        *FirstDeviceIdOut = 0UL;
    }
    while (offset < Bytes) {
        const DEVICESCOPE* scope = NULL;
        if (Bytes - offset < DEVICE_SCOPE_MIN_SIZE) {
            *MalformedOut = TRUE;
            break;
        }
        scope = (const DEVICESCOPE*)(Buffer + offset);
        if (scope->Length < DEVICE_SCOPE_MIN_SIZE || scope->Length > Bytes - offset) {
            *MalformedOut = TRUE;
            break;
        }
        if (((scope->Length - FIELD_OFFSET(DEVICESCOPE, PCIPath)) %
             sizeof(scope->PCIPath[0])) != 0U) {
            *MalformedOut = TRUE;
            break;
        }
        if (count == 0UL && FirstDeviceIdOut != NULL) {
            *FirstDeviceIdOut =
                ((ULONG)scope->StartBusNumber << 8) |
                ((ULONG)scope->PCIPath[0].Device << 3) |
                (ULONG)scope->PCIPath[0].Function;
        }
        ++count;
        offset += scope->Length;
    }
    return count;
}

static NTSTATUS
KswordARKSlatReadVtdMmio(
    _In_ ULONGLONG BaseAddress,
    _Inout_ KSWORD_ARK_IOMMU_ROW* Row,
    _Inout_ KSWORD_ARK_QUERY_SLAT_IOMMU_AUDIT_RESPONSE* Response
    )
{
    PHYSICAL_ADDRESS physicalAddress;
    PVOID mapping = NULL;
    NTSTATUS status = STATUS_SUCCESS;

    if (Row == NULL || Response == NULL || BaseAddress == 0ULL ||
        (BaseAddress & (PAGE_SIZE - 1ULL)) != 0ULL) {
        return STATUS_INVALID_PARAMETER;
    }
    physicalAddress.QuadPart = (LONGLONG)BaseAddress;
    mapping = MmMapIoSpaceEx(
        physicalAddress,
        KSW_VTD_MMIO_BYTES,
        PAGE_READONLY | PAGE_NOCACHE);
    if (mapping == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    __try {
        Row->capability = READ_REGISTER_ULONG64(
            (volatile ULONG64*)((PUCHAR)mapping + 0x08));
        Row->extendedCapability = READ_REGISTER_ULONG64(
            (volatile ULONG64*)((PUCHAR)mapping + 0x10));
        Row->statusRegister = (ULONGLONG)READ_REGISTER_ULONG(
            (volatile ULONG*)((PUCHAR)mapping + 0x1C));
        Row->rootTableAddress = READ_REGISTER_ULONG64(
            (volatile ULONG64*)((PUCHAR)mapping + 0x20));
        Row->flags |= KSWORD_ARK_IOMMU_ROW_FLAG_MMIO_READ;
        Response->fieldFlags |= KSWORD_ARK_SLAT_IOMMU_FIELD_MMIO;
        if ((Row->statusRegister & (1ULL << 31)) != 0ULL) {
            Row->flags |= KSWORD_ARK_IOMMU_ROW_FLAG_TRANSLATION;
            Response->featureFlags |=
                KSWORD_ARK_SLAT_IOMMU_FEATURE_VTD_TRANSLATION;
        }
        else {
            Response->riskFlags |=
                KSWORD_ARK_SLAT_IOMMU_RISK_TRANSLATION_DISABLED;
        }
        if ((Row->statusRegister & (1ULL << 25)) != 0ULL) {
            Row->flags |= KSWORD_ARK_IOMMU_ROW_FLAG_INTERRUPT_REMAP;
            Response->featureFlags |=
                KSWORD_ARK_SLAT_IOMMU_FEATURE_VTD_INTERRUPT_REMAP;
        }
        if ((Row->statusRegister & (1ULL << 30)) != 0ULL &&
            (Row->rootTableAddress & 0x000FFFFFFFFFF000ULL) != 0ULL) {
            Row->flags |= KSWORD_ARK_IOMMU_ROW_FLAG_ROOT_TABLE_VALID;
        }
        else if ((Row->flags & KSWORD_ARK_IOMMU_ROW_FLAG_TRANSLATION) != 0UL) {
            Response->riskFlags |=
                KSWORD_ARK_SLAT_IOMMU_RISK_ROOT_TABLE_UNAVAILABLE;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();
    }
    MmUnmapIoSpace(mapping, KSW_VTD_MMIO_BYTES);
    return status;
}

static NTSTATUS
KswordARKSlatReadAmdIommuMmio(
    _In_ ULONGLONG BaseAddress,
    _Inout_ KSWORD_ARK_IOMMU_ROW* Row,
    _Inout_ KSWORD_ARK_QUERY_SLAT_IOMMU_AUDIT_RESPONSE* Response
    )
{
    PHYSICAL_ADDRESS physicalAddress;
    PVOID mapping = NULL;
    NTSTATUS status = STATUS_SUCCESS;

    if (Row == NULL || Response == NULL || BaseAddress == 0ULL ||
        (BaseAddress & (PAGE_SIZE - 1ULL)) != 0ULL) {
        return STATUS_INVALID_PARAMETER;
    }
    physicalAddress.QuadPart = (LONGLONG)BaseAddress;
    mapping = MmMapIoSpaceEx(
        physicalAddress,
        KSW_AMD_IOMMU_MMIO_BYTES,
        PAGE_READONLY | PAGE_NOCACHE);
    if (mapping == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    __try {
        Row->rootTableAddress = READ_REGISTER_ULONG64(
            (volatile ULONG64*)((PUCHAR)mapping + 0x00));
        Row->capability = READ_REGISTER_ULONG64(
            (volatile ULONG64*)((PUCHAR)mapping + 0x18));
        Row->extendedCapability = READ_REGISTER_ULONG64(
            (volatile ULONG64*)((PUCHAR)mapping + 0x30));
        Row->statusRegister = READ_REGISTER_ULONG64(
            (volatile ULONG64*)((PUCHAR)mapping + 0x2020));
        Row->flags |= KSWORD_ARK_IOMMU_ROW_FLAG_MMIO_READ;
        Response->fieldFlags |= KSWORD_ARK_SLAT_IOMMU_FIELD_MMIO;
        if ((Row->capability & 0x1ULL) != 0ULL) {
            Row->flags |= KSWORD_ARK_IOMMU_ROW_FLAG_TRANSLATION;
        }
        else {
            Response->riskFlags |=
                KSWORD_ARK_SLAT_IOMMU_RISK_TRANSLATION_DISABLED;
        }
        if ((Row->rootTableAddress & 0x000FFFFFFFFFF000ULL) != 0ULL) {
            Row->flags |= KSWORD_ARK_IOMMU_ROW_FLAG_ROOT_TABLE_VALID;
        }
        else if ((Row->flags & KSWORD_ARK_IOMMU_ROW_FLAG_TRANSLATION) != 0UL) {
            Response->riskFlags |=
                KSWORD_ARK_SLAT_IOMMU_RISK_ROOT_TABLE_UNAVAILABLE;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();
    }
    MmUnmapIoSpace(mapping, KSW_AMD_IOMMU_MMIO_BYTES);
    return status;
}

static NTSTATUS
KswordARKSlatParseDmar(
    _In_ BOOLEAN IncludeMmio,
    _Inout_ KSWORD_ARK_QUERY_SLAT_IOMMU_AUDIT_RESPONSE* Response
    )
{
    const DMAR* dmar = NULL;
    const UCHAR* cursor = NULL;
    const UCHAR* end = NULL;
    pHalGetAcpiTable getAcpiTable = NULL;

    if (Response == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    getAcpiTable = KswordARKSlatResolveAcpiGetter();
    if (getAcpiTable == NULL) {
        return STATUS_PROCEDURE_NOT_FOUND;
    }
    dmar = (const DMAR*)getAcpiTable(
        DMAR_SIGNATURE,
        NULL,
        NULL);
    if (dmar == NULL) {
        return STATUS_NOT_FOUND;
    }
    Response->fieldFlags |= KSWORD_ARK_SLAT_IOMMU_FIELD_DMAR;
    Response->featureFlags |= KSWORD_ARK_SLAT_IOMMU_FEATURE_DMAR;
    if (!KswordARKSlatAcpiChecksumValid(
            &dmar->Header,
            FIELD_OFFSET(DMAR, DMARTables))) {
        Response->riskFlags |= KSWORD_ARK_SLAT_IOMMU_RISK_ACPI_CHECKSUM;
    }
    __try {
        Response->dmarFlags = dmar->Flags;
        Response->dmarHostAddressWidth = dmar->HostAddressWidth;
        if ((dmar->Flags & DMAR_FLAG_DMA_CTRL_PLATFORM_OPT_IN) != 0U) {
            Response->featureFlags |=
                KSWORD_ARK_SLAT_IOMMU_FEATURE_DMA_GUARD_OPT_IN;
        }
        cursor = (const UCHAR*)dmar + FIELD_OFFSET(DMAR, DMARTables);
        end = (const UCHAR*)dmar + dmar->Header.Length;
        while (cursor < end) {
            const DMARTABLE* table = NULL;
            KSWORD_ARK_IOMMU_ROW* row = NULL;
            BOOLEAN malformed = FALSE;
            ULONG fixedBytes = sizeof(USHORT) * 2UL;

            if ((ULONG_PTR)(end - cursor) < sizeof(USHORT) * 2UL) {
                Response->riskFlags |=
                    KSWORD_ARK_SLAT_IOMMU_RISK_ACPI_MALFORMED;
                ++Response->malformedRowCount;
                break;
            }
            table = (const DMARTABLE*)cursor;
            if (table->Length < sizeof(USHORT) * 2UL ||
                table->Length > (ULONG_PTR)(end - cursor)) {
                Response->riskFlags |=
                    KSWORD_ARK_SLAT_IOMMU_RISK_ACPI_MALFORMED;
                ++Response->malformedRowCount;
                break;
            }
            row = KswordARKSlatAppendIommuRow(Response);
            if (row == NULL) {
                break;
            }
            switch (table->Type) {
            case DMAR_DRHD:
                row->type = KSWORD_ARK_IOMMU_ROW_INTEL_DRHD;
                fixedBytes = DMAR_DRHD_MIN_SIZE;
                if (table->Length >= fixedBytes) {
                    row->firmwareFlags = table->Drhd.Flags;
                    row->flags = (table->Drhd.Flags & DRHD_INCLUDE_ALL) != 0U
                        ? KSWORD_ARK_IOMMU_ROW_FLAG_INCLUDE_ALL
                        : 0UL;
                    row->segment = table->Drhd.SegmentNumber;
                    row->baseAddress = table->Drhd.BaseAddress;
                    row->scopeCount = KswordARKSlatCountDeviceScopes(
                        cursor + fixedBytes,
                        table->Length - fixedBytes,
                        &malformed,
                        &row->deviceId);
                    if (IncludeMmio != FALSE) {
                        row->status = KswordARKSlatReadVtdMmio(
                            row->baseAddress,
                            row,
                            Response);
                        if (!NT_SUCCESS(row->status)) {
                            Response->riskFlags |=
                                KSWORD_ARK_SLAT_IOMMU_RISK_MMIO_UNREADABLE;
                        }
                    }
                }
                else {
                    malformed = TRUE;
                }
                break;
            case DMAR_RMRR:
                row->type = KSWORD_ARK_IOMMU_ROW_INTEL_RMRR;
                fixedBytes = 24UL;
                if (table->Length >= fixedBytes) {
                    row->flags |=
                        KSWORD_ARK_IOMMU_ROW_FLAG_RESERVED_MEMORY;
                    row->segment = table->Rmrr.SegmentNumber;
                    row->baseAddress = table->Rmrr.RegionBaseAddress;
                    row->limitAddress = table->Rmrr.RegionLimitAddress;
                    row->scopeCount = KswordARKSlatCountDeviceScopes(
                        cursor + fixedBytes,
                        table->Length - fixedBytes,
                        &malformed,
                        &row->deviceId);
                    ++Response->reservedMemoryCount;
                    Response->riskFlags |=
                        KSWORD_ARK_SLAT_IOMMU_RISK_RESERVED_MEMORY_PRESENT;
                }
                else {
                    malformed = TRUE;
                }
                break;
            case DMAR_ATSR:
                row->type = KSWORD_ARK_IOMMU_ROW_INTEL_ATSR;
                fixedBytes = 8UL;
                if (table->Length >= fixedBytes) {
                    row->segment = table->Atsr.SegmentNumber;
                    row->firmwareFlags = table->Atsr.Flags;
                    row->scopeCount = KswordARKSlatCountDeviceScopes(
                        cursor + fixedBytes,
                        table->Length - fixedBytes,
                        &malformed,
                        &row->deviceId);
                }
                else {
                    malformed = TRUE;
                }
                break;
            case DMAR_RHSA:
                row->type = KSWORD_ARK_IOMMU_ROW_INTEL_RHSA;
                if (table->Length >= sizeof(RHSA)) {
                    const RHSA* rhsa = (const RHSA*)cursor;
                    row->baseAddress = rhsa->RegisterBaseAddress;
                    row->segment = rhsa->ProximityDomain;
                }
                else {
                    malformed = TRUE;
                }
                break;
            case DMAR_ANDD:
                row->type = KSWORD_ARK_IOMMU_ROW_INTEL_ANDD;
                break;
            case DMAR_SATC:
                row->type = KSWORD_ARK_IOMMU_ROW_INTEL_SATC;
                fixedBytes = 8UL;
                if (table->Length >= fixedBytes) {
                    row->firmwareFlags = table->Satc.Flags;
                    row->segment = table->Satc.SegmentNumber;
                    row->scopeCount = KswordARKSlatCountDeviceScopes(
                        cursor + fixedBytes,
                        table->Length - fixedBytes,
                        &malformed,
                        &row->deviceId);
                }
                else {
                    malformed = TRUE;
                }
                break;
            default:
                row->type = KSWORD_ARK_IOMMU_ROW_UNKNOWN;
                break;
            }
            if (malformed != FALSE) {
                row->flags |= KSWORD_ARK_IOMMU_ROW_FLAG_MALFORMED;
                row->status = STATUS_DATA_ERROR;
                ++Response->malformedRowCount;
                Response->riskFlags |=
                    KSWORD_ARK_SLAT_IOMMU_RISK_ACPI_MALFORMED;
            }
            cursor += table->Length;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        Response->riskFlags |= KSWORD_ARK_SLAT_IOMMU_RISK_ACPI_MALFORMED;
        return GetExceptionCode();
    }
    return STATUS_SUCCESS;
}

static NTSTATUS
KswordARKSlatParseIvrs(
    _In_ BOOLEAN IncludeMmio,
    _Inout_ KSWORD_ARK_QUERY_SLAT_IOMMU_AUDIT_RESPONSE* Response
    )
{
    const IVRS* ivrs = NULL;
    const UCHAR* cursor = NULL;
    const UCHAR* end = NULL;
    pHalGetAcpiTable getAcpiTable = NULL;

    if (Response == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    getAcpiTable = KswordARKSlatResolveAcpiGetter();
    if (getAcpiTable == NULL) {
        return STATUS_PROCEDURE_NOT_FOUND;
    }
    ivrs = (const IVRS*)getAcpiTable(
        IVRS_SIGNATURE,
        NULL,
        NULL);
    if (ivrs == NULL) {
        return STATUS_NOT_FOUND;
    }
    Response->fieldFlags |= KSWORD_ARK_SLAT_IOMMU_FIELD_IVRS;
    Response->featureFlags |= KSWORD_ARK_SLAT_IOMMU_FEATURE_IVRS;
    if (!KswordARKSlatAcpiChecksumValid(
            &ivrs->Header,
            FIELD_OFFSET(IVRS, DefinitionBlocks))) {
        Response->riskFlags |= KSWORD_ARK_SLAT_IOMMU_RISK_ACPI_CHECKSUM;
    }
    __try {
        Response->ivrsInfo = ivrs->IVInfo.AsUINT32;
        if (ivrs->IVInfo.DmaGuardOptIn != 0U) {
            Response->featureFlags |=
                KSWORD_ARK_SLAT_IOMMU_FEATURE_DMA_GUARD_OPT_IN;
        }
        cursor = (const UCHAR*)ivrs + FIELD_OFFSET(IVRS, DefinitionBlocks);
        end = (const UCHAR*)ivrs + ivrs->Header.Length;
        while (cursor < end) {
            const IVRS_BLOCK_HEADER* header = NULL;
            KSWORD_ARK_IOMMU_ROW* row = NULL;
            BOOLEAN malformed = FALSE;

            if ((ULONG_PTR)(end - cursor) < sizeof(IVRS_BLOCK_HEADER)) {
                ++Response->malformedRowCount;
                Response->riskFlags |=
                    KSWORD_ARK_SLAT_IOMMU_RISK_ACPI_MALFORMED;
                break;
            }
            header = (const IVRS_BLOCK_HEADER*)cursor;
            if (header->Length < sizeof(IVRS_BLOCK_HEADER) ||
                header->Length > (ULONG_PTR)(end - cursor)) {
                ++Response->malformedRowCount;
                Response->riskFlags |=
                    KSWORD_ARK_SLAT_IOMMU_RISK_ACPI_MALFORMED;
                break;
            }
            row = KswordARKSlatAppendIommuRow(Response);
            if (row == NULL) {
                break;
            }
            row->firmwareFlags = header->Flags;
            switch (header->Type) {
            case IommuDefinitionBlockTypeIvhd:
            case IommuDefinitionBlockType11Ivhd:
            case IommuDefinitionBlockType40Ivhd:
                row->type = KSWORD_ARK_IOMMU_ROW_AMD_IVHD;
                if (header->Length >= 24UL) {
                    const IVHD_BLOCK* ivhd = (const IVHD_BLOCK*)cursor;
                    row->deviceId = ivhd->DeviceId;
                    row->segment = ivhd->PciSegment;
                    row->baseAddress = ivhd->IommuBaseAddress;
                    if (IncludeMmio != FALSE) {
                        row->status = KswordARKSlatReadAmdIommuMmio(
                            row->baseAddress,
                            row,
                            Response);
                        if (!NT_SUCCESS(row->status)) {
                            Response->riskFlags |=
                                KSWORD_ARK_SLAT_IOMMU_RISK_MMIO_UNREADABLE;
                        }
                    }
                }
                else {
                    malformed = TRUE;
                }
                break;
            case IommuDefinitionBlockTypeIvmdAll:
            case IommuDefinitionBlockTypeIvmdSpecified:
            case IommuDefinitionBlockTypeIvmdRange:
                row->type = KSWORD_ARK_IOMMU_ROW_AMD_IVMD;
                if (header->Length >= sizeof(IVMD_BLOCK)) {
                    const IVMD_BLOCK* ivmd = (const IVMD_BLOCK*)cursor;
                    row->flags |=
                        KSWORD_ARK_IOMMU_ROW_FLAG_RESERVED_MEMORY;
                    row->deviceId = ivmd->u1.DeviceId;
                    row->endDeviceId = ivmd->u2.EndDeviceId;
                    row->baseAddress = ivmd->StartAddress;
                    row->limitAddress = ivmd->MemoryBlockLength == 0ULL
                        ? ivmd->StartAddress
                        : ivmd->StartAddress + ivmd->MemoryBlockLength - 1ULL;
                    ++Response->reservedMemoryCount;
                    Response->riskFlags |=
                        KSWORD_ARK_SLAT_IOMMU_RISK_RESERVED_MEMORY_PRESENT;
                }
                else {
                    malformed = TRUE;
                }
                break;
            default:
                row->type = KSWORD_ARK_IOMMU_ROW_UNKNOWN;
                break;
            }
            if (malformed != FALSE) {
                row->flags |= KSWORD_ARK_IOMMU_ROW_FLAG_MALFORMED;
                row->status = STATUS_DATA_ERROR;
                ++Response->malformedRowCount;
                Response->riskFlags |=
                    KSWORD_ARK_SLAT_IOMMU_RISK_ACPI_MALFORMED;
            }
            cursor += header->Length;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        Response->riskFlags |= KSWORD_ARK_SLAT_IOMMU_RISK_ACPI_MALFORMED;
        return GetExceptionCode();
    }
    return STATUS_SUCCESS;
}

static VOID
KswordARKSlatQueryIommuInterfaces(
    _Inout_ KSWORD_ARK_QUERY_SLAT_IOMMU_AUDIT_RESPONSE* Response
    )
{
    UNICODE_STRING routineName;
    KSW_IO_GET_IOMMU_INTERFACE_FN getInterface = NULL;
    KSW_IO_GET_IOMMU_INTERFACE_EX_FN getInterfaceEx = NULL;
    DMA_IOMMU_INTERFACE interfaceValue;
    DMA_IOMMU_INTERFACE_EX interfaceExValue;
    ULONG version = 0UL;

    if (Response == NULL) {
        return;
    }
    Response->iommuInterfaceStatus = STATUS_PROCEDURE_NOT_FOUND;
    Response->iommuInterfaceExStatus = STATUS_PROCEDURE_NOT_FOUND;
    RtlInitUnicodeString(&routineName, L"IoGetIommuInterface");
    getInterface = (KSW_IO_GET_IOMMU_INTERFACE_FN)
        MmGetSystemRoutineAddress(&routineName);
    if (getInterface != NULL) {
        Response->featureFlags |=
            KSWORD_ARK_SLAT_IOMMU_FEATURE_IOMMU_EXPORT;
        Response->fieldFlags |=
            KSWORD_ARK_SLAT_IOMMU_FIELD_IOMMU_INTERFACE;
        RtlZeroMemory(&interfaceValue, sizeof(interfaceValue));
        Response->iommuInterfaceStatus = getInterface(
            DMA_IOMMU_INTERFACE_VERSION,
            &interfaceValue);
        if (NT_SUCCESS(Response->iommuInterfaceStatus)) {
            Response->iommuInterfaceVersion = interfaceValue.Version;
            Response->featureFlags |=
                KSWORD_ARK_SLAT_IOMMU_FEATURE_IOMMU_INTERFACE;
        }
    }

    RtlInitUnicodeString(&routineName, L"IoGetIommuInterfaceEx");
    getInterfaceEx = (KSW_IO_GET_IOMMU_INTERFACE_EX_FN)
        MmGetSystemRoutineAddress(&routineName);
    if (getInterfaceEx == NULL) {
        return;
    }
    Response->featureFlags |=
        KSWORD_ARK_SLAT_IOMMU_FEATURE_IOMMU_EX_EXPORT;
    Response->fieldFlags |=
        KSWORD_ARK_SLAT_IOMMU_FIELD_IOMMU_INTERFACE;
    for (version = DMA_IOMMU_INTERFACE_EX_VERSION_MAX;
         version >= DMA_IOMMU_INTERFACE_EX_VERSION_MIN;
         --version) {
        RtlZeroMemory(&interfaceExValue, sizeof(interfaceExValue));
        Response->iommuInterfaceExStatus = getInterfaceEx(
            version,
            0ULL,
            &interfaceExValue);
        if (NT_SUCCESS(Response->iommuInterfaceExStatus)) {
            Response->iommuInterfaceExVersion = interfaceExValue.Version;
            Response->featureFlags |=
                KSWORD_ARK_SLAT_IOMMU_FEATURE_IOMMU_INTERFACE_EX;
            break;
        }
        if (version == DMA_IOMMU_INTERFACE_EX_VERSION_MIN) {
            break;
        }
    }
}

NTSTATUS
KswordARKSlatIommuAuditQuery(
    _In_ const KSWORD_ARK_QUERY_SLAT_IOMMU_AUDIT_REQUEST* Request,
    _Out_ KSWORD_ARK_QUERY_SLAT_IOMMU_AUDIT_RESPONSE* Response
    )
{
    BOOLEAN includeMmio = FALSE;

    if (Request == NULL || Response == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    RtlZeroMemory(Response, sizeof(*Response));
    Response->size = sizeof(*Response);
    Response->version = KSWORD_ARK_SLAT_IOMMU_AUDIT_PROTOCOL_VERSION;
    Response->queryStatus = STATUS_SUCCESS;
    Response->dmarStatus = STATUS_NOT_FOUND;
    Response->ivrsStatus = STATUS_NOT_FOUND;
    Response->iommuInterfaceStatus = STATUS_PROCEDURE_NOT_FOUND;
    Response->iommuInterfaceExStatus = STATUS_PROCEDURE_NOT_FOUND;

    if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
        Response->queryStatus = STATUS_INVALID_DEVICE_STATE;
        return Response->queryStatus;
    }
    if (Request->size != sizeof(*Request) ||
        Request->version != KSWORD_ARK_SLAT_IOMMU_AUDIT_PROTOCOL_VERSION ||
        (Request->flags & ~KSWORD_ARK_SLAT_IOMMU_QUERY_FLAG_INCLUDE_MMIO) != 0UL) {
        Response->queryStatus = STATUS_INVALID_PARAMETER;
        return Response->queryStatus;
    }
    includeMmio = (Request->flags &
        KSWORD_ARK_SLAT_IOMMU_QUERY_FLAG_INCLUDE_MMIO) != 0UL;
    Response->queryFlags = Request->flags;

    KswordARKSlatQueryCpu(Response);
    KswordARKSlatQueryIommuInterfaces(Response);
    Response->dmarStatus = KswordARKSlatParseDmar(includeMmio, Response);
    Response->ivrsStatus = KswordARKSlatParseIvrs(includeMmio, Response);
    KswordARKSlatRunAliasProbes(Response);
    return STATUS_SUCCESS;
}
