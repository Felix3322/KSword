#pragma once

#include "KswordArkProcessIoctl.h"

/* Read-only EPT/NPT cross-view and IOMMU firmware/runtime audit. */
#define KSWORD_ARK_SLAT_IOMMU_AUDIT_PROTOCOL_VERSION 1UL

#define KSWORD_ARK_IOCTL_FUNCTION_QUERY_SLAT_IOMMU_AUDIT 0x8CDUL

#define IOCTL_KSWORD_ARK_QUERY_SLAT_IOMMU_AUDIT \
    CTL_CODE( \
        KSWORD_ARK_IOCTL_DEVICE_TYPE, \
        KSWORD_ARK_IOCTL_FUNCTION_QUERY_SLAT_IOMMU_AUDIT, \
        METHOD_BUFFERED, \
        FILE_ANY_ACCESS)

#define KSWORD_ARK_SLAT_IOMMU_QUERY_FLAG_INCLUDE_MMIO 0x00000001UL

#define KSWORD_ARK_SLAT_IOMMU_FIELD_CPUID          0x00000001UL
#define KSWORD_ARK_SLAT_IOMMU_FIELD_VIRTUALIZATION_MSR 0x00000002UL
#define KSWORD_ARK_SLAT_IOMMU_FIELD_ALIAS_PROBES   0x00000004UL
#define KSWORD_ARK_SLAT_IOMMU_FIELD_DMAR           0x00000008UL
#define KSWORD_ARK_SLAT_IOMMU_FIELD_IVRS           0x00000010UL
#define KSWORD_ARK_SLAT_IOMMU_FIELD_IOMMU_INTERFACE 0x00000020UL
#define KSWORD_ARK_SLAT_IOMMU_FIELD_MMIO           0x00000040UL

#define KSWORD_ARK_SLAT_IOMMU_FEATURE_INTEL              0x0000000000000001ULL
#define KSWORD_ARK_SLAT_IOMMU_FEATURE_AMD                0x0000000000000002ULL
#define KSWORD_ARK_SLAT_IOMMU_FEATURE_VMX                0x0000000000000004ULL
#define KSWORD_ARK_SLAT_IOMMU_FEATURE_EPT                0x0000000000000008ULL
#define KSWORD_ARK_SLAT_IOMMU_FEATURE_SVM                0x0000000000000010ULL
#define KSWORD_ARK_SLAT_IOMMU_FEATURE_NPT                0x0000000000000020ULL
#define KSWORD_ARK_SLAT_IOMMU_FEATURE_HYPERVISOR         0x0000000000000040ULL
#define KSWORD_ARK_SLAT_IOMMU_FEATURE_DMAR               0x0000000000000080ULL
#define KSWORD_ARK_SLAT_IOMMU_FEATURE_IVRS               0x0000000000000100ULL
#define KSWORD_ARK_SLAT_IOMMU_FEATURE_IOMMU_INTERFACE    0x0000000000000200ULL
#define KSWORD_ARK_SLAT_IOMMU_FEATURE_IOMMU_INTERFACE_EX 0x0000000000000400ULL
#define KSWORD_ARK_SLAT_IOMMU_FEATURE_VTD_TRANSLATION    0x0000000000000800ULL
#define KSWORD_ARK_SLAT_IOMMU_FEATURE_VTD_INTERRUPT_REMAP 0x0000000000001000ULL
#define KSWORD_ARK_SLAT_IOMMU_FEATURE_DMA_GUARD_OPT_IN   0x0000000000002000ULL
#define KSWORD_ARK_SLAT_IOMMU_FEATURE_PHYSICAL_ALIAS     0x0000000000004000ULL
#define KSWORD_ARK_SLAT_IOMMU_FEATURE_IOMMU_EXPORT       0x0000000000008000ULL
#define KSWORD_ARK_SLAT_IOMMU_FEATURE_IOMMU_EX_EXPORT    0x0000000000010000ULL

#define KSWORD_ARK_SLAT_IOMMU_RISK_HYPERVISOR_OPAQUE       0x00000001UL
#define KSWORD_ARK_SLAT_IOMMU_RISK_CPUID_INCONSISTENT      0x00000002UL
#define KSWORD_ARK_SLAT_IOMMU_RISK_ALIAS_MISMATCH          0x00000004UL
#define KSWORD_ARK_SLAT_IOMMU_RISK_ALIAS_UNSTABLE          0x00000008UL
#define KSWORD_ARK_SLAT_IOMMU_RISK_ACPI_CHECKSUM           0x00000010UL
#define KSWORD_ARK_SLAT_IOMMU_RISK_ACPI_MALFORMED          0x00000020UL
#define KSWORD_ARK_SLAT_IOMMU_RISK_MMIO_UNREADABLE         0x00000040UL
#define KSWORD_ARK_SLAT_IOMMU_RISK_TRANSLATION_DISABLED    0x00000080UL
#define KSWORD_ARK_SLAT_IOMMU_RISK_ROOT_TABLE_UNAVAILABLE  0x00000100UL
#define KSWORD_ARK_SLAT_IOMMU_RISK_RESERVED_MEMORY_PRESENT 0x00000200UL
#define KSWORD_ARK_SLAT_IOMMU_RISK_TIMING_VARIANCE         0x00000400UL
#define KSWORD_ARK_SLAT_IOMMU_RISK_TRUNCATED               0x00000800UL

#define KSWORD_ARK_SLAT_PROBE_FLAG_VIRTUAL_READ       0x00000001UL
#define KSWORD_ARK_SLAT_PROBE_FLAG_PHYSICAL_READ      0x00000002UL
#define KSWORD_ARK_SLAT_PROBE_FLAG_HASH_MATCH         0x00000004UL
#define KSWORD_ARK_SLAT_PROBE_FLAG_HASH_MISMATCH      0x00000008UL
#define KSWORD_ARK_SLAT_PROBE_FLAG_VIRTUAL_UNSTABLE   0x00000010UL
#define KSWORD_ARK_SLAT_PROBE_FLAG_PHYSICAL_UNSTABLE  0x00000020UL
#define KSWORD_ARK_SLAT_PROBE_FLAG_PAGE_BOUNDARY      0x00000040UL

#define KSWORD_ARK_IOMMU_ROW_INTEL_DRHD 1UL
#define KSWORD_ARK_IOMMU_ROW_INTEL_RMRR 2UL
#define KSWORD_ARK_IOMMU_ROW_INTEL_ATSR 3UL
#define KSWORD_ARK_IOMMU_ROW_INTEL_RHSA 4UL
#define KSWORD_ARK_IOMMU_ROW_AMD_IVHD   5UL
#define KSWORD_ARK_IOMMU_ROW_AMD_IVMD   6UL
#define KSWORD_ARK_IOMMU_ROW_INTEL_ANDD 7UL
#define KSWORD_ARK_IOMMU_ROW_INTEL_SATC 8UL
#define KSWORD_ARK_IOMMU_ROW_UNKNOWN    9UL

#define KSWORD_ARK_IOMMU_ROW_FLAG_INCLUDE_ALL       0x00000001UL
#define KSWORD_ARK_IOMMU_ROW_FLAG_RESERVED_MEMORY   0x00000002UL
#define KSWORD_ARK_IOMMU_ROW_FLAG_MMIO_READ         0x00000004UL
#define KSWORD_ARK_IOMMU_ROW_FLAG_TRANSLATION       0x00000008UL
#define KSWORD_ARK_IOMMU_ROW_FLAG_INTERRUPT_REMAP   0x00000010UL
#define KSWORD_ARK_IOMMU_ROW_FLAG_ROOT_TABLE_VALID  0x00000020UL
#define KSWORD_ARK_IOMMU_ROW_FLAG_MALFORMED         0x00000040UL

#define KSWORD_ARK_SLAT_IOMMU_MAX_PROBES 16UL
#define KSWORD_ARK_SLAT_IOMMU_MAX_ROWS   64UL
#define KSWORD_ARK_SLAT_IOMMU_NAME_CHARS 48U
#define KSWORD_ARK_SLAT_IOMMU_VENDOR_CHARS 16U

typedef struct _KSWORD_ARK_SLAT_PROBE_ROW
{
    unsigned long flags;
    long status;
    unsigned long bytesCompared;
    unsigned long reserved;
    unsigned long long virtualAddress;
    unsigned long long physicalAddress;
    unsigned long long virtualHash;
    unsigned long long physicalHash;
    char name[KSWORD_ARK_SLAT_IOMMU_NAME_CHARS];
} KSWORD_ARK_SLAT_PROBE_ROW;

typedef struct _KSWORD_ARK_IOMMU_ROW
{
    unsigned long type;
    unsigned long flags;
    long status;
    unsigned long segment;
    unsigned long deviceId;
    unsigned long scopeCount;
    unsigned long firmwareFlags;
    unsigned long endDeviceId;
    unsigned long long baseAddress;
    unsigned long long limitAddress;
    unsigned long long capability;
    unsigned long long extendedCapability;
    unsigned long long statusRegister;
    unsigned long long rootTableAddress;
} KSWORD_ARK_IOMMU_ROW;

typedef struct _KSWORD_ARK_QUERY_SLAT_IOMMU_AUDIT_REQUEST
{
    unsigned long size;
    unsigned long version;
    unsigned long flags;
    unsigned long reserved;
} KSWORD_ARK_QUERY_SLAT_IOMMU_AUDIT_REQUEST;

typedef struct _KSWORD_ARK_QUERY_SLAT_IOMMU_AUDIT_RESPONSE
{
    unsigned long size;
    unsigned long version;
    unsigned long fieldFlags;
    unsigned long riskFlags;
    long queryStatus;
    long dmarStatus;
    long ivrsStatus;
    long iommuInterfaceStatus;
    long iommuInterfaceExStatus;
    unsigned long iommuInterfaceVersion;
    unsigned long iommuInterfaceExVersion;
    unsigned long probeCount;
    unsigned long mismatchCount;
    unsigned long unstableCount;
    unsigned long iommuRowCount;
    unsigned long reservedMemoryCount;
    unsigned long malformedRowCount;
    unsigned long dmarFlags;
    unsigned long dmarHostAddressWidth;
    unsigned long ivrsInfo;
    unsigned long cpuidMaxBasic;
    unsigned long cpuidMaxExtended;
    unsigned long cpuidMaxHypervisor;
    unsigned long queryFlags;
    unsigned long long featureFlags;
    unsigned long long vmxFeatureControl;
    unsigned long long vmxEptVpidCapabilities;
    unsigned long long amdVmCr;
    unsigned long long amdEfer;
    unsigned long long cpuidCyclesMinimum;
    unsigned long long cpuidCyclesMedian;
    unsigned long long cpuidCyclesMaximum;
    char cpuVendor[KSWORD_ARK_SLAT_IOMMU_VENDOR_CHARS];
    char hypervisorVendor[KSWORD_ARK_SLAT_IOMMU_VENDOR_CHARS];
    KSWORD_ARK_SLAT_PROBE_ROW probes[KSWORD_ARK_SLAT_IOMMU_MAX_PROBES];
    KSWORD_ARK_IOMMU_ROW iommuRows[KSWORD_ARK_SLAT_IOMMU_MAX_ROWS];
} KSWORD_ARK_QUERY_SLAT_IOMMU_AUDIT_RESPONSE;
