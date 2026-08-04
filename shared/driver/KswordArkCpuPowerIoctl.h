#pragma once

#include "KswordArkProcessIoctl.h"

// ============================================================
// KswordArkCpuPowerIoctl.h
// 作用：
// - 定义 CPU 电源管理页面唯一的 R3/R0 通信协议；
// - 查询接口只读取 CPUID 与经过异常保护的 Intel 架构 MSR；
// - 控制接口只修改已探测且未锁定的 RAPL、HWP、Turbo、Turbo Ratio 与请求倍频字段；
// - 不提供任意 MSR 编号或任意 64 位原始值写入能力。
// ============================================================

#define KSWORD_ARK_CPU_POWER_PROTOCOL_VERSION 2UL

#define KSWORD_ARK_IOCTL_FUNCTION_QUERY_CPU_POWER   0x8F2UL
#define KSWORD_ARK_IOCTL_FUNCTION_CONTROL_CPU_POWER 0x8F3UL

#define IOCTL_KSWORD_ARK_QUERY_CPU_POWER \
    CTL_CODE( \
        KSWORD_ARK_IOCTL_DEVICE_TYPE, \
        KSWORD_ARK_IOCTL_FUNCTION_QUERY_CPU_POWER, \
        METHOD_BUFFERED, \
        FILE_READ_ACCESS)

#define IOCTL_KSWORD_ARK_CONTROL_CPU_POWER \
    CTL_CODE( \
        KSWORD_ARK_IOCTL_DEVICE_TYPE, \
        KSWORD_ARK_IOCTL_FUNCTION_CONTROL_CPU_POWER, \
        METHOD_BUFFERED, \
        FILE_WRITE_ACCESS)

#define KSWORD_ARK_CPU_POWER_VENDOR_UNKNOWN 0UL
#define KSWORD_ARK_CPU_POWER_VENDOR_INTEL   1UL
#define KSWORD_ARK_CPU_POWER_VENDOR_AMD     2UL

#define KSWORD_ARK_CPU_POWER_FIELD_CPUID               0x00000001UL
#define KSWORD_ARK_CPU_POWER_FIELD_RAPL_UNIT           0x00000002UL
#define KSWORD_ARK_CPU_POWER_FIELD_PACKAGE_POWER_LIMIT 0x00000004UL
#define KSWORD_ARK_CPU_POWER_FIELD_PACKAGE_POWER_INFO  0x00000008UL
#define KSWORD_ARK_CPU_POWER_FIELD_PLATFORM_INFO       0x00000010UL
#define KSWORD_ARK_CPU_POWER_FIELD_MISC_ENABLE         0x00000020UL
#define KSWORD_ARK_CPU_POWER_FIELD_PM_ENABLE           0x00000040UL
#define KSWORD_ARK_CPU_POWER_FIELD_HWP_CAPABILITIES    0x00000080UL
#define KSWORD_ARK_CPU_POWER_FIELD_HWP_REQUEST         0x00000100UL
#define KSWORD_ARK_CPU_POWER_FIELD_TURBO_RATIO_LIMIT   0x00000200UL
#define KSWORD_ARK_CPU_POWER_FIELD_PERF_STATUS         0x00000400UL
#define KSWORD_ARK_CPU_POWER_FIELD_PERF_CONTROL        0x00000800UL

#define KSWORD_ARK_CPU_POWER_CAP_RAPL                       0x0000000000000001ULL
#define KSWORD_ARK_CPU_POWER_CAP_PACKAGE_POWER_LIMIT        0x0000000000000002ULL
#define KSWORD_ARK_CPU_POWER_CAP_PACKAGE_POWER_INFO         0x0000000000000004ULL
#define KSWORD_ARK_CPU_POWER_CAP_PACKAGE_POWER_PROGRAMMABLE 0x0000000000000008ULL
#define KSWORD_ARK_CPU_POWER_CAP_TURBO                      0x0000000000000010ULL
#define KSWORD_ARK_CPU_POWER_CAP_TURBO_CONTROL              0x0000000000000020ULL
#define KSWORD_ARK_CPU_POWER_CAP_HWP                        0x0000000000000040ULL
#define KSWORD_ARK_CPU_POWER_CAP_HWP_ENABLED                0x0000000000000080ULL
#define KSWORD_ARK_CPU_POWER_CAP_HWP_EPP                    0x0000000000000100ULL
#define KSWORD_ARK_CPU_POWER_CAP_TURBO_RATIO_LIMIT          0x0000000000000200ULL
#define KSWORD_ARK_CPU_POWER_CAP_TURBO_RATIO_PROGRAMMABLE   0x0000000000000400ULL
#define KSWORD_ARK_CPU_POWER_CAP_PERF_CONTROL                0x0000000000000800ULL
#define KSWORD_ARK_CPU_POWER_CAP_PERF_CONTROL_PROGRAMMABLE   0x0000000000001000ULL

#define KSWORD_ARK_CPU_POWER_RESPONSE_FLAG_UNSUPPORTED_VENDOR   0x00000001UL
#define KSWORD_ARK_CPU_POWER_RESPONSE_FLAG_PARTIAL_MSR          0x00000002UL
#define KSWORD_ARK_CPU_POWER_RESPONSE_FLAG_POWER_LIMIT_LOCKED   0x00000004UL
#define KSWORD_ARK_CPU_POWER_RESPONSE_FLAG_HYPERVISOR_PRESENT   0x00000008UL
#define KSWORD_ARK_CPU_POWER_RESPONSE_FLAG_PLATFORM_MAX_UNKNOWN 0x00000010UL
#define KSWORD_ARK_CPU_POWER_RESPONSE_FLAG_STALE_SNAPSHOT       0x00000020UL
#define KSWORD_ARK_CPU_POWER_RESPONSE_FLAG_WRITE_PARTIAL        0x00000040UL
#define KSWORD_ARK_CPU_POWER_RESPONSE_FLAG_WRITE_VERIFIED       0x00000080UL

// failureReason：在 lastStatus 之外指出请求被拒绝或写入失败的精确阶段。
#define KSWORD_ARK_CPU_POWER_FAILURE_NONE                   0UL
#define KSWORD_ARK_CPU_POWER_FAILURE_REQUEST_HEADER         1UL
#define KSWORD_ARK_CPU_POWER_FAILURE_SAFETY_POLICY          2UL
#define KSWORD_ARK_CPU_POWER_FAILURE_VENDOR                 3UL
#define KSWORD_ARK_CPU_POWER_FAILURE_POWER_CAPABILITY       4UL
#define KSWORD_ARK_CPU_POWER_FAILURE_POWER_ABSOLUTE_RANGE   5UL
#define KSWORD_ARK_CPU_POWER_FAILURE_POWER_PLATFORM_MAXIMUM 6UL
#define KSWORD_ARK_CPU_POWER_FAILURE_POWER_PLATFORM_MINIMUM 7UL
#define KSWORD_ARK_CPU_POWER_FAILURE_POWER_BOOLEAN          8UL
#define KSWORD_ARK_CPU_POWER_FAILURE_TURBO_CAPABILITY       9UL
#define KSWORD_ARK_CPU_POWER_FAILURE_HWP_CAPABILITY         10UL
#define KSWORD_ARK_CPU_POWER_FAILURE_HWP_ORDER              11UL
#define KSWORD_ARK_CPU_POWER_FAILURE_HWP_DESIRED_RANGE      12UL
#define KSWORD_ARK_CPU_POWER_FAILURE_HWP_PLATFORM_RANGE     13UL
#define KSWORD_ARK_CPU_POWER_FAILURE_HWP_EPP                14UL
#define KSWORD_ARK_CPU_POWER_FAILURE_TURBO_RATIO            15UL
#define KSWORD_ARK_CPU_POWER_FAILURE_STALE_SNAPSHOT         16UL
#define KSWORD_ARK_CPU_POWER_FAILURE_PROCESSOR_APPLY        17UL
#define KSWORD_ARK_CPU_POWER_FAILURE_PERF_CONTROL           18UL

#define KSWORD_ARK_CPU_POWER_APPLY_POWER_LIMITS 0x00000001UL
#define KSWORD_ARK_CPU_POWER_APPLY_TURBO       0x00000002UL
#define KSWORD_ARK_CPU_POWER_APPLY_HWP         0x00000004UL
#define KSWORD_ARK_CPU_POWER_APPLY_TURBO_RATIO 0x00000008UL
#define KSWORD_ARK_CPU_POWER_APPLY_PERF_CONTROL 0x00000010UL
#define KSWORD_ARK_CPU_POWER_APPLY_ALL \
    (KSWORD_ARK_CPU_POWER_APPLY_POWER_LIMITS | \
     KSWORD_ARK_CPU_POWER_APPLY_TURBO | \
     KSWORD_ARK_CPU_POWER_APPLY_HWP | \
     KSWORD_ARK_CPU_POWER_APPLY_TURBO_RATIO | \
     KSWORD_ARK_CPU_POWER_APPLY_PERF_CONTROL)

#define KSWORD_ARK_CPU_POWER_REQUEST_FLAG_UI_CONFIRMED    0x00000001UL
#define KSWORD_ARK_CPU_POWER_REQUEST_FLAG_REQUIRE_CURRENT 0x00000002UL
#define KSWORD_ARK_CPU_POWER_REQUEST_FLAG_TURBO_RATIO_ARRAY 0x00000004UL

// 无法从 MSR_PKG_POWER_INFO 取得 SKU 上限时，仍以 1000 W 作为协议绝对硬上限。
#define KSWORD_ARK_CPU_POWER_ABSOLUTE_MAX_MILLIWATTS 1000000UL

#define KSWORD_ARK_CPU_POWER_VENDOR_TEXT_CHARS 13U
#define KSWORD_ARK_CPU_POWER_BRAND_TEXT_CHARS 49U
#define KSWORD_ARK_CPU_POWER_TURBO_RATIO_COUNT 8U

typedef struct _KSWORD_ARK_CPU_POWER_CONTROL_REQUEST
{
    unsigned long size;
    unsigned long version;
    unsigned long applyFlags;
    unsigned long requestFlags;
    unsigned long pl1Milliwatts;
    unsigned long pl2Milliwatts;
    unsigned long pl1Enabled;
    unsigned long pl1ClampEnabled;
    unsigned long pl2Enabled;
    unsigned long pl2ClampEnabled;
    unsigned long turboEnabled;
    unsigned long hwpMinimumPerformance;
    unsigned long hwpMaximumPerformance;
    unsigned long hwpDesiredPerformance;
    unsigned long hwpEnergyPerformancePreference;
    unsigned long turboRatio;
    unsigned long requestedMultiplier;
    // turboRatios 仅在 TURBO_RATIO_ARRAY 标志置位时用于逐档精确还原。
    unsigned long turboRatios[KSWORD_ARK_CPU_POWER_TURBO_RATIO_COUNT];
    unsigned long reserved;
    unsigned long long expectedPackagePowerLimit;
    unsigned long long expectedMiscEnable;
    unsigned long long expectedHwpRequest;
    unsigned long long expectedTurboRatioLimit;
    unsigned long long expectedPerfControl;
} KSWORD_ARK_CPU_POWER_CONTROL_REQUEST;

typedef struct _KSWORD_ARK_CPU_POWER_RESPONSE
{
    unsigned long size;
    unsigned long version;
    unsigned long vendor;
    unsigned long fieldFlags;
    unsigned long responseFlags;
    unsigned long family;
    unsigned long model;
    unsigned long stepping;
    unsigned long logicalProcessorCount;
    unsigned long processorGroupCount;
    unsigned long updatedProcessorCount;
    unsigned long failedProcessorCount;
    long lastStatus;
    unsigned long failureReason;
    unsigned long long capabilityFlags;
    unsigned long powerUnitMicrowatts;
    unsigned long timeUnitNanoseconds;
    unsigned long packageTdpMilliwatts;
    unsigned long packageMinimumPowerMilliwatts;
    unsigned long packageMaximumPowerMilliwatts;
    unsigned long packageMaximumTimeWindowMilliseconds;
    unsigned long pl1Milliwatts;
    unsigned long pl2Milliwatts;
    unsigned long pl1Enabled;
    unsigned long pl1ClampEnabled;
    unsigned long pl2Enabled;
    unsigned long pl2ClampEnabled;
    unsigned long turboEnabled;
    unsigned long requestedMultiplier;
    unsigned long currentMultiplier;
    unsigned long maximumNonTurboRatio;
    unsigned long maximumEfficiencyRatio;
    unsigned long hwpHighestPerformance;
    unsigned long hwpGuaranteedPerformance;
    unsigned long hwpMostEfficientPerformance;
    unsigned long hwpLowestPerformance;
    unsigned long hwpMinimumPerformance;
    unsigned long hwpMaximumPerformance;
    unsigned long hwpDesiredPerformance;
    unsigned long hwpEnergyPerformancePreference;
    unsigned long turboRatios[KSWORD_ARK_CPU_POWER_TURBO_RATIO_COUNT];
    unsigned long long msrRaplPowerUnit;
    unsigned long long msrPackagePowerLimit;
    unsigned long long msrPackagePowerInfo;
    unsigned long long msrPlatformInfo;
    unsigned long long msrMiscEnable;
    unsigned long long msrPmEnable;
    unsigned long long msrHwpCapabilities;
    unsigned long long msrHwpRequest;
    unsigned long long msrTurboRatioLimit;
    unsigned long long msrPerfStatus;
    unsigned long long msrPerfControl;
    char vendorId[KSWORD_ARK_CPU_POWER_VENDOR_TEXT_CHARS];
    char brandText[KSWORD_ARK_CPU_POWER_BRAND_TEXT_CHARS];
} KSWORD_ARK_CPU_POWER_RESPONSE;
