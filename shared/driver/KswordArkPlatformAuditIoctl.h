#pragma once

#include "KswordArkKernelIoctl.h"

// ============================================================
// KswordArkPlatformAuditIoctl.h
// 作用：
// - 定义 R3 <-> R0 HAL/WDF 只读审计协议；
// - 地址只在公开导出、WDF 绑定表或经过结构校验的表内读取；
// - 本协议不提供 patch、restore、unhook 或任意内存读写能力。
// ============================================================

#define KSWORD_ARK_PLATFORM_AUDIT_PROTOCOL_VERSION 1UL

#define KSWORD_ARK_IOCTL_FUNCTION_QUERY_PLATFORM_AUDIT 0x8E4UL
#define IOCTL_KSWORD_ARK_QUERY_PLATFORM_AUDIT \
    CTL_CODE( \
        KSWORD_ARK_IOCTL_DEVICE_TYPE, \
        KSWORD_ARK_IOCTL_FUNCTION_QUERY_PLATFORM_AUDIT, \
        METHOD_BUFFERED, \
        FILE_ANY_ACCESS)

#define KSWORD_ARK_PLATFORM_AUDIT_SCOPE_HAL_DISPATCH       0x00000001UL
#define KSWORD_ARK_PLATFORM_AUDIT_SCOPE_HAL_PRIVATE        0x00000002UL
#define KSWORD_ARK_PLATFORM_AUDIT_SCOPE_HAL_ACPI           0x00000004UL
#define KSWORD_ARK_PLATFORM_AUDIT_SCOPE_HAL_SUBCOMPONENTS  0x00000008UL
#define KSWORD_ARK_PLATFORM_AUDIT_SCOPE_WDF_FUNCTIONS      0x00000010UL
#define KSWORD_ARK_PLATFORM_AUDIT_SCOPE_WDF_CALLBACKS      0x00000020UL
#define KSWORD_ARK_PLATFORM_AUDIT_SCOPE_ALL                0x0000003FUL

#define KSWORD_ARK_PLATFORM_AUDIT_STATUS_UNAVAILABLE       0UL
#define KSWORD_ARK_PLATFORM_AUDIT_STATUS_OK                1UL
#define KSWORD_ARK_PLATFORM_AUDIT_STATUS_PARTIAL           2UL
#define KSWORD_ARK_PLATFORM_AUDIT_STATUS_UNSUPPORTED       3UL
#define KSWORD_ARK_PLATFORM_AUDIT_STATUS_SIGNATURE_MISMATCH 4UL
#define KSWORD_ARK_PLATFORM_AUDIT_STATUS_QUERY_FAILED      5UL
#define KSWORD_ARK_PLATFORM_AUDIT_STATUS_BUFFER_TRUNCATED  6UL

#define KSWORD_ARK_PLATFORM_AUDIT_ROW_TABLE                1UL
#define KSWORD_ARK_PLATFORM_AUDIT_ROW_FUNCTION             2UL
#define KSWORD_ARK_PLATFORM_AUDIT_ROW_CALLBACK             3UL
#define KSWORD_ARK_PLATFORM_AUDIT_ROW_DIAGNOSTIC           4UL

#define KSWORD_ARK_PLATFORM_HOOK_UNKNOWN                   0UL
#define KSWORD_ARK_PLATFORM_HOOK_CLEAN                     1UL
#define KSWORD_ARK_PLATFORM_HOOK_SUSPICIOUS                2UL
#define KSWORD_ARK_PLATFORM_HOOK_UNSUPPORTED               3UL

#define KSWORD_ARK_PLATFORM_CONFIDENCE_NONE                0UL
#define KSWORD_ARK_PLATFORM_CONFIDENCE_LOW                25UL
#define KSWORD_ARK_PLATFORM_CONFIDENCE_MEDIUM             60UL
#define KSWORD_ARK_PLATFORM_CONFIDENCE_HIGH               90UL

#define KSWORD_ARK_PLATFORM_FIELD_LIVE_ADDRESS             0x00000001UL
#define KSWORD_ARK_PLATFORM_FIELD_BASELINE_ADDRESS         0x00000002UL
#define KSWORD_ARK_PLATFORM_FIELD_TABLE_ADDRESS            0x00000004UL
#define KSWORD_ARK_PLATFORM_FIELD_MODULE                   0x00000008UL
#define KSWORD_ARK_PLATFORM_FIELD_VENDOR                   0x00000010UL
#define KSWORD_ARK_PLATFORM_FIELD_PROLOGUE_VALIDATED       0x00000020UL
#define KSWORD_ARK_PLATFORM_FIELD_OWNER_VALIDATED          0x00000040UL
#define KSWORD_ARK_PLATFORM_FIELD_STRUCTURE_VALIDATED      0x00000080UL
#define KSWORD_ARK_PLATFORM_FIELD_EXACT_EXPORT             0x00000100UL
#define KSWORD_ARK_PLATFORM_FIELD_RUNTIME_SNAPSHOT_BASELINE 0x00000200UL

#define KSWORD_ARK_PLATFORM_RESPONSE_TRUNCATED              0x00000001UL
#define KSWORD_ARK_PLATFORM_RESPONSE_PARTIAL                0x00000002UL
#define KSWORD_ARK_PLATFORM_RESPONSE_FAIL_CLOSED            0x00000004UL
#define KSWORD_ARK_PLATFORM_RESPONSE_NO_PDB                 0x00000008UL

#define KSWORD_ARK_PLATFORM_SIGNATURE_NONE                  0UL
#define KSWORD_ARK_PLATFORM_SIGNATURE_PUBLIC_HAL_V6         1UL
#define KSWORD_ARK_PLATFORM_SIGNATURE_COUNT_PREFIXED_TABLE  2UL
#define KSWORD_ARK_PLATFORM_SIGNATURE_WDF_BINDING_TABLE     3UL
#define KSWORD_ARK_PLATFORM_SIGNATURE_X64_PROLOGUE          4UL
#define KSWORD_ARK_PLATFORM_SIGNATURE_EXACT_EXPORT_ONLY     5UL
#define KSWORD_ARK_PLATFORM_SIGNATURE_RIP_RELATIVE_MASKED   6UL

#define KSWORD_ARK_PLATFORM_DEFAULT_MAX_ROWS 256UL
#define KSWORD_ARK_PLATFORM_HARD_MAX_ROWS    512UL

#define KSWORD_ARK_PLATFORM_NAME_CHARS        96U
#define KSWORD_ARK_PLATFORM_MODULE_PATH_CHARS 260U
#define KSWORD_ARK_PLATFORM_VENDOR_CHARS      96U
#define KSWORD_ARK_PLATFORM_DETAIL_CHARS      320U

typedef struct _KSWORD_ARK_QUERY_PLATFORM_AUDIT_REQUEST
{
    // 说明：R3 只传入范围掩码和行预算，R0 会拒绝未知版本与保留字段。
    unsigned long size;
    unsigned long version;
    unsigned long scopeMask;
    unsigned long maxRows;
    unsigned long flags;
    unsigned long reserved0;
} KSWORD_ARK_QUERY_PLATFORM_AUDIT_REQUEST;

typedef struct _KSWORD_ARK_PLATFORM_AUDIT_ENTRY
{
    // 说明：统一承载 HAL 表项、WDF 函数、WDF 回调和显式降级诊断。
    unsigned long size;
    unsigned long scope;
    unsigned long rowKind;
    unsigned long status;
    unsigned long hookStatus;
    unsigned long confidence;
    unsigned long fieldFlags;
    unsigned long signatureId;
    unsigned long entryIndex;
    long lastStatus;
    unsigned long moduleSize;
    unsigned long prologueSignatureId;
    unsigned long long liveAddress;
    unsigned long long baselineAddress;
    unsigned long long tableAddress;
    unsigned long long moduleBase;
    wchar_t name[KSWORD_ARK_PLATFORM_NAME_CHARS];
    wchar_t modulePath[KSWORD_ARK_PLATFORM_MODULE_PATH_CHARS];
    wchar_t vendor[KSWORD_ARK_PLATFORM_VENDOR_CHARS];
    wchar_t detail[KSWORD_ARK_PLATFORM_DETAIL_CHARS];
} KSWORD_ARK_PLATFORM_AUDIT_ENTRY;

typedef struct _KSWORD_ARK_QUERY_PLATFORM_AUDIT_RESPONSE
{
    // 说明：METHOD_BUFFERED 可变长响应，R3 必须同时校验 entrySize 和 returnedCount。
    unsigned long size;
    unsigned long version;
    unsigned long queryStatus;
    unsigned long scopeMask;
    unsigned long responseFlags;
    unsigned long totalCount;
    unsigned long returnedCount;
    unsigned long entrySize;
    unsigned long buildNumber;
    unsigned long signaturePolicyFlags;
    long lastStatus;
    unsigned long reserved0;
    KSWORD_ARK_PLATFORM_AUDIT_ENTRY entries[1];
} KSWORD_ARK_QUERY_PLATFORM_AUDIT_RESPONSE;
