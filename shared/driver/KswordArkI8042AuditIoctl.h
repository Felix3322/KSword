#pragma once

#include "KswordArkKernelIoctl.h"

// ============================================================
// KswordArkI8042AuditIoctl.h
// 作用：
// - 定义 R3 <-> R0 i8042prt 专项只读审计协议；
// - 仅在 PE/RSDS/opcode/DriverObject 全部匹配已知描述符后读取设备扩展指针；
// - 只返回端点地址、归属和设备栈关系，不读取键鼠输入数据，也不提供写入能力。
// ============================================================

#define KSWORD_ARK_I8042_AUDIT_PROTOCOL_VERSION 1UL

#define KSWORD_ARK_IOCTL_FUNCTION_QUERY_I8042_AUDIT 0x8E5UL
#define IOCTL_KSWORD_ARK_QUERY_I8042_AUDIT \
    CTL_CODE( \
        KSWORD_ARK_IOCTL_DEVICE_TYPE, \
        KSWORD_ARK_IOCTL_FUNCTION_QUERY_I8042_AUDIT, \
        METHOD_BUFFERED, \
        FILE_ANY_ACCESS)

#define KSWORD_ARK_I8042_AUDIT_STATUS_UNAVAILABLE        0UL
#define KSWORD_ARK_I8042_AUDIT_STATUS_AVAILABLE          1UL
#define KSWORD_ARK_I8042_AUDIT_STATUS_PARTIAL            2UL
#define KSWORD_ARK_I8042_AUDIT_STATUS_UNSUPPORTED        3UL
#define KSWORD_ARK_I8042_AUDIT_STATUS_SIGNATURE_MISMATCH 4UL
#define KSWORD_ARK_I8042_AUDIT_STATUS_QUERY_FAILED       5UL
#define KSWORD_ARK_I8042_AUDIT_STATUS_BUFFER_TRUNCATED   6UL

#define KSWORD_ARK_I8042_AUDIT_ROW_DEVICE     1UL
#define KSWORD_ARK_I8042_AUDIT_ROW_ENDPOINT   2UL
#define KSWORD_ARK_I8042_AUDIT_ROW_DIAGNOSTIC 3UL

#define KSWORD_ARK_I8042_DEVICE_UNKNOWN  0UL
#define KSWORD_ARK_I8042_DEVICE_KEYBOARD 1UL
#define KSWORD_ARK_I8042_DEVICE_MOUSE    2UL

#define KSWORD_ARK_I8042_ENDPOINT_NONE                         0UL
#define KSWORD_ARK_I8042_ENDPOINT_KEYBOARD_CLASS_SERVICE       1UL
#define KSWORD_ARK_I8042_ENDPOINT_KEYBOARD_INITIALIZATION      2UL
#define KSWORD_ARK_I8042_ENDPOINT_KEYBOARD_ISR                 3UL
#define KSWORD_ARK_I8042_ENDPOINT_MOUSE_CLASS_SERVICE          4UL
#define KSWORD_ARK_I8042_ENDPOINT_MOUSE_ISR                    5UL

// “AVAILABLE”只表示证据可读取；本协议没有独立干净基线，因此不定义 CLEAN。
#define KSWORD_ARK_I8042_VERDICT_UNKNOWN     0UL
#define KSWORD_ARK_I8042_VERDICT_AVAILABLE   1UL
#define KSWORD_ARK_I8042_VERDICT_SUSPICIOUS  2UL
#define KSWORD_ARK_I8042_VERDICT_UNSUPPORTED 3UL

#define KSWORD_ARK_I8042_FIELD_DEVICE_OBJECT        0x00000001UL
#define KSWORD_ARK_I8042_FIELD_PNP_ID               0x00000002UL
#define KSWORD_ARK_I8042_FIELD_CLASS_DEVICE_OBJECT  0x00000004UL
#define KSWORD_ARK_I8042_FIELD_CALLBACK_ADDRESS     0x00000008UL
#define KSWORD_ARK_I8042_FIELD_CONTEXT_ADDRESS      0x00000010UL
#define KSWORD_ARK_I8042_FIELD_OWNER_MODULE         0x00000020UL
#define KSWORD_ARK_I8042_FIELD_EXECUTABLE           0x00000040UL
#define KSWORD_ARK_I8042_FIELD_SAME_DEVICE_STACK    0x00000080UL
#define KSWORD_ARK_I8042_FIELD_IMAGE_VALIDATED      0x00000100UL
#define KSWORD_ARK_I8042_FIELD_DESCRIPTOR_VALIDATED 0x00000200UL
#define KSWORD_ARK_I8042_FIELD_DETAIL_ARGS          0x00000400UL

#define KSWORD_ARK_I8042_RESPONSE_TRUNCATED            0x00000001UL
#define KSWORD_ARK_I8042_RESPONSE_PARTIAL              0x00000002UL
#define KSWORD_ARK_I8042_RESPONSE_FAIL_CLOSED          0x00000004UL
#define KSWORD_ARK_I8042_RESPONSE_IMAGE_VALIDATED      0x00000008UL
#define KSWORD_ARK_I8042_RESPONSE_DESCRIPTOR_VALIDATED 0x00000010UL

#define KSWORD_ARK_I8042_DETAIL_NONE                  0UL
#define KSWORD_ARK_I8042_DETAIL_DESCRIPTOR_VALIDATED  1UL
#define KSWORD_ARK_I8042_DETAIL_DRIVER_NOT_FOUND      2UL
#define KSWORD_ARK_I8042_DETAIL_MODULE_NOT_FOUND      3UL
#define KSWORD_ARK_I8042_DETAIL_IMAGE_MISMATCH        4UL
#define KSWORD_ARK_I8042_DETAIL_RSDS_MISMATCH         5UL
#define KSWORD_ARK_I8042_DETAIL_OPCODE_MISMATCH       6UL
#define KSWORD_ARK_I8042_DETAIL_DRIVER_LAYOUT_MISMATCH 7UL
#define KSWORD_ARK_I8042_DETAIL_DEVICE_ENUM_FAILED    8UL
#define KSWORD_ARK_I8042_DETAIL_NO_DEVICES            9UL
#define KSWORD_ARK_I8042_DETAIL_PNP_CLASS_UNKNOWN    10UL
#define KSWORD_ARK_I8042_DETAIL_EXTENSION_READ_FAILED 11UL
#define KSWORD_ARK_I8042_DETAIL_ENDPOINT_AVAILABLE   12UL
#define KSWORD_ARK_I8042_DETAIL_ENDPOINT_NULL        13UL
#define KSWORD_ARK_I8042_DETAIL_OWNER_MISMATCH       14UL
#define KSWORD_ARK_I8042_DETAIL_NON_EXECUTABLE       15UL
#define KSWORD_ARK_I8042_DETAIL_CLASS_DO_OUTSIDE_STACK 16UL
#define KSWORD_ARK_I8042_DETAIL_BUFFER_TRUNCATED     17UL

#define KSWORD_ARK_I8042_DESCRIPTOR_WIN11_26100_7934 1UL

#define KSWORD_ARK_I8042_DEFAULT_MAX_ROWS 64UL
#define KSWORD_ARK_I8042_HARD_MAX_ROWS   128UL

#define KSWORD_ARK_I8042_PNP_ID_CHARS       260U
#define KSWORD_ARK_I8042_MODULE_PATH_CHARS  260U
#define KSWORD_ARK_I8042_DETAIL_ARG_COUNT     4U
#define KSWORD_ARK_I8042_PDB_GUID_BYTES      16U

typedef struct _KSWORD_ARK_QUERY_I8042_AUDIT_REQUEST
{
    unsigned long size;
    unsigned long version;
    unsigned long maxRows;
    unsigned long flags;
    unsigned long reserved0;
    unsigned long reserved1;
} KSWORD_ARK_QUERY_I8042_AUDIT_REQUEST;

typedef struct _KSWORD_ARK_I8042_AUDIT_ENTRY
{
    unsigned long size;
    unsigned long rowKind;
    unsigned long deviceKind;
    unsigned long endpointKind;
    unsigned long status;
    unsigned long verdict;
    unsigned long fieldFlags;
    unsigned long detailCode;
    long lastStatus;
    unsigned long moduleSize;
    unsigned long reserved0;
    unsigned long reserved1;
    unsigned long long deviceObject;
    unsigned long long classDeviceObject;
    unsigned long long callbackAddress;
    unsigned long long contextAddress;
    unsigned long long moduleBase;
    unsigned long long detailArgs[KSWORD_ARK_I8042_DETAIL_ARG_COUNT];
    wchar_t pnpId[KSWORD_ARK_I8042_PNP_ID_CHARS];
    wchar_t ownerModulePath[KSWORD_ARK_I8042_MODULE_PATH_CHARS];
} KSWORD_ARK_I8042_AUDIT_ENTRY;

typedef struct _KSWORD_ARK_QUERY_I8042_AUDIT_RESPONSE
{
    unsigned long size;
    unsigned long version;
    unsigned long queryStatus;
    unsigned long responseFlags;
    unsigned long totalCount;
    unsigned long returnedCount;
    unsigned long entrySize;
    unsigned long descriptorId;
    unsigned long imageTimeDateStamp;
    unsigned long imageSize;
    unsigned long imageChecksum;
    unsigned long pdbAge;
    unsigned char pdbGuid[KSWORD_ARK_I8042_PDB_GUID_BYTES];
    long lastStatus;
    unsigned long reserved0;
    unsigned long long imageBase;
    KSWORD_ARK_I8042_AUDIT_ENTRY entries[1];
} KSWORD_ARK_QUERY_I8042_AUDIT_RESPONSE;
