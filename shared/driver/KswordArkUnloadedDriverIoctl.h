#pragma once

#include "KswordArkProcessIoctl.h"

// ============================================================
// KswordArkUnloadedDriverIoctl.h
// 作用：
// - 定义 R3/R0 共用的“已卸载驱动”只读枚举协议；
// - 三个来源共用一套行结构，UI 可在来源间切换并复用过滤/复制逻辑；
// - 本协议没有删除、清理、修改 PiDDB 或 CI 哈希缓存的动作。
// ============================================================

#define KSWORD_ARK_UNLOADED_DRIVER_PROTOCOL_VERSION 1UL
#define KSWORD_ARK_IOCTL_FUNCTION_QUERY_UNLOADED_DRIVERS 0x8A8UL

#define IOCTL_KSWORD_ARK_QUERY_UNLOADED_DRIVERS \
    CTL_CODE( \
        KSWORD_ARK_IOCTL_DEVICE_TYPE, \
        KSWORD_ARK_IOCTL_FUNCTION_QUERY_UNLOADED_DRIVERS, \
        METHOD_BUFFERED, \
        FILE_ANY_ACCESS)

#define KSWORD_ARK_UNLOADED_DRIVER_SOURCE_MM_UNLOADED_DRIVERS 1UL
#define KSWORD_ARK_UNLOADED_DRIVER_SOURCE_PIDDB_CACHE_TABLE 2UL
#define KSWORD_ARK_UNLOADED_DRIVER_SOURCE_KERNEL_HASH_BUCKET_LIST 3UL

#define KSWORD_ARK_UNLOADED_DRIVER_DEFAULT_ROWS 256UL
#define KSWORD_ARK_UNLOADED_DRIVER_MAX_ROWS 4096UL
#define KSWORD_ARK_UNLOADED_DRIVER_NAME_CHARS 260U

// 查询状态属于业务状态；IOCTL 传输成功时也可能返回可读的降级原因。
#define KSWORD_ARK_UNLOADED_DRIVER_STATUS_OK 0UL
#define KSWORD_ARK_UNLOADED_DRIVER_STATUS_INVALID_REQUEST 1UL
#define KSWORD_ARK_UNLOADED_DRIVER_STATUS_DYNDATA_UNAVAILABLE 2UL
#define KSWORD_ARK_UNLOADED_DRIVER_STATUS_MODULE_PROFILE_UNAVAILABLE 3UL
#define KSWORD_ARK_UNLOADED_DRIVER_STATUS_LAYOUT_UNAVAILABLE 4UL
#define KSWORD_ARK_UNLOADED_DRIVER_STATUS_READ_FAILED 5UL
#define KSWORD_ARK_UNLOADED_DRIVER_STATUS_PARTIAL 6UL

#define KSWORD_ARK_UNLOADED_DRIVER_RESPONSE_FLAG_TRUNCATED 0x00000001UL
#define KSWORD_ARK_UNLOADED_DRIVER_RESPONSE_FLAG_SKIPPED_INVALID_ROW 0x00000002UL
#define KSWORD_ARK_UNLOADED_DRIVER_RESPONSE_FLAG_SNAPSHOT_RACY 0x00000004UL

// 每个 HAS_* 位精确说明该列是否有来源支持，UI 不把缺失值伪装成 0。
#define KSWORD_ARK_UNLOADED_DRIVER_ROW_FLAG_HAS_NAME 0x00000001UL
#define KSWORD_ARK_UNLOADED_DRIVER_ROW_FLAG_HAS_BASE 0x00000002UL
#define KSWORD_ARK_UNLOADED_DRIVER_ROW_FLAG_HAS_SIZE 0x00000004UL
#define KSWORD_ARK_UNLOADED_DRIVER_ROW_FLAG_HAS_TIMESTAMP 0x00000008UL
#define KSWORD_ARK_UNLOADED_DRIVER_ROW_FLAG_HAS_LOAD_STATUS 0x00000010UL
#define KSWORD_ARK_UNLOADED_DRIVER_ROW_FLAG_HAS_UNLOAD_TIME 0x00000020UL

typedef struct _KSWORD_ARK_QUERY_UNLOADED_DRIVERS_REQUEST
{
    unsigned long version;
    unsigned long size;
    unsigned long source;
    unsigned long maxRows;
    unsigned long flags;
    unsigned long reserved;
} KSWORD_ARK_QUERY_UNLOADED_DRIVERS_REQUEST;

typedef struct _KSWORD_ARK_UNLOADED_DRIVER_ROW
{
    unsigned long source;
    unsigned long flags;
    unsigned long long entryAddress;
    unsigned long long baseAddress;
    unsigned long long imageSize;
    unsigned long long unloadTime;
    unsigned long timeDateStamp;
    long loadStatus;
    unsigned long nameLengthBytes;
    unsigned long reserved;
    wchar_t driverName[KSWORD_ARK_UNLOADED_DRIVER_NAME_CHARS];
} KSWORD_ARK_UNLOADED_DRIVER_ROW;

typedef struct _KSWORD_ARK_QUERY_UNLOADED_DRIVERS_RESPONSE
{
    unsigned long version;
    unsigned long size;
    unsigned long rowSize;
    unsigned long source;
    unsigned long queryStatus;
    unsigned long responseFlags;
    unsigned long totalRows;
    unsigned long returnedRows;
    unsigned long skippedRows;
    long lastStatus;
    unsigned long reserved[2];
    KSWORD_ARK_UNLOADED_DRIVER_ROW rows[1];
} KSWORD_ARK_QUERY_UNLOADED_DRIVERS_RESPONSE;

#define KSWORD_ARK_QUERY_UNLOADED_DRIVERS_RESPONSE_HEADER_SIZE \
    (sizeof(KSWORD_ARK_QUERY_UNLOADED_DRIVERS_RESPONSE) - \
        sizeof(KSWORD_ARK_UNLOADED_DRIVER_ROW))
