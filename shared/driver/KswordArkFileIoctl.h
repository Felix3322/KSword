#pragma once

#include "KswordArkProcessIoctl.h"

// ============================================================
// KswordArkFileIoctl.h
// Purpose:
// - Shared IOCTL code and request struct for R3 <-> R0 file actions.
// - Current scope: delete a single file-system path by NT path.
// - Phase 10 adds a read-only file basic information query packet.
// ============================================================

#define KSWORD_ARK_FILE_PROTOCOL_VERSION 1UL
#define KSWORD_ARK_DIRECTORY_ENUM_PROTOCOL_VERSION 1UL

#define KSWORD_ARK_IOCTL_FUNCTION_DELETE_PATH 0x804
#define KSWORD_ARK_IOCTL_FUNCTION_QUERY_FILE_INFO 0x812UL
#define KSWORD_ARK_IOCTL_FUNCTION_SET_FILE_INTEGRITY 0x84DUL
#define KSWORD_ARK_IOCTL_FUNCTION_ENUM_DIRECTORY 0x8CFUL

#define IOCTL_KSWORD_ARK_DELETE_PATH \
    CTL_CODE( \
        KSWORD_ARK_IOCTL_DEVICE_TYPE, \
        KSWORD_ARK_IOCTL_FUNCTION_DELETE_PATH, \
        METHOD_BUFFERED, \
        FILE_ANY_ACCESS)

#define IOCTL_KSWORD_ARK_QUERY_FILE_INFO \
    CTL_CODE( \
        KSWORD_ARK_IOCTL_DEVICE_TYPE, \
        KSWORD_ARK_IOCTL_FUNCTION_QUERY_FILE_INFO, \
        METHOD_BUFFERED, \
        FILE_ANY_ACCESS)

#define IOCTL_KSWORD_ARK_SET_FILE_INTEGRITY \
    CTL_CODE( \
        KSWORD_ARK_IOCTL_DEVICE_TYPE, \
        KSWORD_ARK_IOCTL_FUNCTION_SET_FILE_INTEGRITY, \
        METHOD_BUFFERED, \
        FILE_WRITE_ACCESS)

#define IOCTL_KSWORD_ARK_ENUM_DIRECTORY \
    CTL_CODE( \
        KSWORD_ARK_IOCTL_DEVICE_TYPE, \
        KSWORD_ARK_IOCTL_FUNCTION_ENUM_DIRECTORY, \
        METHOD_BUFFERED, \
        FILE_READ_ACCESS)

#define KSWORD_ARK_DELETE_PATH_FLAG_DIRECTORY 0x00000001UL
#define KSWORD_ARK_DELETE_PATH_MAX_CHARS 1024U

#define KSWORD_ARK_FILE_INTEGRITY_PROTOCOL_VERSION 1UL
#define KSWORD_ARK_FILE_INTEGRITY_FLAG_DIRECTORY 0x00000001UL
#define KSWORD_ARK_FILE_INTEGRITY_FLAG_UI_CONFIRMED 0x00000002UL
#define KSWORD_ARK_FILE_INTEGRITY_PATH_MAX_CHARS 1024U

#define KSWORD_ARK_FILE_INTEGRITY_STATUS_UNKNOWN 0UL
#define KSWORD_ARK_FILE_INTEGRITY_STATUS_APPLIED 1UL
#define KSWORD_ARK_FILE_INTEGRITY_STATUS_FAILED 2UL

#define KSWORD_ARK_QUERY_FILE_INFO_FLAG_DIRECTORY 0x00000001UL
#define KSWORD_ARK_QUERY_FILE_INFO_FLAG_OPEN_REPARSE_POINT 0x00000002UL
#define KSWORD_ARK_QUERY_FILE_INFO_FLAG_INCLUDE_OBJECT_NAME 0x00000004UL
#define KSWORD_ARK_QUERY_FILE_INFO_FLAG_INCLUDE_SECTION_POINTERS 0x00000008UL
#define KSWORD_ARK_QUERY_FILE_INFO_FLAG_INCLUDE_ALL \
    (KSWORD_ARK_QUERY_FILE_INFO_FLAG_OPEN_REPARSE_POINT | \
     KSWORD_ARK_QUERY_FILE_INFO_FLAG_INCLUDE_OBJECT_NAME | \
     KSWORD_ARK_QUERY_FILE_INFO_FLAG_INCLUDE_SECTION_POINTERS)

#define KSWORD_ARK_FILE_INFO_FIELD_BASIC_PRESENT 0x00000001UL
#define KSWORD_ARK_FILE_INFO_FIELD_STANDARD_PRESENT 0x00000002UL
#define KSWORD_ARK_FILE_INFO_FIELD_OBJECT_NAME_PRESENT 0x00000004UL
#define KSWORD_ARK_FILE_INFO_FIELD_FILE_OBJECT_PRESENT 0x00000008UL
#define KSWORD_ARK_FILE_INFO_FIELD_SECTION_POINTERS_PRESENT 0x00000010UL
#define KSWORD_ARK_FILE_INFO_FIELD_DATA_SECTION_PRESENT 0x00000020UL
#define KSWORD_ARK_FILE_INFO_FIELD_IMAGE_SECTION_PRESENT 0x00000040UL
#define KSWORD_ARK_FILE_INFO_FIELD_DIRECTORY 0x00000080UL
#define KSWORD_ARK_FILE_INFO_FIELD_REQUEST_PATH_PRESENT 0x00000100UL
#define KSWORD_ARK_FILE_INFO_FIELD_DEVICE_OBJECT_PRESENT 0x00000200UL
#define KSWORD_ARK_FILE_INFO_FIELD_VPB_PRESENT 0x00000400UL
#define KSWORD_ARK_FILE_INFO_FIELD_FS_CONTEXT_PRESENT 0x00000800UL
#define KSWORD_ARK_FILE_INFO_FIELD_SHARE_ACCESS_PRESENT 0x00001000UL
#define KSWORD_ARK_FILE_INFO_FIELD_SHARED_CACHE_MAP_PRESENT 0x00002000UL

#define KSWORD_ARK_FILE_INFO_STATUS_UNAVAILABLE 0UL
#define KSWORD_ARK_FILE_INFO_STATUS_OK 1UL
#define KSWORD_ARK_FILE_INFO_STATUS_PARTIAL 2UL
#define KSWORD_ARK_FILE_INFO_STATUS_OPEN_FAILED 3UL
#define KSWORD_ARK_FILE_INFO_STATUS_BASIC_FAILED 4UL
#define KSWORD_ARK_FILE_INFO_STATUS_STANDARD_FAILED 5UL
#define KSWORD_ARK_FILE_INFO_STATUS_OBJECT_FAILED 6UL
#define KSWORD_ARK_FILE_INFO_STATUS_NAME_FAILED 7UL

#define KSWORD_ARK_FILE_INFO_PATH_MAX_CHARS 1024U
#define KSWORD_ARK_FILE_INFO_OBJECT_NAME_MAX_CHARS 1024U
#define KSWORD_ARK_FILE_INFO_DEVICE_NAME_MAX_CHARS 512U
#define KSWORD_ARK_FILE_INFO_VOLUME_LABEL_MAX_CHARS 64U

// 驱动目录枚举采用小页分页，避免 METHOD_BUFFERED 为单个大目录锁定过大的非分页缓冲。
#define KSWORD_ARK_DIRECTORY_ENUM_PATH_MAX_CHARS 1024U
#define KSWORD_ARK_DIRECTORY_ENUM_NAME_MAX_CHARS 260U
#define KSWORD_ARK_DIRECTORY_ENUM_FS_NAME_MAX_CHARS 32U
#define KSWORD_ARK_DIRECTORY_ENUM_DEFAULT_PAGE_ENTRIES 256UL
#define KSWORD_ARK_DIRECTORY_ENUM_MAX_PAGE_ENTRIES 512UL
#define KSWORD_ARK_DIRECTORY_ENUM_MAX_TOTAL_ENTRIES 65536UL

// queryStatus 区分通信成功与目录打开/枚举语义结果，R3 不得把部分结果误报为完整快照。
#define KSWORD_ARK_DIRECTORY_ENUM_STATUS_UNAVAILABLE 0UL
#define KSWORD_ARK_DIRECTORY_ENUM_STATUS_OK 1UL
#define KSWORD_ARK_DIRECTORY_ENUM_STATUS_PARTIAL 2UL
#define KSWORD_ARK_DIRECTORY_ENUM_STATUS_OPEN_FAILED 3UL
#define KSWORD_ARK_DIRECTORY_ENUM_STATUS_QUERY_FAILED 4UL
#define KSWORD_ARK_DIRECTORY_ENUM_STATUS_INVALID_REQUEST 5UL

// MORE_AVAILABLE 表示 R3 应使用 nextIndex 请求下一页；FS_NAME_PRESENT 表示文件系统名可信。
#define KSWORD_ARK_DIRECTORY_ENUM_RESPONSE_FLAG_MORE_AVAILABLE 0x00000001UL
#define KSWORD_ARK_DIRECTORY_ENUM_RESPONSE_FLAG_FS_NAME_PRESENT 0x00000002UL

// 行标志由驱动依据 FILE_ID_BOTH_DIR_INFORMATION 生成，避免 R3 重复解释属性位。
#define KSWORD_ARK_DIRECTORY_ENTRY_FLAG_DIRECTORY 0x00000001UL
#define KSWORD_ARK_DIRECTORY_ENTRY_FLAG_REPARSE_POINT 0x00000002UL
#define KSWORD_ARK_DIRECTORY_ENTRY_FLAG_NAME_TRUNCATED 0x00000004UL

typedef struct _KSWORD_ARK_DELETE_PATH_REQUEST
{
    unsigned long flags;
    unsigned short pathLengthChars;
    unsigned short reserved;
    wchar_t path[KSWORD_ARK_DELETE_PATH_MAX_CHARS];
} KSWORD_ARK_DELETE_PATH_REQUEST;

typedef struct _KSWORD_ARK_QUERY_FILE_INFO_REQUEST
{
    unsigned long flags;
    unsigned short pathLengthChars;
    unsigned short reserved;
    wchar_t path[KSWORD_ARK_FILE_INFO_PATH_MAX_CHARS];
} KSWORD_ARK_QUERY_FILE_INFO_REQUEST;

typedef struct _KSWORD_ARK_SET_FILE_INTEGRITY_REQUEST
{
    unsigned long size;
    unsigned long version;
    unsigned long flags;
    unsigned long integrityRid;
    unsigned short pathLengthChars;
    unsigned short reserved;
    wchar_t path[KSWORD_ARK_FILE_INTEGRITY_PATH_MAX_CHARS];
} KSWORD_ARK_SET_FILE_INTEGRITY_REQUEST;

typedef struct _KSWORD_ARK_SET_FILE_INTEGRITY_RESPONSE
{
    unsigned long size;
    unsigned long version;
    unsigned long flags;
    unsigned long integrityRid;
    unsigned long status;
    long lastStatus;
    unsigned short pathLengthChars;
    unsigned short reserved;
} KSWORD_ARK_SET_FILE_INTEGRITY_RESPONSE;

typedef struct _KSWORD_ARK_QUERY_FILE_INFO_RESPONSE
{
    unsigned long version;
    unsigned long size;
    unsigned long fieldFlags;
    unsigned long queryStatus;
    long openStatus;
    long basicStatus;
    long standardStatus;
    long objectStatus;
    long nameStatus;
    unsigned long fileAttributes;
    unsigned long reserved0;
    unsigned long reserved1;
    long long allocationSize;
    long long endOfFile;
    long long creationTime;
    long long lastAccessTime;
    long long lastWriteTime;
    long long changeTime;
    unsigned long long fileObjectAddress;
    unsigned long long deviceObjectAddress;
    unsigned long long vpbAddress;
    unsigned long long fsContextAddress;
    unsigned long long fsContext2Address;
    unsigned long long sectionObjectPointersAddress;
    unsigned long long dataSectionObjectAddress;
    unsigned long long imageSectionObjectAddress;
    unsigned long long sharedCacheMapAddress;
    unsigned long deletePending;
    unsigned long readAccess;
    unsigned long writeAccess;
    unsigned long deleteAccess;
    unsigned long sharedRead;
    unsigned long sharedWrite;
    unsigned long sharedDelete;
    unsigned long vpbFlags;
    unsigned long vpbSerialNumber;
    unsigned long reserved2;
    wchar_t ntPath[KSWORD_ARK_FILE_INFO_PATH_MAX_CHARS];
    wchar_t objectName[KSWORD_ARK_FILE_INFO_OBJECT_NAME_MAX_CHARS];
    wchar_t deviceName[KSWORD_ARK_FILE_INFO_DEVICE_NAME_MAX_CHARS];
    wchar_t volumeLabel[KSWORD_ARK_FILE_INFO_VOLUME_LABEL_MAX_CHARS];
} KSWORD_ARK_QUERY_FILE_INFO_RESPONSE;

// KSWORD_ARK_ENUM_DIRECTORY_REQUEST：按稳定的可见条目索引请求一个目录页。
typedef struct _KSWORD_ARK_ENUM_DIRECTORY_REQUEST
{
    unsigned long version;
    unsigned long size;
    unsigned long flags;
    unsigned long startIndex;
    unsigned long maxEntries;
    unsigned short pathLengthChars;
    unsigned short reserved;
    wchar_t path[KSWORD_ARK_DIRECTORY_ENUM_PATH_MAX_CHARS];
} KSWORD_ARK_ENUM_DIRECTORY_REQUEST,
  *PKSWORD_ARK_ENUM_DIRECTORY_REQUEST;

// KSWORD_ARK_DIRECTORY_ENTRY：R0 返回的目录项元数据；名称始终由驱动边界校验并补 NUL。
typedef struct _KSWORD_ARK_DIRECTORY_ENTRY
{
    unsigned long flags;
    unsigned long fileAttributes;
    unsigned long nameLengthChars;
    unsigned long reserved;
    unsigned long long fileId;
    long long allocationSize;
    long long endOfFile;
    long long creationTime;
    long long lastAccessTime;
    long long lastWriteTime;
    long long changeTime;
    wchar_t name[KSWORD_ARK_DIRECTORY_ENUM_NAME_MAX_CHARS];
} KSWORD_ARK_DIRECTORY_ENTRY,
  *PKSWORD_ARK_DIRECTORY_ENTRY;

// KSWORD_ARK_ENUM_DIRECTORY_RESPONSE：固定头后紧跟 rowCount 个同版本固定大小行。
typedef struct _KSWORD_ARK_ENUM_DIRECTORY_RESPONSE
{
    unsigned long version;
    unsigned long size;
    unsigned long queryStatus;
    unsigned long responseFlags;
    unsigned long rowSize;
    unsigned long rowCount;
    unsigned long startIndex;
    unsigned long nextIndex;
    long openStatus;
    long lastStatus;
    unsigned long fileSystemNameLengthChars;
    unsigned long reserved;
    wchar_t fileSystemName[KSWORD_ARK_DIRECTORY_ENUM_FS_NAME_MAX_CHARS];
    KSWORD_ARK_DIRECTORY_ENTRY rows[1];
} KSWORD_ARK_ENUM_DIRECTORY_RESPONSE,
  *PKSWORD_ARK_ENUM_DIRECTORY_RESPONSE;

#define KSWORD_ARK_ENUM_DIRECTORY_RESPONSE_HEADER_SIZE \
    (sizeof(KSWORD_ARK_ENUM_DIRECTORY_RESPONSE) - sizeof(KSWORD_ARK_DIRECTORY_ENTRY))
