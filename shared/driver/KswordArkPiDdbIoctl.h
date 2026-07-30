#pragma once

#include "KswordArkProcessIoctl.h"

#define KSWORD_ARK_PIDDB_PROTOCOL_VERSION 1UL

#define KSWORD_ARK_IOCTL_FUNCTION_QUERY_PIDDB  0x8C8UL
#define KSWORD_ARK_IOCTL_FUNCTION_DELETE_PIDDB 0x8C9UL

#define IOCTL_KSWORD_ARK_QUERY_PIDDB \
    CTL_CODE(KSWORD_ARK_IOCTL_DEVICE_TYPE, KSWORD_ARK_IOCTL_FUNCTION_QUERY_PIDDB, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_KSWORD_ARK_DELETE_PIDDB \
    CTL_CODE(KSWORD_ARK_IOCTL_DEVICE_TYPE, KSWORD_ARK_IOCTL_FUNCTION_DELETE_PIDDB, METHOD_BUFFERED, FILE_WRITE_ACCESS)

#define KSWORD_ARK_PIDDB_MAX_ROWS 4096UL
#define KSWORD_ARK_PIDDB_DEFAULT_ROWS 512UL
#define KSWORD_ARK_PIDDB_NAME_CHARS 260U

#define KSWORD_ARK_PIDDB_QUERY_STATUS_OK              0UL
#define KSWORD_ARK_PIDDB_QUERY_STATUS_DYNDATA_MISSING 1UL
#define KSWORD_ARK_PIDDB_QUERY_STATUS_INVALID_LAYOUT  2UL
#define KSWORD_ARK_PIDDB_QUERY_STATUS_READ_FAILED     3UL
#define KSWORD_ARK_PIDDB_QUERY_STATUS_PARTIAL         4UL

#define KSWORD_ARK_PIDDB_RESPONSE_FLAG_TRUNCATED 0x00000001UL

#define KSWORD_ARK_PIDDB_DELETE_FLAG_UI_CONFIRMED 0x00000001UL
#define KSWORD_ARK_PIDDB_DELETE_FLAG_FORCE        0x00000002UL
#define KSWORD_ARK_PIDDB_DELETE_CONFIRMATION_TOKEN 0x50494442UL

#define KSWORD_ARK_PIDDB_DELETE_STATUS_OK               0UL
#define KSWORD_ARK_PIDDB_DELETE_STATUS_INVALID_REQUEST  1UL
#define KSWORD_ARK_PIDDB_DELETE_STATUS_DYNDATA_MISSING  2UL
#define KSWORD_ARK_PIDDB_DELETE_STATUS_NOT_FOUND        3UL
#define KSWORD_ARK_PIDDB_DELETE_STATUS_IDENTITY_CHANGED 4UL
#define KSWORD_ARK_PIDDB_DELETE_STATUS_FORCE_REQUIRED   5UL
#define KSWORD_ARK_PIDDB_DELETE_STATUS_DELETE_FAILED    6UL
#define KSWORD_ARK_PIDDB_DELETE_STATUS_VERIFY_FAILED    7UL

typedef struct _KSWORD_ARK_QUERY_PIDDB_REQUEST
{
    unsigned long version;
    unsigned long size;
    unsigned long flags;
    unsigned long maxRows;
} KSWORD_ARK_QUERY_PIDDB_REQUEST;

typedef struct _KSWORD_ARK_PIDDB_ROW
{
    unsigned long long entryAddress;
    unsigned long timeDateStamp;
    long loadStatus;
    unsigned long nameLengthBytes;
    unsigned long reserved;
    wchar_t driverName[KSWORD_ARK_PIDDB_NAME_CHARS];
} KSWORD_ARK_PIDDB_ROW;

typedef struct _KSWORD_ARK_QUERY_PIDDB_RESPONSE
{
    unsigned long version;
    unsigned long size;
    unsigned long rowSize;
    unsigned long queryStatus;
    unsigned long responseFlags;
    unsigned long totalRows;
    unsigned long returnedRows;
    long lastStatus;
    KSWORD_ARK_PIDDB_ROW rows[1];
} KSWORD_ARK_QUERY_PIDDB_RESPONSE;

#define KSWORD_ARK_QUERY_PIDDB_RESPONSE_HEADER_SIZE \
    (sizeof(KSWORD_ARK_QUERY_PIDDB_RESPONSE) - sizeof(KSWORD_ARK_PIDDB_ROW))

typedef struct _KSWORD_ARK_DELETE_PIDDB_REQUEST
{
    unsigned long version;
    unsigned long size;
    unsigned long flags;
    unsigned long confirmationToken;
    unsigned long long expectedEntryAddress;
    unsigned long expectedTimeDateStamp;
    long expectedLoadStatus;
    wchar_t driverName[KSWORD_ARK_PIDDB_NAME_CHARS];
} KSWORD_ARK_DELETE_PIDDB_REQUEST;

typedef struct _KSWORD_ARK_DELETE_PIDDB_RESPONSE
{
    unsigned long version;
    unsigned long size;
    unsigned long status;
    unsigned long remainingRows;
    long lastStatus;
    unsigned long reserved;
    unsigned long long matchedEntryAddress;
    unsigned long matchedTimeDateStamp;
    long matchedLoadStatus;
    wchar_t matchedDriverName[KSWORD_ARK_PIDDB_NAME_CHARS];
} KSWORD_ARK_DELETE_PIDDB_RESPONSE;
