#pragma once

#include "KswordArkProcessIoctl.h"

#define KSWORD_ARK_KERNEL_BASELINE_PROTOCOL_VERSION 1UL

#define KSWORD_ARK_IOCTL_FUNCTION_RESTORE_IDT_BASELINE 0x8C7UL

#define IOCTL_KSWORD_ARK_RESTORE_IDT_BASELINE \
    CTL_CODE( \
        KSWORD_ARK_IOCTL_DEVICE_TYPE, \
        KSWORD_ARK_IOCTL_FUNCTION_RESTORE_IDT_BASELINE, \
        METHOD_BUFFERED, \
        FILE_WRITE_ACCESS)

#define KSWORD_ARK_IDT_RESTORE_FLAG_UI_CONFIRMED 0x00000001UL
#define KSWORD_ARK_IDT_RESTORE_FLAG_FORCE        0x00000002UL

#define KSWORD_ARK_IDT_RESTORE_STATUS_OK                 0UL
#define KSWORD_ARK_IDT_RESTORE_STATUS_INVALID_REQUEST    1UL
#define KSWORD_ARK_IDT_RESTORE_STATUS_BASELINE_MISSING   2UL
#define KSWORD_ARK_IDT_RESTORE_STATUS_CPU_UNAVAILABLE    3UL
#define KSWORD_ARK_IDT_RESTORE_STATUS_TABLE_CHANGED      4UL
#define KSWORD_ARK_IDT_RESTORE_STATUS_CURRENT_MISMATCH   5UL
#define KSWORD_ARK_IDT_RESTORE_STATUS_FORCE_REQUIRED     6UL
#define KSWORD_ARK_IDT_RESTORE_STATUS_WRITE_FAILED       7UL
#define KSWORD_ARK_IDT_RESTORE_STATUS_VERIFY_FAILED      8UL

#define KSWORD_ARK_IDT_RESTORE_CONFIRMATION_TOKEN 0x49445452UL

typedef struct _KSWORD_ARK_RESTORE_IDT_BASELINE_REQUEST
{
    unsigned long version;
    unsigned long size;
    unsigned long flags;
    unsigned long confirmationToken;
    unsigned short processorGroup;
    unsigned char processorNumber;
    unsigned char vector;
    unsigned long reserved;
    unsigned long long expectedRawLow;
    unsigned long long expectedRawHigh;
} KSWORD_ARK_RESTORE_IDT_BASELINE_REQUEST;

typedef struct _KSWORD_ARK_RESTORE_IDT_BASELINE_RESPONSE
{
    unsigned long version;
    unsigned long size;
    unsigned long status;
    unsigned long baselineGeneration;
    long lastStatus;
    unsigned long reserved;
    unsigned long long entryAddress;
    unsigned long long beforeRawLow;
    unsigned long long beforeRawHigh;
    unsigned long long baselineRawLow;
    unsigned long long baselineRawHigh;
    unsigned long long afterRawLow;
    unsigned long long afterRawHigh;
} KSWORD_ARK_RESTORE_IDT_BASELINE_RESPONSE;
