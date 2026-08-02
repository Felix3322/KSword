#pragma once

#include "KswordArkKernelIoctl.h"

/*
 * Generic DriverObject MajorFunction editor.
 *
 * The protocol deliberately does not impose target-driver, address-owner, or
 * product policy restrictions. APPLY is guarded only by an exact module /
 * DriverObject / slot / current-value identity tuple, an atomic CAS, and the
 * explicit confirmation token. The UI is responsible for presenting the
 * consequences of installing an arbitrary pointer.
 */
#define KSWORD_ARK_DRIVER_DISPATCH_PROTOCOL_VERSION 1UL

#define KSWORD_ARK_IOCTL_FUNCTION_CONTROL_DRIVER_DISPATCH 0x8CCUL

#define IOCTL_KSWORD_ARK_CONTROL_DRIVER_DISPATCH \
    CTL_CODE( \
        KSWORD_ARK_IOCTL_DEVICE_TYPE, \
        KSWORD_ARK_IOCTL_FUNCTION_CONTROL_DRIVER_DISPATCH, \
        METHOD_BUFFERED, \
        FILE_WRITE_ACCESS)

#define KSWORD_ARK_DRIVER_DISPATCH_ACTION_QUERY   0UL
#define KSWORD_ARK_DRIVER_DISPATCH_ACTION_APPLY   1UL
#define KSWORD_ARK_DRIVER_DISPATCH_ACTION_RESTORE 2UL
#define KSWORD_ARK_DRIVER_DISPATCH_ACTION_ABANDON 3UL

#define KSWORD_ARK_DRIVER_DISPATCH_STATE_INACTIVE 0UL
#define KSWORD_ARK_DRIVER_DISPATCH_STATE_ACTIVE   1UL
#define KSWORD_ARK_DRIVER_DISPATCH_STATE_CONFLICT 2UL

#define KSWORD_ARK_DRIVER_DISPATCH_FLAG_TARGET_MODULE_BASE_PRESENT      0x00000001UL
#define KSWORD_ARK_DRIVER_DISPATCH_FLAG_EXPECTED_DRIVER_OBJECT_PRESENT  0x00000002UL
#define KSWORD_ARK_DRIVER_DISPATCH_FLAG_EXPECTED_CURRENT_PRESENT        0x00000004UL
#define KSWORD_ARK_DRIVER_DISPATCH_FLAG_EXPECTED_GENERATION_PRESENT     0x00000008UL
#define KSWORD_ARK_DRIVER_DISPATCH_FLAG_UI_CONFIRMED                    0x00000010UL

#define KSWORD_ARK_DRIVER_DISPATCH_RESPONSE_FLAG_RECORD_PRESENT          0x00000001UL
#define KSWORD_ARK_DRIVER_DISPATCH_RESPONSE_FLAG_OWNED                   0x00000002UL
#define KSWORD_ARK_DRIVER_DISPATCH_RESPONSE_FLAG_FOREIGN_CHANGE          0x00000004UL
#define KSWORD_ARK_DRIVER_DISPATCH_RESPONSE_FLAG_CURRENT_IS_ORIGINAL     0x00000008UL
#define KSWORD_ARK_DRIVER_DISPATCH_RESPONSE_FLAG_CURRENT_IS_APPLIED      0x00000010UL
#define KSWORD_ARK_DRIVER_DISPATCH_RESPONSE_FLAG_SELF_TARGET             0x00000020UL
#define KSWORD_ARK_DRIVER_DISPATCH_RESPONSE_FLAG_SELF_CONTROL_CHANNEL    0x00000040UL
#define KSWORD_ARK_DRIVER_DISPATCH_RESPONSE_FLAG_WARN_ONLY_POLICY        0x00000080UL
#define KSWORD_ARK_DRIVER_DISPATCH_RESPONSE_FLAG_CHANGED                 0x00000100UL

#define KSWORD_ARK_DRIVER_DISPATCH_CONFIRMATION_TOKEN 0x49525045UL

typedef struct _KSWORD_ARK_DRIVER_DISPATCH_REQUEST
{
    unsigned long version;
    unsigned long action;
    unsigned long flags;
    unsigned long majorFunction;
    unsigned long confirmationToken;
    unsigned long expectedGeneration;
    unsigned long reserved0;
    unsigned long reserved1;
    unsigned long long targetModuleBase;
    unsigned long long expectedDriverObjectAddress;
    unsigned long long expectedCurrentDispatchAddress;
    unsigned long long desiredDispatchAddress;
    wchar_t driverName[KSWORD_ARK_DRIVER_OBJECT_NAME_CHARS];
} KSWORD_ARK_DRIVER_DISPATCH_REQUEST;

typedef struct _KSWORD_ARK_DRIVER_DISPATCH_RESPONSE
{
    unsigned long version;
    unsigned long action;
    unsigned long state;
    unsigned long responseFlags;
    long lastStatus;
    unsigned long majorFunction;
    unsigned long generation;
    unsigned long reserved;
    unsigned long long targetModuleBase;
    unsigned long long driverObjectAddress;
    unsigned long long currentDispatchAddress;
    unsigned long long originalDispatchAddress;
    unsigned long long appliedDispatchAddress;
    unsigned long long requestedDispatchAddress;
    unsigned long long selfDriverObjectAddress;
    wchar_t driverName[KSWORD_ARK_DRIVER_OBJECT_NAME_CHARS];
} KSWORD_ARK_DRIVER_DISPATCH_RESPONSE;
