#pragma once

#include "KswordArkKernelIoctl.h"

/*
 * DriverObject image metadata and PsLoadedModuleList transaction protocol.
 *
 * The protocol does not restrict a target by driver class, product identity,
 * image-owner policy, or requested value. Mutations remain guarded by an exact
 * DriverObject identity, expected-current values, loader-link observations,
 * a transaction generation, and an explicit UI confirmation token.
 */
#define KSWORD_ARK_DRIVER_IMAGE_PROTOCOL_VERSION 1UL

#define KSWORD_ARK_IOCTL_FUNCTION_CONTROL_DRIVER_IMAGE 0x8CEUL

#define IOCTL_KSWORD_ARK_CONTROL_DRIVER_IMAGE \
    CTL_CODE( \
        KSWORD_ARK_IOCTL_DEVICE_TYPE, \
        KSWORD_ARK_IOCTL_FUNCTION_CONTROL_DRIVER_IMAGE, \
        METHOD_BUFFERED, \
        FILE_WRITE_ACCESS)

#define KSWORD_ARK_DRIVER_IMAGE_ACTION_QUERY        0UL
#define KSWORD_ARK_DRIVER_IMAGE_ACTION_APPLY_FIELDS 1UL
#define KSWORD_ARK_DRIVER_IMAGE_ACTION_HIDE         2UL
#define KSWORD_ARK_DRIVER_IMAGE_ACTION_RESTORE      3UL
#define KSWORD_ARK_DRIVER_IMAGE_ACTION_ABANDON      4UL

#define KSWORD_ARK_DRIVER_IMAGE_STATE_INACTIVE 0UL
#define KSWORD_ARK_DRIVER_IMAGE_STATE_ACTIVE   1UL
#define KSWORD_ARK_DRIVER_IMAGE_STATE_CONFLICT 2UL

#define KSWORD_ARK_DRIVER_IMAGE_FIELD_DRIVER_START       0x00000001UL
#define KSWORD_ARK_DRIVER_IMAGE_FIELD_DRIVER_SIZE        0x00000002UL
#define KSWORD_ARK_DRIVER_IMAGE_FIELD_DRIVER_SECTION     0x00000004UL
#define KSWORD_ARK_DRIVER_IMAGE_FIELD_KLDR_DLL_BASE      0x00000008UL
#define KSWORD_ARK_DRIVER_IMAGE_FIELD_KLDR_SIZE_OF_IMAGE 0x00000010UL
#define KSWORD_ARK_DRIVER_IMAGE_FIELD_ALL                0x0000001FUL

#define KSWORD_ARK_DRIVER_IMAGE_FLAG_TARGET_MODULE_BASE_PRESENT     0x00000001UL
#define KSWORD_ARK_DRIVER_IMAGE_FLAG_EXPECTED_DRIVER_OBJECT_PRESENT 0x00000002UL
#define KSWORD_ARK_DRIVER_IMAGE_FLAG_EXPECTED_GENERATION_PRESENT    0x00000004UL
#define KSWORD_ARK_DRIVER_IMAGE_FLAG_EXPECTED_VALUES_PRESENT        0x00000008UL
#define KSWORD_ARK_DRIVER_IMAGE_FLAG_EXPECTED_LINKS_PRESENT         0x00000010UL
#define KSWORD_ARK_DRIVER_IMAGE_FLAG_UI_CONFIRMED                   0x00000020UL
#define KSWORD_ARK_DRIVER_IMAGE_FLAG_RESTORE_LINK                   0x00000040UL

#define KSWORD_ARK_DRIVER_IMAGE_RESPONSE_FLAG_RECORD_PRESENT             0x00000001UL
#define KSWORD_ARK_DRIVER_IMAGE_RESPONSE_FLAG_WARN_ONLY_POLICY           0x00000002UL
#define KSWORD_ARK_DRIVER_IMAGE_RESPONSE_FLAG_SELF_TARGET                0x00000004UL
#define KSWORD_ARK_DRIVER_IMAGE_RESPONSE_FLAG_LAYOUT_AVAILABLE           0x00000008UL
#define KSWORD_ARK_DRIVER_IMAGE_RESPONSE_FLAG_LIST_LOCK_AVAILABLE        0x00000010UL
#define KSWORD_ARK_DRIVER_IMAGE_RESPONSE_FLAG_LOADER_AVAILABLE           0x00000020UL
#define KSWORD_ARK_DRIVER_IMAGE_RESPONSE_FLAG_LINK_VISIBLE               0x00000040UL
#define KSWORD_ARK_DRIVER_IMAGE_RESPONSE_FLAG_LINK_HIDDEN                0x00000080UL
#define KSWORD_ARK_DRIVER_IMAGE_RESPONSE_FLAG_LINK_OWNED                 0x00000100UL
#define KSWORD_ARK_DRIVER_IMAGE_RESPONSE_FLAG_LINK_CONFLICT              0x00000200UL
#define KSWORD_ARK_DRIVER_IMAGE_RESPONSE_FLAG_FIELDS_OWNED               0x00000400UL
#define KSWORD_ARK_DRIVER_IMAGE_RESPONSE_FLAG_FIELDS_CONFLICT            0x00000800UL
#define KSWORD_ARK_DRIVER_IMAGE_RESPONSE_FLAG_CHANGED                    0x00001000UL
#define KSWORD_ARK_DRIVER_IMAGE_RESPONSE_FLAG_RESTORED_ORIGINAL_POSITION 0x00002000UL
#define KSWORD_ARK_DRIVER_IMAGE_RESPONSE_FLAG_RESTORED_LIST_TAIL         0x00004000UL
#define KSWORD_ARK_DRIVER_IMAGE_RESPONSE_FLAG_DRIVER_SECTION_MATCH       0x00008000UL
#define KSWORD_ARK_DRIVER_IMAGE_RESPONSE_FLAG_DRIVER_START_MATCH         0x00010000UL
#define KSWORD_ARK_DRIVER_IMAGE_RESPONSE_FLAG_PARTIAL_VIEW               0x00020000UL

#define KSWORD_ARK_DRIVER_IMAGE_LAYOUT_FLAG_DYNDATA_VALIDATED 0x00000001UL
#define KSWORD_ARK_DRIVER_IMAGE_LAYOUT_FLAG_LIST_EXPORT       0x00000002UL
#define KSWORD_ARK_DRIVER_IMAGE_LAYOUT_FLAG_RESOURCE_EXPORT   0x00000004UL

#define KSWORD_ARK_DRIVER_IMAGE_CONFIRMATION_TOKEN 0x4C445258UL

typedef struct _KSWORD_ARK_DRIVER_IMAGE_VALUES
{
    unsigned long long driverStart;
    unsigned long long driverSize;
    unsigned long long driverSection;
    unsigned long long kldrDllBase;
    unsigned long long kldrSizeOfImage;
} KSWORD_ARK_DRIVER_IMAGE_VALUES;

typedef struct _KSWORD_ARK_DRIVER_IMAGE_REQUEST
{
    unsigned long version;
    unsigned long action;
    unsigned long flags;
    unsigned long fieldMask;
    unsigned long confirmationToken;
    unsigned long expectedGeneration;
    unsigned long reserved0;
    unsigned long reserved1;
    unsigned long long targetModuleBase;
    unsigned long long expectedDriverObjectAddress;
    unsigned long long expectedLinkFlink;
    unsigned long long expectedLinkBlink;
    KSWORD_ARK_DRIVER_IMAGE_VALUES expectedValues;
    KSWORD_ARK_DRIVER_IMAGE_VALUES desiredValues;
    wchar_t driverName[KSWORD_ARK_DRIVER_OBJECT_NAME_CHARS];
} KSWORD_ARK_DRIVER_IMAGE_REQUEST;

typedef struct _KSWORD_ARK_DRIVER_IMAGE_RESPONSE
{
    unsigned long version;
    unsigned long action;
    unsigned long state;
    unsigned long responseFlags;
    long lastStatus;
    unsigned long generation;
    unsigned long managedFieldMask;
    unsigned long ownedFieldMask;
    unsigned long conflictFieldMask;
    unsigned long changedFieldMask;
    unsigned long layoutFlags;
    long loaderStatus;
    unsigned long long targetModuleBase;
    unsigned long long driverObjectAddress;
    unsigned long long selfDriverObjectAddress;
    unsigned long long loaderEntryAddress;
    unsigned long long listHeadAddress;
    unsigned long long listResourceAddress;
    unsigned long long loaderLinkAddress;
    unsigned long long currentLinkFlink;
    unsigned long long currentLinkBlink;
    unsigned long long originalLinkFlink;
    unsigned long long originalLinkBlink;
    KSWORD_ARK_DRIVER_IMAGE_VALUES currentValues;
    KSWORD_ARK_DRIVER_IMAGE_VALUES originalValues;
    KSWORD_ARK_DRIVER_IMAGE_VALUES appliedValues;
    KSWORD_ARK_DRIVER_IMAGE_VALUES requestedValues;
    wchar_t driverName[KSWORD_ARK_DRIVER_OBJECT_NAME_CHARS];
} KSWORD_ARK_DRIVER_IMAGE_RESPONSE;
