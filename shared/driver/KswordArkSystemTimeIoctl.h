/*
 * 参考机制的许可证与归档说明：
 * third_party/SystemWideTransmission/LICENSE.txt
 * third_party/SystemWideTransmission/NOTICE.md
 */
#pragma once

#include "KswordArkProcessIoctl.h"

/*
 * 系统全局变速协议只描述 R3/R0 之间的稳定数据契约。
 * 内核地址仅用于诊断展示，R3 不得直接读写这些地址。
 */
#define KSWORD_ARK_SYSTEM_TIME_PROTOCOL_VERSION 3UL

#define KSWORD_ARK_IOCTL_FUNCTION_QUERY_SYSTEM_TIME   0x865UL
#define KSWORD_ARK_IOCTL_FUNCTION_CONTROL_SYSTEM_TIME 0x866UL

#define IOCTL_KSWORD_ARK_QUERY_SYSTEM_TIME \
    CTL_CODE( \
        KSWORD_ARK_IOCTL_DEVICE_TYPE, \
        KSWORD_ARK_IOCTL_FUNCTION_QUERY_SYSTEM_TIME, \
        METHOD_BUFFERED, \
        FILE_ANY_ACCESS)

#define IOCTL_KSWORD_ARK_CONTROL_SYSTEM_TIME \
    CTL_CODE( \
        KSWORD_ARK_IOCTL_DEVICE_TYPE, \
        KSWORD_ARK_IOCTL_FUNCTION_CONTROL_SYSTEM_TIME, \
        METHOD_BUFFERED, \
        FILE_WRITE_ACCESS)

/* 倍率上限用于限制计数器增量溢出和系统失稳范围。 */
#define KSWORD_ARK_SYSTEM_TIME_MIN_FACTOR 2UL
#define KSWORD_ARK_SYSTEM_TIME_MAX_FACTOR 64UL

/* 控制命令统一覆盖加速、减速和恢复原始计时路径。 */
#define KSWORD_ARK_SYSTEM_TIME_COMMAND_RESET     1UL
#define KSWORD_ARK_SYSTEM_TIME_COMMAND_SPEED_UP  2UL
#define KSWORD_ARK_SYSTEM_TIME_COMMAND_SLOW_DOWN 3UL

/*
 * ORIGINAL_COMPAT 按系统版本特征直接定位 HAL 计数器描述符。
 * GUARDED 使用相同接管原理，但在返回目标前额外验证描述符和函数槽。
 */
#define KSWORD_ARK_SYSTEM_TIME_RESOLUTION_ORIGINAL_COMPAT 1UL
#define KSWORD_ARK_SYSTEM_TIME_RESOLUTION_GUARDED         2UL

/*
 * HYPERV_SHARED_QPC 同时接管 Hyper-V 用户共享 QPC 页和内核 HAL 回调。
 * HAL_COMPAT 保留原有关闭用户快速旁路并接管 HAL 回调的兼容路径。
 */
#define KSWORD_ARK_SYSTEM_TIME_BACKEND_HYPERV_SHARED_QPC 1UL
#define KSWORD_ARK_SYSTEM_TIME_BACKEND_HAL_COMPAT        2UL

/* UI_CONFIRMED 表示 R3 已完成持久警告之外的本次双重确认。 */
#define KSWORD_ARK_SYSTEM_TIME_CONTROL_FLAG_UI_CONFIRMED 0x00000001UL
#define KSWORD_ARK_SYSTEM_TIME_CONFIRMATION_TOKEN        0x54494D45UL

/* 状态位描述当前解析、接管、旁路修正和冲突情况。 */
#define KSWORD_ARK_SYSTEM_TIME_STATE_INITIALIZED          0x00000001UL
#define KSWORD_ARK_SYSTEM_TIME_STATE_SUPPORTED            0x00000002UL
#define KSWORD_ARK_SYSTEM_TIME_STATE_ACTIVE               0x00000004UL
#define KSWORD_ARK_SYSTEM_TIME_STATE_SPEED_UP              0x00000008UL
#define KSWORD_ARK_SYSTEM_TIME_STATE_SLOW_DOWN             0x00000010UL
#define KSWORD_ARK_SYSTEM_TIME_STATE_PRIMARY_HOOKED        0x00000020UL
#define KSWORD_ARK_SYSTEM_TIME_STATE_SECONDARY_HOOKED      0x00000040UL
#define KSWORD_ARK_SYSTEM_TIME_STATE_QPC_BYPASS_DISABLED   0x00000080UL
#define KSWORD_ARK_SYSTEM_TIME_STATE_INTERNAL_FLAG_PATCHED 0x00000100UL
#define KSWORD_ARK_SYSTEM_TIME_STATE_HANDLER_TABLE         0x00000200UL
#define KSWORD_ARK_SYSTEM_TIME_STATE_CONFLICT              0x00000400UL
#define KSWORD_ARK_SYSTEM_TIME_STATE_HYPERV_PRESENT         0x00000800UL
#define KSWORD_ARK_SYSTEM_TIME_STATE_HYPERV_SHARED_PAGE     0x00001000UL
#define KSWORD_ARK_SYSTEM_TIME_STATE_HYPERV_ACTIVE          0x00002000UL

/* 运行时状态码与 NTSTATUS 分离，便于旧 UI 稳定解释失败原因。 */
#define KSWORD_ARK_SYSTEM_TIME_STATUS_OK                    0UL
#define KSWORD_ARK_SYSTEM_TIME_STATUS_INVALID_REQUEST       1UL
#define KSWORD_ARK_SYSTEM_TIME_STATUS_CONFIRMATION_REQUIRED 2UL
#define KSWORD_ARK_SYSTEM_TIME_STATUS_UNSUPPORTED_BUILD     3UL
#define KSWORD_ARK_SYSTEM_TIME_STATUS_RESOLVE_FAILED        4UL
#define KSWORD_ARK_SYSTEM_TIME_STATUS_PATCH_FAILED          5UL
#define KSWORD_ARK_SYSTEM_TIME_STATUS_CONFLICT              6UL
#define KSWORD_ARK_SYSTEM_TIME_STATUS_STALE_GENERATION      7UL
#define KSWORD_ARK_SYSTEM_TIME_STATUS_NOT_ACTIVE            8UL
#define KSWORD_ARK_SYSTEM_TIME_STATUS_INTERNAL_ERROR        9UL
#define KSWORD_ARK_SYSTEM_TIME_STATUS_HYPERV_NOT_PRESENT    10UL
#define KSWORD_ARK_SYSTEM_TIME_STATUS_HYPERV_PAGE_UNAVAILABLE 11UL
#define KSWORD_ARK_SYSTEM_TIME_STATUS_HYPERV_VALIDATION_FAILED 12UL
#define KSWORD_ARK_SYSTEM_TIME_STATUS_HYPERV_WRITE_FAILED   13UL

/* 查询请求保持固定大小，后续版本可通过 flags 扩展只读诊断。 */
typedef struct _KSWORD_ARK_QUERY_SYSTEM_TIME_REQUEST
{
    unsigned long version;
    unsigned long size;
    unsigned long flags;
    unsigned long reserved;
} KSWORD_ARK_QUERY_SYSTEM_TIME_REQUEST;

/*
 * 查询响应同时返回用户可见状态与有限的解析证据。
 * counterValue 是接管后的连续虚拟计数器快照，不是系统墙上时间。
 */
typedef struct _KSWORD_ARK_QUERY_SYSTEM_TIME_RESPONSE
{
    unsigned long version;
    unsigned long size;
    unsigned long status;
    unsigned long stateFlags;
    unsigned long generation;
    unsigned long command;
    unsigned long factor;
    unsigned long osBuildNumber;
    long lastStatus;
    unsigned long resolutionMode;
    unsigned long backend;
    unsigned long reserved;
    unsigned long long counterValue;
    unsigned long long counterSourceAddress;
    unsigned long long primarySlotAddress;
    unsigned long long secondarySlotAddress;
    unsigned long long hypervisorSharedPageAddress;
    unsigned long long hypervisorTimeUpdateLock;
    unsigned long long hypervisorOriginalMultiplier;
    unsigned long long hypervisorOriginalBias;
    unsigned long long hypervisorCurrentMultiplier;
    unsigned long long hypervisorCurrentBias;
} KSWORD_ARK_QUERY_SYSTEM_TIME_RESPONSE;

/*
 * expectedGeneration 防止页面使用过期状态覆盖其他控制者的操作。
 * RESET 始终允许恢复，不要求 confirmationToken。
 */
typedef struct _KSWORD_ARK_CONTROL_SYSTEM_TIME_REQUEST
{
    unsigned long version;
    unsigned long size;
    unsigned long command;
    unsigned long factor;
    unsigned long flags;
    unsigned long confirmationToken;
    unsigned long expectedGeneration;
    unsigned long resolutionMode;
    unsigned long backend;
} KSWORD_ARK_CONTROL_SYSTEM_TIME_REQUEST;

/* 控制响应返回动作前后状态，R3 可立即更新页面而无需猜测。 */
typedef struct _KSWORD_ARK_CONTROL_SYSTEM_TIME_RESPONSE
{
    unsigned long version;
    unsigned long size;
    unsigned long status;
    unsigned long oldStateFlags;
    unsigned long newStateFlags;
    unsigned long oldGeneration;
    unsigned long newGeneration;
    unsigned long command;
    unsigned long factor;
    unsigned long osBuildNumber;
    long lastStatus;
    unsigned long resolutionMode;
    unsigned long backend;
    unsigned long reserved;
    unsigned long long counterValue;
} KSWORD_ARK_CONTROL_SYSTEM_TIME_RESPONSE;
