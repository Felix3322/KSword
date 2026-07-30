#pragma once

// ============================================================
// DiskMonitorStorageLeaseCoordinator.h
// 作用：
// 1) 为磁盘存储页提供按卷唯一的性能计数器 lease；
// 2) 把 IOCTL_DISK_PERFORMANCE_OFF 交给单一后台 worker；
// 3) 在 OFF 持续失败时保留有界、可重试的进程期账本。
// ============================================================

#include <QString>

#include <array>
#include <cstdint>
#include <memory>

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>

namespace disk_monitor_storage_lease
{
    // Lease：
    // - 由协调器创建并按卷 GUID 唯一持有；
    // - 活动态由采样线程读写，退役后只允许协调器 worker 访问；
    // - ownedEnableReferenceCount 精确记录本进程需要补偿的 OFF 次数。
    struct Lease
    {
        QString volumeGuidName;               // volumeGuidName：规范化后的卷 GUID 路径。
        QString storageManagerName;           // storageManagerName：性能提供者名称。
        std::array<std::uint16_t, 8> storageManagerIdentity{}; // storageManagerIdentity：原始提供者身份。
        std::uint32_t volumeSerialNumber = 0U; // volumeSerialNumber：卷序列号。
        std::uint32_t storageDeviceNumber = 0U; // storageDeviceNumber：性能提供者设备编号。
        HANDLE volumeHandle = INVALID_HANDLE_VALUE; // volumeHandle：性能查询与 OFF 共用的卷句柄。
        std::uint32_t ownedEnableReferenceCount = 0U; // ownedEnableReferenceCount：仍需 OFF 的本进程引用数。
        std::uint32_t lastQueryError = 0U;     // lastQueryError：最后一次查询或平衡错误。
        std::uint32_t consecutiveQueryFailureCount = 0U; // consecutiveQueryFailureCount：连续查询失败次数。
    };

    using LeasePointer = std::shared_ptr<Lease>;

    // tryAcquireActiveLease：
    // - 输入：规范化前或规范化后的卷 GUID；
    // - 返回：该卷没有 active/retiring 槽位时返回唯一 lease，否则返回空；
    // - 调用方获得 lease 后必须插入活动表，或调用 releaseUnusedActiveLease。
    LeasePointer tryAcquireActiveLease(const QString& volumeGuidName);

    // releaseUnusedActiveLease：
    // - 输入：尚未成功增加性能引用的 active lease；
    // - 处理：移除按卷占位，不执行 OFF，也不关闭调用方仍持有的句柄；
    // - 返回：槽位与传入 lease 匹配时为 true。
    bool releaseUnusedActiveLease(const LeasePointer& lease);

    // retireLeaseAsync：
    // - 输入：需要补偿 ownedEnableReferenceCount 的 active lease 和诊断原因；
    // - 处理：原子切换为 retiring，唤醒唯一后台 worker；
    // - 返回：成功接管或同一 lease 已在退役时为 true，不执行同步 OFF。
    bool retireLeaseAsync(
        const LeasePointer& lease,
        const QString& reason);

    // turnOffOneReference：
    // - 输入：lease 与可选错误码输出；
    // - 处理：只补偿一次本进程拥有的性能启用引用；
    // - 返回：无需补偿或本次 OFF 成功时为 true。
    bool turnOffOneReference(
        Lease* lease,
        DWORD* errorOut = nullptr);
}
