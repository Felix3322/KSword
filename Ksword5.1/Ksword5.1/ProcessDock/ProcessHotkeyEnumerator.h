#pragma once

#include <QString>

#include <cstdint>
#include <functional>
#include <string>
#include <vector>

namespace ks::process
{
    // UserModeHotkeyRecord：进程详情“热键”页中可由 R3 读取的一条热键记录。
    struct UserModeHotkeyRecord
    {
        QString objectText;
        std::uint32_t hotkeyId = 0;
        std::uint32_t modifiers = 0;
        std::uint32_t virtualKey = 0;
        QString hotkeyText;
        std::uint32_t processId = 0;
        std::uint32_t threadId = 0;
        QString processName;
        QString sourceText;
        QString detailText;
    };

    struct UserModeHotkeyProcessTarget
    {
        std::uint32_t processId = 0;
        QString processName;
        QString processImagePath;
    };

    struct UserModeHotkeyBatchProgress
    {
        std::uint32_t completedProcessCount = 0;
        std::uint32_t totalProcessCount = 0;
        QString processName;
        QString diagnosticText;
        std::vector<UserModeHotkeyRecord> records;
    };

    using UserModeHotkeyBatchCallback = std::function<void(UserModeHotkeyBatchProgress progress)>;

    // EnumerateUserModeHotkeysForProcess：复用进程详情的 R3 热键采集路径。
    // 只扫描窗口热键、菜单快捷键、PE Accelerator 资源和 .lnk 快捷方式热键，不访问驱动。
    std::vector<UserModeHotkeyRecord> EnumerateUserModeHotkeysForProcess(
        std::uint32_t processId,
        QString processName = {},
        QString processImagePath = {},
        QString* diagnosticTextOut = nullptr);

    // EnumerateUserModeHotkeysForProcesses：全量扫描时共享一次 .lnk 读取结果，逐进程回调。
    void EnumerateUserModeHotkeysForProcesses(
        const std::vector<UserModeHotkeyProcessTarget>& targets,
        const UserModeHotkeyBatchCallback& progressCallback,
        QString* diagnosticTextOut = nullptr);
}
