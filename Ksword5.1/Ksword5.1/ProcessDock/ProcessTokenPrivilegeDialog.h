#pragma once

#include <cstdint>

class QString;
class QWidget;

namespace ks::process_ui
{
    // showProcessTokenPrivilegeDialog：
    // - 输入：父窗口、目标 PID、可选创建时间和进程显示名；
    // - 处理：读取目标主令牌特权并提供 R3/R0 调整编辑器；
    // - 返回：true 表示本次窗口生命周期内至少提交过一项调整。
    bool showProcessTokenPrivilegeDialog(
        QWidget* parent,
        std::uint32_t processId,
        std::uint64_t expectedCreateTime100ns,
        const QString& processDisplayName);
}
