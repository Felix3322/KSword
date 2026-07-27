#pragma once

class QApplication;

#include <QtGlobal>

namespace ks::ui
{
    // InstallGlobalTableInteractionSupport 作用：
    // - 为应用内所有 QTableView/QTableWidget 统一提供 Ctrl 多选、Ctrl+C 复制和 TSV 导出；
    // - 保留业务表格的原有右键菜单，并在其末尾追加复制选中行和导出选中行；
    // - 每张表顶部预留紧凑操作区并放置导出按钮，动态创建的表格也会自动接入。
    void InstallGlobalTableInteractionSupport(QApplication* appInstance);

    // OpenProcessDetailByPid 作用：请求主窗口打开指定 PID 的进程详细信息。
    // - 由各业务表的右键菜单显式调用，不负责自动为表格添加菜单项；
    // - pid 为 0 或主窗口尚未创建时不执行操作。
    void OpenProcessDetailByPid(quint32 pid);
}
