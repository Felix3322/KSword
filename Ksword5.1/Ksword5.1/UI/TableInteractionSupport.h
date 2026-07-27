#pragma once

class QApplication;

namespace ks::ui
{
    // InstallGlobalTableInteractionSupport 作用：
    // - 为应用内所有 QTableView/QTableWidget 统一提供 Ctrl 多选、Ctrl+C 复制和 TSV 导出；
    // - 保留业务表格的原有右键菜单，并在其末尾追加复制选中行和导出选中行；
    // - 每张表顶部预留紧凑操作区并放置导出按钮，动态创建的表格也会自动接入。
    void InstallGlobalTableInteractionSupport(QApplication* appInstance);
}
