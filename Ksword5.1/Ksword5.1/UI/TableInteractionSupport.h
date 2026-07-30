#pragma once

class QApplication;
class QObject;
class QTableView;

#include <QList>
#include <QString>
#include <QtGlobal>

#include <functional>

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

    // OpenProcessDetailByIdentity 作用：
    // - 按 PID 与捕获时创建时间请求打开历史进程详情；
    // - 调用方式：持有历史事件 identity 的业务表右键菜单调用；
    // - 入参 pid：历史事件中的进程 PID；
    // - 入参 creationTime100ns：历史事件捕获时的进程创建时间；
    // - 返回：无；identity 缺失时不降级为纯 PID 跳转。
    void OpenProcessDetailByIdentity(
        quint32 pid,
        quint64 creationTime100ns);

    // DeferTableUiCommitIfContextMenuOpen 作用：
    // - 输入：提交任务所有者、稳定去重键、会被重建的表格集合和 UI 提交函数；
    // - 处理：任一表格的右键菜单打开时只保留同 owner/key 的最新提交，菜单关闭后回投；
    // - 返回：true 表示本次提交已延后，false 表示当前没有右键菜单，调用方应立即提交。
    // 调用方法：刷新函数在修改模型前调用；返回 true 时立即结束本轮刷新。
    bool DeferTableUiCommitIfContextMenuOpen(
        QObject* owner,
        const QString& commitKey,
        const QList<QTableView*>& tableList,
        std::function<void()> commitAction);
}
