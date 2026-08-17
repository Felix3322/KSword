#pragma once

#include <functional>

#include <QObject>
#include <QSize>
#include <QTabWidget>
#include <QWidget>

// createBasicPlaceholder:
// - Inputs: tipText is the text displayed in the placeholder body.
// - Processing: the implementation builds a simple QWidget with centered text.
// - Return: a newly allocated QWidget owned by the caller/Qt parent chain.
QWidget* createBasicPlaceholder(const QString& tipText = "Placeholder panel");

namespace ks::ui
{
    // applyResponsiveWindowGeometry 作用：
    // - 依据父窗口所在屏幕的可用区域钳制初始尺寸与最低尺寸；
    // - 高 DPI、小屏和远程桌面环境下不会因硬编码 minimumSize 把窗口撑出工作区；
    // - 只约束初始/最低尺寸，不限制用户之后最大化窗口。
    void applyResponsiveWindowGeometry(
        QWidget* window,
        QWidget* candidateParent,
        const QSize& preferredSize,
        const QSize& minimumSize,
        double maxAvailableRatio = 0.9);

    // scheduleDeferredTabActivation 作用：
    // - 将重型 Tab 页面构造从 currentChanged 同步调用点延后到下一轮 UI 事件循环；
    // - context/placeholder 任何一个销毁后，回调都不会再访问失效控件。
    using DeferredTabActivationCallback = std::function<void()>;

    void scheduleDeferredTabActivation(
        QObject* context,
        QTabWidget* tabWidget,
        int tabIndex,
        QWidget* placeholderPage,
        DeferredTabActivationCallback callback);
}
