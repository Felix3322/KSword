#pragma once

#include <functional>

#include <QObject>
#include <QTabWidget>
#include <QWidget>

// createBasicPlaceholder:
// - Inputs: tipText is the text displayed in the placeholder body.
// - Processing: the implementation builds a simple QWidget with centered text.
// - Return: a newly allocated QWidget owned by the caller/Qt parent chain.
QWidget* createBasicPlaceholder(const QString& tipText = "Placeholder panel");

namespace ks::ui
{
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
