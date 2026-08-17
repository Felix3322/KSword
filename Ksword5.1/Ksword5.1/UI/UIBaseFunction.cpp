#include "UI_All.h"
#include "../theme.h"

#include <QApplication>
#include <QGuiApplication>
#include <QLabel>
#include <QPointer>
#include <QScreen>
#include <QTimer>
#include <QVBoxLayout>
#include <QWidget>
#include <QWindow>

#include <algorithm>
#include <cmath>
#include <utility>

QWidget* createBasicPlaceholder(const QString& tipText/* = "Placeholder panel"*/)
{
    // Allocate the placeholder without a parent. The caller or the layout that
    // receives the widget is responsible for transferring ownership into Qt's
    // normal parent-child object tree.
    QWidget* placeholder = new QWidget();

    // Let the placeholder fill whatever dock/page area requested it, while the
    // border makes unfinished panels visible during development and testing.
    placeholder->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Expanding);
    placeholder->setStyleSheet(
        QStringLiteral(
            "border: 2px solid %1; "
            "background-color: transparent; "
            "border-radius: 0px;")
            .arg(KswordTheme::InfoColor().name(QColor::HexRgb)));

    // The label carries the caller-provided hint text and stays centered so the
    // placeholder remains useful even when the containing panel is resized.
    QLabel* tipLabel = new QLabel(tipText, placeholder);
    tipLabel->setStyleSheet(
        QStringLiteral("color:%1; font-size:14px;")
            .arg(KswordTheme::InfoColor().name(QColor::HexRgb)));
    tipLabel->setAlignment(Qt::AlignCenter);

    // A zero-margin vertical layout keeps the label centered in the full widget
    // rectangle and returns the finished placeholder to the caller.
    QVBoxLayout* layout = new QVBoxLayout(placeholder);
    layout->addWidget(tipLabel);
    layout->setContentsMargins(0, 0, 0, 0);

    return placeholder;
}

void ks::ui::applyResponsiveWindowGeometry(
    QWidget* window,
    QWidget* candidateParent,
    const QSize& preferredSize,
    const QSize& minimumSize,
    const double maxAvailableRatio)
{
    if (window == nullptr)
    {
        return;
    }

    const auto screenForWidget = [](QWidget* widget) -> QScreen*
    {
        if (widget == nullptr)
        {
            return nullptr;
        }
        if (QWindow* handle = widget->windowHandle(); handle != nullptr && handle->screen() != nullptr)
        {
            return handle->screen();
        }
        if (QWidget* topLevel = widget->window(); topLevel != nullptr && topLevel != widget)
        {
            if (QWindow* handle = topLevel->windowHandle(); handle != nullptr && handle->screen() != nullptr)
            {
                return handle->screen();
            }
        }
        if (widget->isVisible())
        {
            return QGuiApplication::screenAt(widget->mapToGlobal(widget->rect().center()));
        }
        return nullptr;
    };

    QScreen* targetScreen = screenForWidget(candidateParent);
    if (targetScreen == nullptr)
    {
        targetScreen = screenForWidget(window);
    }
    if (targetScreen == nullptr)
    {
        targetScreen = screenForWidget(QApplication::activeWindow());
    }
    if (targetScreen == nullptr)
    {
        targetScreen = QApplication::primaryScreen();
    }

    const QSize normalizedPreferred(
        std::max(1, preferredSize.width()),
        std::max(1, preferredSize.height()));
    const QSize normalizedMinimum(
        std::max(1, minimumSize.width()),
        std::max(1, minimumSize.height()));
    const double boundedRatio = maxAvailableRatio > 0.0
        ? std::min(1.0, maxAvailableRatio)
        : 0.9;
    QSize availableSize = targetScreen != nullptr
        ? targetScreen->availableGeometry().size()
        : normalizedPreferred.expandedTo(normalizedMinimum);
    if (availableSize.width() <= 0 || availableSize.height() <= 0)
    {
        availableSize = normalizedPreferred.expandedTo(normalizedMinimum);
    }

    const QSize maximumInitialSize(
        std::max(1, static_cast<int>(std::floor(availableSize.width() * boundedRatio))),
        std::max(1, static_cast<int>(std::floor(availableSize.height() * boundedRatio))));
    const QSize effectiveMinimumSize(
        std::min(normalizedMinimum.width(), maximumInitialSize.width()),
        std::min(normalizedMinimum.height(), maximumInitialSize.height()));
    const QSize effectiveInitialSize(
        std::clamp(
            normalizedPreferred.width(),
            effectiveMinimumSize.width(),
            maximumInitialSize.width()),
        std::clamp(
            normalizedPreferred.height(),
            effectiveMinimumSize.height(),
            maximumInitialSize.height()));

    window->setMinimumSize(effectiveMinimumSize);
    window->resize(effectiveInitialSize);
}

void ks::ui::scheduleDeferredTabActivation(
    QObject* context,
    QTabWidget* tabWidget,
    const int tabIndex,
    QWidget* placeholderPage,
    DeferredTabActivationCallback callback)
{
    if (context == nullptr || tabWidget == nullptr || placeholderPage == nullptr || !callback)
    {
        return;
    }

    const QPointer<QObject> contextGuard(context);
    const QPointer<QTabWidget> tabGuard(tabWidget);
    const QPointer<QWidget> placeholderGuard(placeholderPage);
    QTimer::singleShot(
        0,
        context,
        [contextGuard, tabGuard, placeholderGuard, tabIndex, callback = std::move(callback)]()
        {
            if (contextGuard.isNull() || tabGuard.isNull() || placeholderGuard.isNull() ||
                tabGuard->currentIndex() != tabIndex ||
                tabGuard->widget(tabIndex) != placeholderGuard.data())
            {
                return;
            }
            callback();
        });
}
