#include "UI_All.h"
#include "../theme.h"

#include <QLabel>
#include <QPointer>
#include <QTimer>
#include <QVBoxLayout>
#include <QWidget>

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
