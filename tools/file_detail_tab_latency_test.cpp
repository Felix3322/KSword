// Regression harness for file-property left-navigation Tab latency.
//
// The navigation click changes QTabWidget::currentIndex synchronously. The
// expensive page builder must run on the next event-loop turn so the right
// side can paint the selected placeholder before the real page is constructed.

#include "../Ksword5.1/Ksword5.1/UI/UI_All.h"

#include <QApplication>
#include <QCoreApplication>
#include <QEventLoop>

#include <iostream>

int main(int argc, char* argv[])
{
    QApplication application(argc, argv);

    QTabWidget tabWidget;
    auto* placeholderPage = new QWidget(&tabWidget);
    tabWidget.addTab(placeholderPage, QStringLiteral("deferred"));
    auto* otherPage = new QWidget(&tabWidget);
    tabWidget.addTab(otherPage, QStringLiteral("other"));

    bool callbackCalled = false;
    ks::ui::scheduleDeferredTabActivation(
        &tabWidget,
        &tabWidget,
        0,
        placeholderPage,
        [&callbackCalled]()
        {
            callbackCalled = true;
        });

    // A rapid second click must cancel construction for the tab that is no
    // longer current; otherwise a heavy page can still block the next switch.
    tabWidget.setCurrentIndex(1);
    QCoreApplication::processEvents(QEventLoop::AllEvents);
    if (callbackCalled)
    {
        std::cout << "STALE_CALLBACK_AFTER_SWITCH=1\n";
        return 3;
    }
    std::cout << "STALE_CALLBACK_AFTER_SWITCH=0\n";

    tabWidget.setCurrentIndex(0);
    ks::ui::scheduleDeferredTabActivation(
        &tabWidget,
        &tabWidget,
        0,
        placeholderPage,
        [&callbackCalled]()
        {
            callbackCalled = true;
        });

    std::cout << "CALLBACK_BEFORE_EVENT_LOOP=" << (callbackCalled ? 1 : 0) << '\n';
    if (callbackCalled)
    {
        return 1;
    }

    QCoreApplication::processEvents(QEventLoop::AllEvents);
    std::cout << "CALLBACK_AFTER_EVENT_LOOP=" << (callbackCalled ? 1 : 0) << '\n';
    return callbackCalled ? 0 : 2;
}
