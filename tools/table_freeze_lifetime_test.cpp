// Deterministic lifetime regression harness for TableFrozenPaneController.
//
// The production action bar owns the controller while the target table owns
// the action bar. Destroying the table therefore exercises the same QObject
// child-destruction order used when a file-properties window is closed.

#include "../Ksword5.1/Ksword5.1/UI/TableFreezeSupport.h"
#include "../Ksword5.1/Ksword5.1/UI/VisibleTableWidget.h"

#include <QApplication>
#include <QFrame>
#include <QTableWidgetItem>

int main(int argc, char* argv[])
{
    QApplication application(argc, argv);

    for (int iteration = 0; iteration < 100; ++iteration)
    {
        auto* table = new ks::ui::VisibleTableWidget();
        table->setColumnCount(2);
        table->setRowCount(2);
        table->setItem(0, 0, new QTableWidgetItem(QStringLiteral("holder")));

        // Match TableActionBar's ownership: table -> action bar -> controller.
        auto* actionBar = new QFrame(table);
        auto* controller = new ks::ui::TableFrozenPaneController(actionBar);
        controller->setTargetTable(table);

        delete table;
        QCoreApplication::sendPostedEvents(nullptr, QEvent::DeferredDelete);
    }

    return 0;
}
