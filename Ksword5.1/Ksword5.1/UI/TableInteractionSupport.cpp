#include "TableInteractionSupport.h"

#include "../Internationalization/LanguageManager.h"

#include <QApplication>
#include <QAbstractItemModel>
#include <QClipboard>
#include <QContextMenuEvent>
#include <QDateTime>
#include <QEvent>
#include <QFileDialog>
#include <QFileInfo>
#include <QHeaderView>
#include <QIcon>
#include <QItemSelectionModel>
#include <QKeyEvent>
#include <QKeySequence>
#include <QMenu>
#include <QMessageBox>
#include <QModelIndex>
#include <QPointer>
#include <QSaveFile>
#include <QStringConverter>
#include <QSize>
#include <QTableView>
#include <QTextStream>
#include <QToolButton>
#include <QVariant>
#include <QWidget>

#include <algorithm>

namespace
{
    constexpr char kInstalledProperty[] = "KSWORD_TABLE_INTERACTION_SUPPORT_INSTALLED";
    constexpr char kExportButtonProperty[] = "KSWORD_TABLE_INTERACTION_EXPORT_BUTTON";
    constexpr char kStandardContextMenuProperty[] = "KSWORD_TABLE_INTERACTION_STANDARD_CONTEXT_MENU";
    constexpr char kContextActionsInstalledProperty[] = "KSWORD_TABLE_INTERACTION_CONTEXT_ACTIONS_INSTALLED";
    constexpr int kExportButtonSize = 26;

    QString localizedSourceText(const char* sourceText)
    {
        return ks::i18n::sourceText(QString::fromUtf8(sourceText));
    }

    QTableView* tableForEventObject(QObject* watchedObject)
    {
        if (QTableView* tableView = qobject_cast<QTableView*>(watchedObject))
        {
            return tableView;
        }

        QTableView* tableView = qobject_cast<QTableView*>(watchedObject != nullptr
            ? watchedObject->parent()
            : nullptr);
        if (tableView != nullptr && watchedObject == tableView->viewport())
        {
            return tableView;
        }
        return nullptr;
    }

    QString normalizedTsvField(const QVariant& value)
    {
        QString text = value.toString();
        text.replace(QLatin1Char('\t'), QLatin1Char(' '));
        text.replace(QLatin1Char('\r'), QLatin1Char(' '));
        text.replace(QLatin1Char('\n'), QLatin1Char(' '));
        return text;
    }

    QVector<int> selectedVisibleRows(QTableView* tableView, const bool includeCurrentFallback)
    {
        QVector<int> rowList;
        if (tableView == nullptr || tableView->model() == nullptr || tableView->selectionModel() == nullptr)
        {
            return rowList;
        }

        const QModelIndexList selectedIndexList = tableView->selectionModel()->selectedIndexes();
        rowList.reserve(selectedIndexList.size());
        for (const QModelIndex& index : selectedIndexList)
        {
            if (index.isValid() && !tableView->isRowHidden(index.row()))
            {
                rowList.push_back(index.row());
            }
        }

        std::sort(rowList.begin(), rowList.end());
        rowList.erase(std::unique(rowList.begin(), rowList.end()), rowList.end());

        if (rowList.isEmpty() && includeCurrentFallback)
        {
            const QModelIndex currentIndex = tableView->currentIndex();
            if (currentIndex.isValid() && !tableView->isRowHidden(currentIndex.row()))
            {
                rowList.push_back(currentIndex.row());
            }
        }
        return rowList;
    }

    QVector<int> exportRows(QTableView* tableView)
    {
        QVector<int> rowList = selectedVisibleRows(tableView, false);
        if (tableView == nullptr || tableView->model() == nullptr || !rowList.isEmpty())
        {
            return rowList;
        }

        const int rowCount = tableView->model()->rowCount();
        rowList.reserve(rowCount);
        for (int row = 0; row < rowCount; ++row)
        {
            if (!tableView->isRowHidden(row))
            {
                rowList.push_back(row);
            }
        }
        return rowList;
    }

    QVector<int> visibleColumns(const QTableView* tableView)
    {
        QVector<int> columnList;
        if (tableView == nullptr || tableView->model() == nullptr)
        {
            return columnList;
        }

        const int columnCount = tableView->model()->columnCount();
        columnList.reserve(columnCount);
        for (int column = 0; column < columnCount; ++column)
        {
            if (!tableView->isColumnHidden(column))
            {
                columnList.push_back(column);
            }
        }
        return columnList;
    }

    QString tableRowsToTsv(
        QTableView* tableView,
        const QVector<int>& rowList,
        const bool includeHeader)
    {
        if (tableView == nullptr || tableView->model() == nullptr)
        {
            return {};
        }

        QAbstractItemModel* modelObject = tableView->model();
        const QVector<int> columnList = visibleColumns(tableView);
        if (rowList.isEmpty() || columnList.isEmpty())
        {
            return {};
        }

        QStringList lineList;
        lineList.reserve(rowList.size() + (includeHeader ? 1 : 0));
        if (includeHeader)
        {
            QStringList headerList;
            headerList.reserve(columnList.size());
            for (const int column : columnList)
            {
                headerList.push_back(normalizedTsvField(
                    modelObject->headerData(column, Qt::Horizontal, Qt::DisplayRole)));
            }
            lineList.push_back(headerList.join(QLatin1Char('\t')));
        }

        for (const int row : rowList)
        {
            if (row < 0 || row >= modelObject->rowCount() || tableView->isRowHidden(row))
            {
                continue;
            }

            QStringList valueList;
            valueList.reserve(columnList.size());
            for (const int column : columnList)
            {
                valueList.push_back(normalizedTsvField(
                    modelObject->data(modelObject->index(row, column), Qt::DisplayRole)));
            }
            lineList.push_back(valueList.join(QLatin1Char('\t')));
        }

        return lineList.join(QLatin1Char('\n'));
    }

    void copySelectedRowsToClipboard(QTableView* tableView)
    {
        if (QClipboard* clipboardObject = QApplication::clipboard())
        {
            const QString text = tableRowsToTsv(
                tableView,
                selectedVisibleRows(tableView, true),
                false);
            if (!text.isEmpty())
            {
                clipboardObject->setText(text);
            }
        }
    }

    void exportTableToTsv(QTableView* tableView)
    {
        const QVector<int> rowList = exportRows(tableView);
        const QString tableText = tableRowsToTsv(tableView, rowList, true);
        if (tableText.isEmpty())
        {
            QMessageBox::information(
                tableView,
                localizedSourceText("导出 TSV"),
                localizedSourceText("没有可导出的行。"));
            return;
        }

        QString outputPath = QFileDialog::getSaveFileName(
            tableView,
            localizedSourceText("导出 TSV"),
            QStringLiteral("table_export_")
                + QDateTime::currentDateTime().toString(QStringLiteral("yyyyMMdd_HHmmss"))
                + QStringLiteral(".tsv"),
            localizedSourceText("TSV 文件 (*.tsv)"));
        if (outputPath.trimmed().isEmpty())
        {
            return;
        }
        if (QFileInfo(outputPath).suffix().isEmpty())
        {
            outputPath += QStringLiteral(".tsv");
        }

        QSaveFile fileObject(outputPath);
        if (!fileObject.open(QIODevice::WriteOnly | QIODevice::Text))
        {
            QMessageBox::warning(
                tableView,
                localizedSourceText("导出 TSV"),
                localizedSourceText("导出失败：%1").arg(fileObject.errorString()));
            return;
        }

        QTextStream outputStream(&fileObject);
        outputStream.setEncoding(QStringConverter::Utf8);
        outputStream << tableText << Qt::endl;
        if (outputStream.status() != QTextStream::Ok || !fileObject.commit())
        {
            QMessageBox::warning(
                tableView,
                localizedSourceText("导出 TSV"),
                localizedSourceText("导出失败：%1").arg(fileObject.errorString()));
        }
    }

    void positionExportButton(QTableView* tableView)
    {
        if (tableView == nullptr || tableView->horizontalHeader() == nullptr)
        {
            return;
        }

        QHeaderView* horizontalHeader = tableView->horizontalHeader();
        QToolButton* exportButton = horizontalHeader->findChild<QToolButton*>(
            QString::fromLatin1(kExportButtonProperty),
            Qt::FindDirectChildrenOnly);
        if (exportButton == nullptr)
        {
            return;
        }

        const int x = std::max(0, horizontalHeader->width() - exportButton->width() - 2);
        const int y = std::max(0, (horizontalHeader->height() - exportButton->height()) / 2);
        exportButton->move(x, y);
        exportButton->raise();
    }

    void installExportButton(QTableView* tableView)
    {
        if (tableView == nullptr || tableView->horizontalHeader() == nullptr ||
            tableView->horizontalHeader()->findChild<QToolButton*>(
                QString::fromLatin1(kExportButtonProperty),
                Qt::FindDirectChildrenOnly) != nullptr)
        {
            return;
        }

        auto* exportButton = new QToolButton(tableView->horizontalHeader());
        exportButton->setObjectName(QString::fromLatin1(kExportButtonProperty));
        exportButton->setIcon(QIcon(QStringLiteral(":/Icon/log_export.svg")));
        exportButton->setIconSize(QSize(18, 18));
        exportButton->setFixedSize(kExportButtonSize, kExportButtonSize);
        exportButton->setAutoRaise(true);
        exportButton->setToolButtonStyle(Qt::ToolButtonIconOnly);
        exportButton->setToolTip(localizedSourceText("导出 TSV"));
        exportButton->setAccessibleName(localizedSourceText("导出 TSV"));
        QObject::connect(exportButton, &QToolButton::clicked, tableView, [tableView]()
            {
                exportTableToTsv(tableView);
            });
        positionExportButton(tableView);
    }

    void showMultiSelectionContextMenu(QTableView* tableView, const QPoint& globalPosition)
    {
        if (tableView == nullptr)
        {
            return;
        }

        QMenu menu(tableView);
        menu.setProperty(kStandardContextMenuProperty, true);
        QAction* copyAction = menu.addAction(
            QIcon(QStringLiteral(":/Icon/log_copy.svg")),
            localizedSourceText("复制选中行（TSV）"));
        QAction* exportAction = menu.addAction(
            QIcon(QStringLiteral(":/Icon/log_export.svg")),
            localizedSourceText("导出 TSV"));

        const bool hasSelectedRows = !selectedVisibleRows(tableView, true).isEmpty();
        copyAction->setEnabled(hasSelectedRows);
        exportAction->setEnabled(!exportRows(tableView).isEmpty());

        QAction* selectedAction = menu.exec(globalPosition);
        if (selectedAction == copyAction)
        {
            copySelectedRowsToClipboard(tableView);
        }
        else if (selectedAction == exportAction)
        {
            exportTableToTsv(tableView);
        }
    }

    void appendTableContextActions(QMenu* menu)
    {
        if (menu == nullptr ||
            menu->property(kStandardContextMenuProperty).toBool() ||
            menu->property(kContextActionsInstalledProperty).toBool())
        {
            return;
        }

        QTableView* tableView = qobject_cast<QTableView*>(menu->parent());
        if (tableView == nullptr)
        {
            return;
        }

        menu->setProperty(kContextActionsInstalledProperty, true);
        menu->addSeparator();
        QAction* copyAction = menu->addAction(
            QIcon(QStringLiteral(":/Icon/log_copy.svg")),
            localizedSourceText("复制选中行（TSV）"));
        QAction* exportAction = menu->addAction(
            QIcon(QStringLiteral(":/Icon/log_export.svg")),
            localizedSourceText("导出 TSV"));

        const QPointer<QTableView> guardedTable(tableView);
        copyAction->setEnabled(!selectedVisibleRows(tableView, true).isEmpty());
        exportAction->setEnabled(!exportRows(tableView).isEmpty());
        QObject::connect(copyAction, &QAction::triggered, menu, [guardedTable]()
            {
                if (!guardedTable.isNull())
                {
                    copySelectedRowsToClipboard(guardedTable.data());
                }
            });
        QObject::connect(exportAction, &QAction::triggered, menu, [guardedTable]()
            {
                if (!guardedTable.isNull())
                {
                    exportTableToTsv(guardedTable.data());
                }
            });
    }

    void selectContextRow(QTableView* tableView, const QModelIndex& clickedIndex)
    {
        if (tableView == nullptr || !clickedIndex.isValid() || tableView->selectionModel() == nullptr)
        {
            return;
        }

        const QVector<int> selectedRowList = selectedVisibleRows(tableView, false);
        if (std::find(selectedRowList.cbegin(), selectedRowList.cend(), clickedIndex.row()) != selectedRowList.cend())
        {
            tableView->selectionModel()->setCurrentIndex(clickedIndex, QItemSelectionModel::NoUpdate);
            return;
        }

        tableView->selectionModel()->setCurrentIndex(
            clickedIndex,
            QItemSelectionModel::ClearAndSelect | QItemSelectionModel::Rows);
    }

    void installDefaultContextMenu(QTableView* tableView)
    {
        if (tableView == nullptr || tableView->contextMenuPolicy() != Qt::DefaultContextMenu)
        {
            return;
        }

        tableView->setContextMenuPolicy(Qt::CustomContextMenu);
        QObject::connect(
            tableView,
            &QTableView::customContextMenuRequested,
            tableView,
            [tableView](const QPoint& localPosition)
            {
                const QModelIndex clickedIndex = tableView->indexAt(localPosition);
                selectContextRow(tableView, clickedIndex);
                showMultiSelectionContextMenu(
                    tableView,
                    tableView->viewport()->mapToGlobal(localPosition));
            });
    }

    void configureTable(QTableView* tableView)
    {
        if (tableView == nullptr || tableView->model() == nullptr)
        {
            return;
        }

        tableView->setSelectionMode(QAbstractItemView::ExtendedSelection);
        installExportButton(tableView);
        installDefaultContextMenu(tableView);
        positionExportButton(tableView);
    }

    class GlobalTableInteractionSupportFilter final : public QObject
    {
    public:
        explicit GlobalTableInteractionSupportFilter(QObject* parentObject)
            : QObject(parentObject)
        {
        }

    protected:
        bool eventFilter(QObject* watchedObject, QEvent* eventObject) override
        {
            if (eventObject == nullptr)
            {
                return QObject::eventFilter(watchedObject, eventObject);
            }

            if (eventObject->type() == QEvent::Show)
            {
                appendTableContextActions(qobject_cast<QMenu*>(watchedObject));
            }

            QTableView* tableView = tableForEventObject(watchedObject);
            if (tableView == nullptr)
            {
                return QObject::eventFilter(watchedObject, eventObject);
            }

            const QEvent::Type eventType = eventObject->type();
            if (eventType == QEvent::Show ||
                eventType == QEvent::Polish ||
                eventType == QEvent::LayoutRequest ||
                eventType == QEvent::StyleChange)
            {
                configureTable(tableView);
            }
            else if (eventType == QEvent::Resize)
            {
                positionExportButton(tableView);
            }
            else if (eventType == QEvent::KeyPress)
            {
                auto* keyEvent = static_cast<QKeyEvent*>(eventObject);
                if (keyEvent->matches(QKeySequence::Copy))
                {
                    copySelectedRowsToClipboard(tableView);
                    keyEvent->accept();
                    return true;
                }
            }
            else if (eventType == QEvent::ContextMenu)
            {
                auto* contextMenuEvent = static_cast<QContextMenuEvent*>(eventObject);
                const QPoint viewportPosition = watchedObject == tableView
                    ? tableView->viewport()->mapFrom(tableView, contextMenuEvent->pos())
                    : contextMenuEvent->pos();
                const QModelIndex clickedIndex = tableView->indexAt(viewportPosition);
                selectContextRow(tableView, clickedIndex);
                if (selectedVisibleRows(tableView, false).size() > 1)
                {
                    showMultiSelectionContextMenu(tableView, contextMenuEvent->globalPos());
                    contextMenuEvent->accept();
                    return true;
                }
            }

            return QObject::eventFilter(watchedObject, eventObject);
        }
    };
}

namespace ks::ui
{
    void InstallGlobalTableInteractionSupport(QApplication* appInstance)
    {
        if (appInstance == nullptr || appInstance->property(kInstalledProperty).toBool())
        {
            return;
        }

        auto* filter = new GlobalTableInteractionSupportFilter(appInstance);
        appInstance->installEventFilter(filter);
        appInstance->setProperty(kInstalledProperty, true);

        for (QWidget* widget : appInstance->allWidgets())
        {
            configureTable(qobject_cast<QTableView*>(widget));
        }
    }
}
