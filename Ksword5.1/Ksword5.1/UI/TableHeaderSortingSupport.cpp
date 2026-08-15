#include "TableHeaderSortingSupport.h"

#include <QAbstractItemModel>
#include <QHeaderView>
#include <QList>
#include <QModelIndex>
#include <QPointer>
#include <QTableWidget>
#include <QVariant>

namespace
{
    // 下列动态属性只保存通用表头排序的安装状态和最近一次手动排序状态。
    // 属性挂在表格对象上，避免额外控制器与表格生命周期不同步。
    constexpr char kHeaderSortingInstalledProperty[] =
        "KSWORD_TABLE_HEADER_SORTING_INSTALLED";
    constexpr char kHeaderSortingDisabledProperty[] =
        "KSWORD_TABLE_HEADER_SORTING_DISABLED";
    constexpr char kManualSortActiveProperty[] =
        "KSWORD_TABLE_HEADER_MANUAL_SORT_ACTIVE";
    constexpr char kManualSortColumnProperty[] =
        "KSWORD_TABLE_HEADER_MANUAL_SORT_COLUMN";
    constexpr char kManualSortOrderProperty[] =
        "KSWORD_TABLE_HEADER_MANUAL_SORT_ORDER";

    // clearManualSortState 作用：
    // - 清除通用排序记录，并按需隐藏只属于通用排序的表头箭头；
    // - 原生 sortingEnabled 为 true 时由调用方跳过本函数，避免隐藏 Qt 自己的箭头。
    // 传入 tableWidget：目标表格；hideIndicator：是否隐藏排序指示器；传出：无。
    void clearManualSortState(
        QTableWidget* tableWidget,
        const bool hideIndicator)
    {
        if (tableWidget == nullptr)
        {
            return;
        }

        tableWidget->setProperty(kManualSortActiveProperty, false);
        tableWidget->setProperty(kManualSortColumnProperty, -1);
        tableWidget->setProperty(
            kManualSortOrderProperty,
            static_cast<int>(Qt::AscendingOrder));

        QHeaderView* const headerView = tableWidget->horizontalHeader();
        if (hideIndicator && headerView != nullptr)
        {
            headerView->setSortIndicatorShown(false);
        }
    }

    // invalidateManualSortAfterDataChange 作用：
    // - 数据源发生增删、重置或改单元格后撤销手动排序标记；
    // - 不自动重排新数据，避免异步分批填表期间搬动尚未填完整的行；
    // - 用户再次点击表头即可按新快照排序。
    void invalidateManualSortAfterDataChange(
        const QPointer<QTableWidget>& guardedTable)
    {
        if (guardedTable.isNull() || guardedTable->isSortingEnabled())
        {
            return;
        }
        if (!guardedTable->property(kManualSortActiveProperty).toBool())
        {
            return;
        }

        clearManualSortState(guardedTable.data(), true);
    }

    // nextSortOrder 作用：
    // - 新列第一次点击使用升序；连续点击同一列时在升序和降序之间切换；
    // - 最近列与顺序由表格动态属性读取，不依赖 QHeaderView 未显示时的默认值。
    // 传入 tableWidget：目标表格；logicalColumn：本次点击列；返回本次排序方向。
    Qt::SortOrder nextSortOrder(
        const QTableWidget* tableWidget,
        const int logicalColumn)
    {
        const bool manualSortActive =
            tableWidget->property(kManualSortActiveProperty).toBool();
        const int previousColumn =
            tableWidget->property(kManualSortColumnProperty).toInt();
        if (!manualSortActive || previousColumn != logicalColumn)
        {
            return Qt::AscendingOrder;
        }

        const auto previousOrder = static_cast<Qt::SortOrder>(
            tableWidget->property(kManualSortOrderProperty).toInt());
        return previousOrder == Qt::AscendingOrder
            ? Qt::DescendingOrder
            : Qt::AscendingOrder;
    }

    // sortByClickedHeader 作用：
    // - 响应一次水平表头点击并排序 QTableWidget 的完整内部模型；
    // - 原生持续排序开启或业务禁用通用排序时不介入；
    // - 返回：无，排序结果直接体现在目标表格。
    void sortByClickedHeader(
        QTableWidget* tableWidget,
        const int logicalColumn)
    {
        if (tableWidget == nullptr ||
            tableWidget->property(kHeaderSortingDisabledProperty).toBool() ||
            logicalColumn < 0 ||
            logicalColumn >= tableWidget->columnCount())
        {
            return;
        }

        // Qt 原生排序已经连接表头信号，此处只清理旧的手动状态，避免执行两次排序。
        if (tableWidget->isSortingEnabled())
        {
            tableWidget->setProperty(kManualSortActiveProperty, false);
            return;
        }

        const Qt::SortOrder sortOrder = nextSortOrder(tableWidget, logicalColumn);
        tableWidget->setProperty(kManualSortActiveProperty, true);
        tableWidget->setProperty(kManualSortColumnProperty, logicalColumn);
        tableWidget->setProperty(kManualSortOrderProperty, static_cast<int>(sortOrder));

        tableWidget->sortItems(logicalColumn, sortOrder);
        QHeaderView* const headerView = tableWidget->horizontalHeader();
        if (headerView != nullptr)
        {
            headerView->setSortIndicator(logicalColumn, sortOrder);
            headerView->setSortIndicatorShown(true);
        }
    }
}

namespace ks::ui
{
    void InstallTableHeaderClickSorting(QTableWidget* tableWidget)
    {
        if (tableWidget == nullptr ||
            tableWidget->model() == nullptr ||
            tableWidget->property(kHeaderSortingInstalledProperty).toBool())
        {
            return;
        }

        QHeaderView* const headerView = tableWidget->horizontalHeader();
        if (headerView == nullptr)
        {
            return;
        }

        tableWidget->setProperty(kHeaderSortingInstalledProperty, true);
        headerView->setSectionsClickable(true);
        const QPointer<QTableWidget> guardedTable(tableWidget);

        QObject::connect(
            headerView,
            &QHeaderView::sectionClicked,
            tableWidget,
            [guardedTable](const int logicalColumn)
            {
                sortByClickedHeader(guardedTable.data(), logicalColumn);
            });

        // 内部 QTableWidget model 与表格同寿命。任何数据变化都只撤销旧箭头，
        // 不在填充信号中重排，兼容同步和定时器分批刷新两种页面。
        QAbstractItemModel* const tableModel = tableWidget->model();
        QObject::connect(
            tableModel,
            &QAbstractItemModel::modelReset,
            tableWidget,
            [guardedTable]()
            {
                invalidateManualSortAfterDataChange(guardedTable);
            });
        QObject::connect(
            tableModel,
            &QAbstractItemModel::rowsInserted,
            tableWidget,
            [guardedTable](const QModelIndex&, const int, const int)
            {
                invalidateManualSortAfterDataChange(guardedTable);
            });
        QObject::connect(
            tableModel,
            &QAbstractItemModel::rowsRemoved,
            tableWidget,
            [guardedTable](const QModelIndex&, const int, const int)
            {
                invalidateManualSortAfterDataChange(guardedTable);
            });
        QObject::connect(
            tableModel,
            &QAbstractItemModel::dataChanged,
            tableWidget,
            [guardedTable](const QModelIndex&, const QModelIndex&, const QList<int>&)
            {
                invalidateManualSortAfterDataChange(guardedTable);
            });
    }

    void SetTableHeaderClickSortingEnabled(
        QTableWidget* tableWidget,
        const bool enabled)
    {
        if (tableWidget == nullptr)
        {
            return;
        }

        tableWidget->setProperty(kHeaderSortingDisabledProperty, !enabled);
        if (!enabled && !tableWidget->isSortingEnabled())
        {
            clearManualSortState(tableWidget, true);
        }
    }
}
