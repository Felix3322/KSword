#include "TableFreezeSupport.h"

#include "VisibleTableWidget.h"

#include <QAbstractItemDelegate>
#include <QAbstractItemView>
#include <QCoreApplication>
#include <QEvent>
#include <QHeaderView>
#include <QItemSelectionModel>
#include <QMouseEvent>
#include <QPalette>
#include <QScrollBar>
#include <QSize>
#include <QTableView>
#include <QTimer>
#include <QVariant>
#include <QWheelEvent>

#include <algorithm>
#include <utility>

namespace
{
    constexpr char kFrozenPaneAuxiliaryProperty[] =
        "KSWORD_TABLE_INTERACTION_FROZEN_PANE_AUXILIARY";
    constexpr char kFrozenPaneSourceProperty[] =
        "KSWORD_TABLE_INTERACTION_FROZEN_PANE_SOURCE";

    // 冻结区最多吃掉可用尺寸的一半。没有这条上限，对着靠下的行执行冻结就会把整屏钉死，
    // 滚动区高度归零，表格看上去彻底不动了。
    constexpr int kFrozenBandBudgetDivisor = 2;

    // 主表滚动位置随可视行高刷新而抖动时，多镜像几行以免冻结列窗格底部露白。
    constexpr int kMirrorRowMargin = 3;

    // FrozenPaneTableView 作用：
    // - 冻结窗格用的只读附属视图，与主表共享模型与选择模型；
    // - 自身不接受滚轮与滚动，一切滚动交还主表，再由控制器把窗格对齐回去。
    class FrozenPaneTableView final : public QTableView
    {
    public:
        explicit FrozenPaneTableView(QTableView* sourceTable, QWidget* parent)
            : QTableView(parent)
            , m_sourceTable(sourceTable)
        {
        }

    protected:
        void wheelEvent(QWheelEvent* eventObject) override
        {
            if (eventObject == nullptr || m_sourceTable.isNull() ||
                m_sourceTable->viewport() == nullptr)
            {
                QTableView::wheelEvent(eventObject);
                return;
            }

            // 冻结区域自身不滚动；把滚轮输入交还主表，随后由控制器同步窗格。
            QCoreApplication::sendEvent(m_sourceTable->viewport(), eventObject);
        }

        void mousePressEvent(QMouseEvent* eventObject) override
        {
            const QPoint restorePoint = sourceScrollPoint();
            QTableView::mousePressEvent(eventObject);
            restoreSourceScroll(restorePoint);
        }

        void mouseDoubleClickEvent(QMouseEvent* eventObject) override
        {
            const QPoint restorePoint = sourceScrollPoint();
            QTableView::mouseDoubleClickEvent(eventObject);
            restoreSourceScroll(restorePoint);
        }

    private:
        // sourceScrollPoint / restoreSourceScroll 作用：
        // - 冻结区与主表共用选择模型，点中的行往往并不在主表可视区内；
        // - QAbstractItemView 在 currentChanged 里会 scrollTo(current)，不还原就会整表乱跳。
        QPoint sourceScrollPoint() const
        {
            if (m_sourceTable.isNull())
            {
                return QPoint(-1, -1);
            }
            return QPoint(
                m_sourceTable->horizontalScrollBar()->value(),
                m_sourceTable->verticalScrollBar()->value());
        }

        void restoreSourceScroll(const QPoint& restorePoint)
        {
            if (m_sourceTable.isNull() || restorePoint.x() < 0)
            {
                return;
            }
            if (m_sourceTable->horizontalScrollBar()->value() != restorePoint.x())
            {
                m_sourceTable->horizontalScrollBar()->setValue(restorePoint.x());
            }
            if (m_sourceTable->verticalScrollBar()->value() != restorePoint.y())
            {
                m_sourceTable->verticalScrollBar()->setValue(restorePoint.y());
            }
        }

        QPointer<QTableView> m_sourceTable;
    };

    int headerBandHeight(const QTableView* tableView)
    {
        const QHeaderView* header = tableView != nullptr ? tableView->horizontalHeader() : nullptr;
        return header != nullptr && !header->isHidden() ? header->height() : 0;
    }

    int headerBandWidth(const QTableView* tableView)
    {
        const QHeaderView* header = tableView != nullptr ? tableView->verticalHeader() : nullptr;
        return header != nullptr && !header->isHidden() ? header->width() : 0;
    }

    // setPaneScrollValue 作用：
    // - 窗格滚动条完全由控制器驱动，QTableView 自己算出的范围可能不覆盖目标偏移；
    // - 直接扩展范围后再赋值，避免被 clamp 成错位的一格。
    void setPaneScrollValue(QScrollBar* scrollBar, const int value)
    {
        if (scrollBar == nullptr)
        {
            return;
        }
        if (scrollBar->minimum() > value)
        {
            scrollBar->setMinimum(value);
        }
        if (scrollBar->maximum() < value)
        {
            scrollBar->setMaximum(value);
        }
        if (scrollBar->value() != value)
        {
            scrollBar->setValue(value);
        }
    }
}

namespace ks::ui
{
    TablePausedSnapshotModel::TablePausedSnapshotModel(
        TableSnapshot snapshot,
        QObject* parent)
        : QAbstractTableModel(parent)
        , m_snapshot(std::move(snapshot))
    {
    }

    const TableSnapshot& TablePausedSnapshotModel::snapshot() const
    {
        return m_snapshot;
    }

    int TablePausedSnapshotModel::rowCount(const QModelIndex& parent) const
    {
        return parent.isValid() ? 0 : m_snapshot.rows.size();
    }

    int TablePausedSnapshotModel::columnCount(const QModelIndex& parent) const
    {
        return parent.isValid() ? 0 : m_snapshot.visibleColumns.size();
    }

    QVariant TablePausedSnapshotModel::data(const QModelIndex& index, const int role) const
    {
        if (!index.isValid() ||
            index.row() < 0 ||
            index.row() >= m_snapshot.rows.size() ||
            index.column() < 0 ||
            index.column() >= m_snapshot.visibleColumns.size())
        {
            return QVariant();
        }

        const TableSnapshotRow& row = m_snapshot.rows.at(index.row());
        if (index.column() >= row.values.size())
        {
            return QVariant();
        }
        if (role == Qt::DisplayRole || role == Qt::EditRole || role == Qt::ToolTipRole)
        {
            return row.values.at(index.column());
        }
        return QVariant();
    }

    QVariant TablePausedSnapshotModel::headerData(
        const int section,
        const Qt::Orientation orientation,
        const int role) const
    {
        if (role != Qt::DisplayRole || section < 0)
        {
            return QVariant();
        }
        if (orientation == Qt::Horizontal)
        {
            return section < m_snapshot.visibleColumns.size()
                ? m_snapshot.visibleColumns.at(section).headerText
                : QVariant();
        }
        if (section >= m_snapshot.rows.size())
        {
            return QVariant();
        }
        const int sourceRow = m_snapshot.rows.at(section).sourceRow;
        return sourceRow >= 0 ? QVariant(sourceRow + 1) : QVariant(section + 1);
    }

    Qt::ItemFlags TablePausedSnapshotModel::flags(const QModelIndex& index) const
    {
        return index.isValid()
            ? Qt::ItemIsEnabled | Qt::ItemIsSelectable
            : Qt::NoItemFlags;
    }

    TableFrozenPaneController::TableFrozenPaneController(QObject* parent)
        : QObject(parent)
    {
    }

    TableFrozenPaneController::~TableFrozenPaneController()
    {
        releaseTarget();
    }

    void TableFrozenPaneController::setTargetTable(QTableView* tableView)
    {
        if (m_targetTable == tableView)
        {
            refreshGeometry();
            return;
        }

        // 冻结锚点是“可视序号”，换一张表之后完全没有意义，因此一并解冻。
        releaseTarget();
        m_targetTable = tableView;
        m_targetModel = tableView != nullptr ? tableView->model() : nullptr;
        connectTarget();
        refreshGeometry();
    }

    QTableView* TableFrozenPaneController::targetTable() const
    {
        return m_targetTable.data();
    }

    bool TableFrozenPaneController::canFreeze() const
    {
        return !m_targetTable.isNull() &&
            m_targetTable->model() != nullptr &&
            m_targetTable->viewport() != nullptr &&
            TableActionBarHostFor(m_targetTable.data()) != nullptr;
    }

    int TableFrozenPaneController::freezeRowsThroughVisualRow(const int lastVisualRow)
    {
        if (!canFreeze() || m_targetTable->verticalHeader() == nullptr)
        {
            return 0;
        }

        QTableView* tableView = m_targetTable.data();
        const int sectionCount = tableView->verticalHeader()->count();
        if (lastVisualRow < 0 || lastVisualRow >= sectionCount)
        {
            return 0;
        }

        int anchorVisual = topVisibleVisualRow();
        if (anchorVisual < 0 || anchorVisual > lastVisualRow)
        {
            anchorVisual = lastVisualRow;
        }
        const int endVisual = lastVisualRow + 1;

        const int budget = std::max(
            0,
            (tableView->viewport()->height() + m_appliedFrozenHeight) / kFrozenBandBudgetDivisor);
        while (anchorVisual < endVisual &&
            rowsBandHeight(anchorVisual, endVisual) > budget)
        {
            ++anchorVisual;
        }
        if (anchorVisual >= endVisual || rowsBandHeight(anchorVisual, endVisual) <= 0)
        {
            return 0;
        }

        m_rowAnchorVisual = anchorVisual;
        m_rowEndVisual = endVisual;
        refreshGeometry();
        return m_rowEndVisual - m_rowAnchorVisual;
    }

    int TableFrozenPaneController::freezeColumnsThroughVisualColumn(const int lastVisualColumn)
    {
        if (!canFreeze() || m_targetTable->horizontalHeader() == nullptr)
        {
            return 0;
        }

        QTableView* tableView = m_targetTable.data();
        const int sectionCount = tableView->horizontalHeader()->count();
        if (lastVisualColumn < 0 || lastVisualColumn >= sectionCount)
        {
            return 0;
        }

        int anchorVisual = leftVisibleVisualColumn();
        if (anchorVisual < 0 || anchorVisual > lastVisualColumn)
        {
            anchorVisual = lastVisualColumn;
        }
        const int endVisual = lastVisualColumn + 1;

        const int budget = std::max(
            0,
            (tableView->viewport()->width() + m_appliedFrozenWidth) / kFrozenBandBudgetDivisor);
        while (anchorVisual < endVisual &&
            columnsBandWidth(anchorVisual, endVisual) > budget)
        {
            ++anchorVisual;
        }
        if (anchorVisual >= endVisual || columnsBandWidth(anchorVisual, endVisual) <= 0)
        {
            return 0;
        }

        m_columnAnchorVisual = anchorVisual;
        m_columnEndVisual = endVisual;
        refreshGeometry();
        return m_columnEndVisual - m_columnAnchorVisual;
    }

    void TableFrozenPaneController::clearFrozenRows()
    {
        if (m_rowEndVisual == m_rowAnchorVisual)
        {
            return;
        }
        m_rowAnchorVisual = 0;
        m_rowEndVisual = 0;
        refreshGeometry();
    }

    void TableFrozenPaneController::clearFrozenColumns()
    {
        if (m_columnEndVisual == m_columnAnchorVisual)
        {
            return;
        }
        m_columnAnchorVisual = 0;
        m_columnEndVisual = 0;
        refreshGeometry();
    }

    void TableFrozenPaneController::clearFrozenPanes()
    {
        m_rowAnchorVisual = 0;
        m_rowEndVisual = 0;
        m_columnAnchorVisual = 0;
        m_columnEndVisual = 0;
        refreshGeometry();
    }

    int TableFrozenPaneController::frozenRowCount() const
    {
        return rowBandActive() ? m_rowEndVisual - m_rowAnchorVisual : 0;
    }

    int TableFrozenPaneController::frozenColumnCount() const
    {
        return columnBandActive() ? m_columnEndVisual - m_columnAnchorVisual : 0;
    }

    bool TableFrozenPaneController::eventFilter(QObject* watchedObject, QEvent* eventObject)
    {
        if (eventObject != nullptr &&
            (eventObject->type() == QEvent::Resize ||
                eventObject->type() == QEvent::Show ||
                eventObject->type() == QEvent::LayoutRequest ||
                eventObject->type() == QEvent::StyleChange))
        {
            scheduleRefresh();
        }
        return QObject::eventFilter(watchedObject, eventObject);
    }

    void TableFrozenPaneController::disconnectTarget()
    {
        if (!m_targetTable.isNull())
        {
            QObject::disconnect(m_targetTable, nullptr, this, nullptr);
            if (QHeaderView* header = m_targetTable->horizontalHeader())
            {
                QObject::disconnect(header, nullptr, this, nullptr);
            }
            if (QHeaderView* header = m_targetTable->verticalHeader())
            {
                QObject::disconnect(header, nullptr, this, nullptr);
            }
            if (QScrollBar* scrollBar = m_targetTable->horizontalScrollBar())
            {
                QObject::disconnect(scrollBar, nullptr, this, nullptr);
            }
            if (QScrollBar* scrollBar = m_targetTable->verticalScrollBar())
            {
                QObject::disconnect(scrollBar, nullptr, this, nullptr);
            }
            m_targetTable->removeEventFilter(this);
            if (m_targetTable->viewport() != nullptr)
            {
                m_targetTable->viewport()->removeEventFilter(this);
            }
        }
        if (!m_targetModel.isNull())
        {
            QObject::disconnect(m_targetModel, nullptr, this, nullptr);
        }
    }

    void TableFrozenPaneController::connectTarget()
    {
        if (m_targetTable.isNull())
        {
            return;
        }

        const auto onScrolled = [this]()
        {
            if (m_refreshing)
            {
                return;
            }
            m_refreshing = true;
            applySourceScrollLimits();
            syncPanes();
            m_refreshing = false;
        };
        const auto onSectionChanged = [this]()
        {
            if (!m_mirroringSections)
            {
                scheduleRefresh();
            }
        };

        connect(m_targetTable->horizontalScrollBar(), &QScrollBar::valueChanged, this, onScrolled);
        connect(m_targetTable->verticalScrollBar(), &QScrollBar::valueChanged, this, onScrolled);
        connect(m_targetTable->horizontalScrollBar(), &QScrollBar::rangeChanged, this, onScrolled);
        connect(m_targetTable->verticalScrollBar(), &QScrollBar::rangeChanged, this, onScrolled);
        connect(
            m_targetTable->horizontalHeader(),
            &QHeaderView::sectionResized,
            this,
            onSectionChanged);
        connect(
            m_targetTable->verticalHeader(),
            &QHeaderView::sectionResized,
            this,
            onSectionChanged);
        connect(
            m_targetTable->horizontalHeader(),
            &QHeaderView::sectionMoved,
            this,
            onSectionChanged);
        connect(
            m_targetTable->horizontalHeader(),
            &QHeaderView::sortIndicatorChanged,
            this,
            onSectionChanged);
        m_targetTable->installEventFilter(this);
        if (m_targetTable->viewport() != nullptr)
        {
            m_targetTable->viewport()->installEventFilter(this);
        }

        if (!m_targetModel.isNull())
        {
            const auto onModelChanged = [this]() { scheduleRefresh(); };
            connect(m_targetModel, &QAbstractItemModel::modelReset, this, onModelChanged);
            connect(m_targetModel, &QAbstractItemModel::rowsInserted, this, onModelChanged);
            connect(m_targetModel, &QAbstractItemModel::rowsRemoved, this, onModelChanged);
            connect(m_targetModel, &QAbstractItemModel::columnsInserted, this, onModelChanged);
            connect(m_targetModel, &QAbstractItemModel::columnsRemoved, this, onModelChanged);
            connect(m_targetModel, &QAbstractItemModel::layoutChanged, this, onModelChanged);
        }
    }

    void TableFrozenPaneController::scheduleRefresh()
    {
        if (m_refreshScheduled)
        {
            return;
        }
        // 没有任何冻结时无事可做。进程表这类每秒重建模型的表格挂着大量这种信号，
        // 白跑一轮虽然便宜，但没必要。
        const bool hasBands =
            m_rowEndVisual > m_rowAnchorVisual || m_columnEndVisual > m_columnAnchorVisual;
        if (!hasBands &&
            m_topPane.isNull() &&
            m_leftPane.isNull() &&
            m_cornerPane.isNull() &&
            m_appliedFrozenWidth == 0 &&
            m_appliedFrozenHeight == 0)
        {
            return;
        }
        m_refreshScheduled = true;
        QTimer::singleShot(0, this, [this]()
            {
                m_refreshScheduled = false;
                refreshGeometry();
            });
    }

    void TableFrozenPaneController::releaseTarget()
    {
        destroyPanes();
        if (!m_targetTable.isNull())
        {
            if (TableActionBarHost* host = TableActionBarHostFor(m_targetTable.data()))
            {
                host->setFrozenPaneReservation(0, 0);
            }
            if (QScrollBar* scrollBar = m_targetTable->verticalScrollBar())
            {
                scrollBar->setMinimum(0);
            }
            if (QScrollBar* scrollBar = m_targetTable->horizontalScrollBar())
            {
                scrollBar->setMinimum(0);
            }
        }
        disconnectTarget();
        m_targetTable.clear();
        m_targetModel.clear();
        m_rowAnchorVisual = 0;
        m_rowEndVisual = 0;
        m_columnAnchorVisual = 0;
        m_columnEndVisual = 0;
        m_appliedFrozenWidth = 0;
        m_appliedFrozenHeight = 0;
    }

    void TableFrozenPaneController::destroyPanes()
    {
        for (QPointer<QTableView>* guardedPane : { &m_topPane, &m_leftPane, &m_cornerPane })
        {
            if (!guardedPane->isNull())
            {
                guardedPane->data()->hide();
                guardedPane->data()->deleteLater();
                guardedPane->clear();
            }
        }
    }

    QTableView* TableFrozenPaneController::createPane(QPointer<QTableView>& guardedPane)
    {
        if (guardedPane.isNull())
        {
            guardedPane = new FrozenPaneTableView(m_targetTable.data(), m_targetTable.data());
        }
        return guardedPane.data();
    }

    void TableFrozenPaneController::ensurePanes()
    {
        const bool rowsFrozen = rowBandActive();
        const bool columnsFrozen = columnBandActive();
        if (!rowsFrozen && !columnsFrozen)
        {
            destroyPanes();
            return;
        }

        QTableView* tableView = m_targetTable.data();
        const int headerHeight = headerBandHeight(tableView);
        const int headerWidth = headerBandWidth(tableView);
        // 交叉窗格同时承担三件事：冻结行的行号、冻结列的列标题、以及两者相交的单元格。
        const bool cornerNeeded =
            (m_appliedFrozenWidth + headerWidth) > 0 &&
            (m_appliedFrozenHeight + headerHeight) > 0;

        if (rowsFrozen)
        {
            configurePane(createPane(m_topPane), false, false);
        }
        else if (!m_topPane.isNull())
        {
            m_topPane->hide();
            m_topPane->deleteLater();
            m_topPane.clear();
        }

        if (columnsFrozen)
        {
            configurePane(createPane(m_leftPane), false, false);
        }
        else if (!m_leftPane.isNull())
        {
            m_leftPane->hide();
            m_leftPane->deleteLater();
            m_leftPane.clear();
        }

        if (cornerNeeded)
        {
            configurePane(createPane(m_cornerPane), headerHeight > 0, headerWidth > 0);
        }
        else if (!m_cornerPane.isNull())
        {
            m_cornerPane->hide();
            m_cornerPane->deleteLater();
            m_cornerPane.clear();
        }
    }

    void TableFrozenPaneController::configurePane(
        QTableView* pane,
        const bool showHorizontalHeader,
        const bool showVerticalHeader)
    {
        if (pane == nullptr || m_targetTable.isNull() || m_targetTable->model() == nullptr)
        {
            return;
        }

        QTableView* sourceTable = m_targetTable.data();
        pane->setProperty(kFrozenPaneAuxiliaryProperty, true);
        pane->setProperty(
            kFrozenPaneSourceProperty,
            QVariant::fromValue(static_cast<QObject*>(sourceTable)));

        // setModel 会重建列宽与选择模型，只在真的换了模型时才做。
        if (pane->model() != sourceTable->model())
        {
            pane->setModel(sourceTable->model());
        }
        if (sourceTable->selectionModel() != nullptr &&
            pane->selectionModel() != sourceTable->selectionModel())
        {
            pane->setSelectionModel(sourceTable->selectionModel());
        }
        if (pane->itemDelegate() != sourceTable->itemDelegate())
        {
            pane->setItemDelegate(sourceTable->itemDelegate());
        }
        const int columnCount = sourceTable->model()->columnCount();
        for (int column = 0; column < columnCount; ++column)
        {
            QAbstractItemDelegate* columnDelegate = sourceTable->itemDelegateForColumn(column);
            if (columnDelegate != pane->itemDelegateForColumn(column))
            {
                pane->setItemDelegateForColumn(column, columnDelegate);
            }
        }

        pane->setSelectionMode(sourceTable->selectionMode());
        pane->setSelectionBehavior(sourceTable->selectionBehavior());
        pane->setEditTriggers(QAbstractItemView::NoEditTriggers);
        // 偏移完全由控制器按像素计算，窗格必须固定在按像素滚动模式。
        pane->setVerticalScrollMode(QAbstractItemView::ScrollPerPixel);
        pane->setHorizontalScrollMode(QAbstractItemView::ScrollPerPixel);
        pane->setVerticalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
        pane->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
        pane->setAlternatingRowColors(sourceTable->alternatingRowColors());
        pane->setShowGrid(sourceTable->showGrid());
        pane->setGridStyle(sourceTable->gridStyle());
        pane->setTextElideMode(sourceTable->textElideMode());
        pane->setWordWrap(sourceTable->wordWrap());
        pane->setSortingEnabled(false);
        pane->setFrameShape(QFrame::NoFrame);
        // 键盘焦点留在主表，否则方向键会在冻结区里移动当前项。
        pane->setFocusPolicy(Qt::NoFocus);
        pane->setFont(sourceTable->font());
        pane->setPalette(sourceTable->palette());
        pane->setAutoFillBackground(true);
        pane->viewport()->setAutoFillBackground(true);
        pane->viewport()->setPalette(sourceTable->viewport()->palette());
        pane->setCornerButtonEnabled(
            showHorizontalHeader && showVerticalHeader && sourceTable->isCornerButtonEnabled());

        QHeaderView* sourceHorizontalHeader = sourceTable->horizontalHeader();
        QHeaderView* paneHorizontalHeader = pane->horizontalHeader();
        paneHorizontalHeader->setVisible(showHorizontalHeader);
        if (showHorizontalHeader && sourceHorizontalHeader != nullptr)
        {
            paneHorizontalHeader->setFixedHeight(sourceHorizontalHeader->height());
            paneHorizontalHeader->setDefaultAlignment(
                sourceHorizontalHeader->defaultAlignment());
            paneHorizontalHeader->setHighlightSections(
                sourceHorizontalHeader->highlightSections());
            paneHorizontalHeader->setSectionsClickable(
                sourceHorizontalHeader->sectionsClickable());
            paneHorizontalHeader->setSectionsMovable(false);
            paneHorizontalHeader->setStretchLastSection(false);
            paneHorizontalHeader->setSortIndicatorShown(
                sourceHorizontalHeader->isSortIndicatorShown());
            paneHorizontalHeader->setFont(sourceHorizontalHeader->font());
            paneHorizontalHeader->setPalette(sourceHorizontalHeader->palette());
            if (!pane->property("kswordFrozenHeaderBridged").toBool())
            {
                pane->setProperty("kswordFrozenHeaderBridged", true);
                bridgeFrozenHeader(pane);
            }
        }

        QHeaderView* sourceVerticalHeader = sourceTable->verticalHeader();
        QHeaderView* paneVerticalHeader = pane->verticalHeader();
        paneVerticalHeader->setVisible(showVerticalHeader);
        if (showVerticalHeader && sourceVerticalHeader != nullptr)
        {
            paneVerticalHeader->setFixedWidth(sourceVerticalHeader->width());
            paneVerticalHeader->setDefaultAlignment(sourceVerticalHeader->defaultAlignment());
            paneVerticalHeader->setSectionsClickable(false);
            paneVerticalHeader->setFont(sourceVerticalHeader->font());
            paneVerticalHeader->setPalette(sourceVerticalHeader->palette());
        }
    }

    void TableFrozenPaneController::bridgeFrozenHeader(QTableView* pane)
    {
        if (pane == nullptr || pane->horizontalHeader() == nullptr)
        {
            return;
        }

        QHeaderView* paneHeader = pane->horizontalHeader();
        // 冻结列的列标题由交叉窗格绘制，点击排序、拖拽列宽都要转交主表处理，
        // 否则冻结之后这几列的表头就变成了死区。
        connect(
            paneHeader,
            &QHeaderView::sectionClicked,
            this,
            [this](const int logicalIndex)
            {
                if (m_targetTable.isNull() ||
                    !m_targetTable->isSortingEnabled() ||
                    m_targetTable->horizontalHeader() == nullptr)
                {
                    return;
                }
                QHeaderView* sourceHeader = m_targetTable->horizontalHeader();
                const Qt::SortOrder nextOrder =
                    sourceHeader->sortIndicatorSection() == logicalIndex &&
                        sourceHeader->sortIndicatorOrder() == Qt::AscendingOrder
                    ? Qt::DescendingOrder
                    : Qt::AscendingOrder;
                m_targetTable->sortByColumn(logicalIndex, nextOrder);
            });
        connect(
            paneHeader,
            &QHeaderView::sectionResized,
            this,
            [this](const int logicalIndex, int, const int newSize)
            {
                if (m_mirroringSections || m_targetTable.isNull())
                {
                    return;
                }
                m_targetTable->setColumnWidth(logicalIndex, newSize);
            });
    }

    void TableFrozenPaneController::mirrorColumnLayout(QTableView* pane)
    {
        if (pane == nullptr || m_targetTable.isNull())
        {
            return;
        }

        QHeaderView* sourceHeader = m_targetTable->horizontalHeader();
        QHeaderView* paneHeader = pane->horizontalHeader();
        if (sourceHeader == nullptr || paneHeader == nullptr)
        {
            return;
        }

        m_mirroringSections = true;
        paneHeader->setDefaultSectionSize(sourceHeader->defaultSectionSize());
        const int sectionCount = std::min(sourceHeader->count(), paneHeader->count());
        for (int visualIndex = 0; visualIndex < sectionCount; ++visualIndex)
        {
            const int logicalIndex = sourceHeader->logicalIndex(visualIndex);
            if (logicalIndex < 0)
            {
                continue;
            }
            const int paneVisualIndex = paneHeader->visualIndex(logicalIndex);
            if (paneVisualIndex >= 0 && paneVisualIndex != visualIndex)
            {
                paneHeader->moveSection(paneVisualIndex, visualIndex);
            }
        }
        for (int logicalIndex = 0; logicalIndex < sectionCount; ++logicalIndex)
        {
            const bool hidden = sourceHeader->isSectionHidden(logicalIndex);
            if (paneHeader->isSectionHidden(logicalIndex) != hidden)
            {
                paneHeader->setSectionHidden(logicalIndex, hidden);
            }
            if (!hidden)
            {
                paneHeader->resizeSection(logicalIndex, sourceHeader->sectionSize(logicalIndex));
            }
        }
        if (paneHeader->isSortIndicatorShown())
        {
            paneHeader->setSortIndicator(
                sourceHeader->sortIndicatorSection(),
                sourceHeader->sortIndicatorOrder());
        }
        m_mirroringSections = false;
    }

    void TableFrozenPaneController::mirrorRowLayout(
        QTableView* pane,
        const int firstLogicalRow,
        const int lastLogicalRow)
    {
        if (pane == nullptr || m_targetTable.isNull())
        {
            return;
        }

        QHeaderView* sourceHeader = m_targetTable->verticalHeader();
        QHeaderView* paneHeader = pane->verticalHeader();
        if (sourceHeader == nullptr || paneHeader == nullptr)
        {
            return;
        }

        m_mirroringSections = true;
        paneHeader->setDefaultSectionSize(sourceHeader->defaultSectionSize());
        const int sectionCount = std::min(sourceHeader->count(), paneHeader->count());
        const int firstRow = std::max(0, firstLogicalRow);
        const int lastRow = std::min(sectionCount - 1, lastLogicalRow);
        for (int logicalRow = firstRow; logicalRow <= lastRow; ++logicalRow)
        {
            const bool hidden = sourceHeader->isSectionHidden(logicalRow);
            if (paneHeader->isSectionHidden(logicalRow) != hidden)
            {
                paneHeader->setSectionHidden(logicalRow, hidden);
            }
            if (!hidden)
            {
                paneHeader->resizeSection(logicalRow, sourceHeader->sectionSize(logicalRow));
            }
        }
        m_mirroringSections = false;
    }

    void TableFrozenPaneController::clampBandsToModel()
    {
        QTableView* tableView = m_targetTable.data();
        if (tableView == nullptr)
        {
            return;
        }

        const int rowSectionCount =
            tableView->verticalHeader() != nullptr ? tableView->verticalHeader()->count() : 0;
        const int columnSectionCount =
            tableView->horizontalHeader() != nullptr ? tableView->horizontalHeader()->count() : 0;

        m_rowAnchorVisual = std::clamp(m_rowAnchorVisual, 0, rowSectionCount);
        m_rowEndVisual = std::clamp(m_rowEndVisual, 0, rowSectionCount);
        m_columnAnchorVisual = std::clamp(m_columnAnchorVisual, 0, columnSectionCount);
        m_columnEndVisual = std::clamp(m_columnEndVisual, 0, columnSectionCount);

        // 视口被拉小或行高变大时，旧的冻结区可能已经超出预算，这里再收一次。
        const int rowBudget = std::max(
            0,
            (tableView->viewport()->height() + m_appliedFrozenHeight) / kFrozenBandBudgetDivisor);
        while (m_rowAnchorVisual < m_rowEndVisual &&
            rowsBandHeight(m_rowAnchorVisual, m_rowEndVisual) > rowBudget)
        {
            ++m_rowAnchorVisual;
        }
        if (m_rowAnchorVisual >= m_rowEndVisual)
        {
            m_rowAnchorVisual = 0;
            m_rowEndVisual = 0;
        }

        const int columnBudget = std::max(
            0,
            (tableView->viewport()->width() + m_appliedFrozenWidth) / kFrozenBandBudgetDivisor);
        while (m_columnAnchorVisual < m_columnEndVisual &&
            columnsBandWidth(m_columnAnchorVisual, m_columnEndVisual) > columnBudget)
        {
            ++m_columnAnchorVisual;
        }
        if (m_columnAnchorVisual >= m_columnEndVisual)
        {
            m_columnAnchorVisual = 0;
            m_columnEndVisual = 0;
        }
    }

    void TableFrozenPaneController::layoutPanes()
    {
        QTableView* tableView = m_targetTable.data();
        if (tableView == nullptr || tableView->viewport() == nullptr)
        {
            return;
        }

        const QRect viewportGeometry = tableView->viewport()->geometry();
        const int frozenWidth = m_appliedFrozenWidth;
        const int frozenHeight = m_appliedFrozenHeight;
        const int headerHeight = headerBandHeight(tableView);
        const int headerWidth = headerBandWidth(tableView);
        const bool rightToLeft = tableView->isRightToLeft();
        const int bandLeft = rightToLeft
            ? viewportGeometry.right() + 1
            : viewportGeometry.left() - frozenWidth;
        const int cornerLeft = rightToLeft ? bandLeft : bandLeft - headerWidth;

        if (!m_topPane.isNull())
        {
            mirrorColumnLayout(m_topPane.data());
            m_topPane->setGeometry(
                viewportGeometry.left(),
                viewportGeometry.top() - frozenHeight,
                viewportGeometry.width(),
                frozenHeight);
            m_topPane->setVisible(frozenHeight > 0 && viewportGeometry.width() > 0);
            m_topPane->raise();
        }
        if (!m_leftPane.isNull())
        {
            mirrorColumnLayout(m_leftPane.data());
            m_leftPane->setGeometry(
                bandLeft,
                viewportGeometry.top(),
                frozenWidth,
                viewportGeometry.height());
            m_leftPane->setVisible(frozenWidth > 0 && viewportGeometry.height() > 0);
            m_leftPane->raise();
        }
        if (!m_cornerPane.isNull())
        {
            mirrorColumnLayout(m_cornerPane.data());
            m_cornerPane->setGeometry(
                cornerLeft,
                viewportGeometry.top() - frozenHeight - headerHeight,
                frozenWidth + headerWidth,
                frozenHeight + headerHeight);
            m_cornerPane->setVisible(
                (frozenWidth + headerWidth) > 0 && (frozenHeight + headerHeight) > 0);
            m_cornerPane->raise();
        }

        const int bandFirstRow = firstBandLogicalRow();
        if (bandFirstRow >= 0)
        {
            const int bandLastRow = lastBandLogicalRow();
            if (!m_topPane.isNull())
            {
                mirrorRowLayout(m_topPane.data(), bandFirstRow, bandLastRow);
            }
            if (!m_cornerPane.isNull())
            {
                mirrorRowLayout(m_cornerPane.data(), bandFirstRow, bandLastRow);
            }
        }
    }

    void TableFrozenPaneController::syncPanes()
    {
        QTableView* tableView = m_targetTable.data();
        if (tableView == nullptr || tableView->model() == nullptr)
        {
            return;
        }

        const int bandFirstRow = firstBandLogicalRow();
        const int bandFirstColumn = firstBandLogicalColumn();

        if (!m_topPane.isNull())
        {
            setPaneVerticalToRow(m_topPane.data(), bandFirstRow);
            setPaneHorizontalToSource(m_topPane.data());
        }
        if (!m_leftPane.isNull())
        {
            mirrorVisibleRowLayout(m_leftPane.data());
            setPaneVerticalToSource(m_leftPane.data());
            setPaneHorizontalToColumn(m_leftPane.data(), bandFirstColumn);
        }
        if (!m_cornerPane.isNull())
        {
            setPaneVerticalToRow(m_cornerPane.data(), bandFirstRow);
            setPaneHorizontalToColumn(m_cornerPane.data(), bandFirstColumn);
        }
    }

    void TableFrozenPaneController::mirrorVisibleRowLayout(QTableView* pane)
    {
        QTableView* tableView = m_targetTable.data();
        if (pane == nullptr || tableView == nullptr || tableView->model() == nullptr)
        {
            return;
        }

        const int rowCount = tableView->model()->rowCount();
        if (rowCount <= 0)
        {
            return;
        }

        int firstRow = tableView->rowAt(0);
        if (firstRow < 0)
        {
            firstRow = 0;
        }
        int lastRow = tableView->rowAt(std::max(0, tableView->viewport()->height() - 1));
        if (lastRow < 0)
        {
            lastRow = rowCount - 1;
        }
        if (lastRow < firstRow)
        {
            std::swap(firstRow, lastRow);
        }
        mirrorRowLayout(
            pane,
            std::max(0, firstRow - 1),
            std::min(rowCount - 1, lastRow + kMirrorRowMargin));
    }

    void TableFrozenPaneController::setPaneVerticalToRow(QTableView* pane, const int logicalRow)
    {
        if (pane == nullptr || pane->verticalHeader() == nullptr)
        {
            return;
        }
        const int position = logicalRow >= 0
            ? std::max(0, pane->verticalHeader()->sectionPosition(logicalRow))
            : 0;
        setPaneScrollValue(pane->verticalScrollBar(), position);
    }

    void TableFrozenPaneController::setPaneHorizontalToColumn(
        QTableView* pane,
        const int logicalColumn)
    {
        if (pane == nullptr || pane->horizontalHeader() == nullptr)
        {
            return;
        }
        const int position = logicalColumn >= 0
            ? std::max(0, pane->horizontalHeader()->sectionPosition(logicalColumn))
            : 0;
        setPaneScrollValue(pane->horizontalScrollBar(), position);
    }

    void TableFrozenPaneController::setPaneVerticalToSource(QTableView* pane)
    {
        QTableView* tableView = m_targetTable.data();
        if (pane == nullptr || tableView == nullptr || pane->verticalHeader() == nullptr)
        {
            return;
        }

        // 主表可能按整行滚动，滚动条数值并非像素；统一按“视口顶行的像素落点”对齐，
        // 这样两种滚动模式下冻结列都不会与主表错行。
        const int firstRow = tableView->rowAt(0);
        if (firstRow < 0)
        {
            setPaneScrollValue(pane->verticalScrollBar(), 0);
            return;
        }
        const int sectionPosition = pane->verticalHeader()->sectionPosition(firstRow);
        if (sectionPosition < 0)
        {
            return;
        }
        setPaneScrollValue(
            pane->verticalScrollBar(),
            std::max(0, sectionPosition - tableView->rowViewportPosition(firstRow)));
    }

    void TableFrozenPaneController::setPaneHorizontalToSource(QTableView* pane)
    {
        QTableView* tableView = m_targetTable.data();
        if (pane == nullptr || tableView == nullptr || pane->horizontalHeader() == nullptr)
        {
            return;
        }

        const int firstColumn = tableView->columnAt(0);
        if (firstColumn < 0)
        {
            setPaneScrollValue(pane->horizontalScrollBar(), 0);
            return;
        }
        const int sectionPosition = pane->horizontalHeader()->sectionPosition(firstColumn);
        if (sectionPosition < 0)
        {
            return;
        }
        setPaneScrollValue(
            pane->horizontalScrollBar(),
            std::max(0, sectionPosition - tableView->columnViewportPosition(firstColumn)));
    }

    void TableFrozenPaneController::applySourceScrollLimits()
    {
        QTableView* tableView = m_targetTable.data();
        if (tableView == nullptr || tableView->model() == nullptr)
        {
            return;
        }

        // Excel 语义：冻结之后滚动区只覆盖冻结区之后的行列，冻结区之前的内容在解冻前不可达。
        // 抬高滚动条下限即可，比“滚完再纠正”稳，也不会和平滑滚动动画来回打架。
        // 按像素滚动时滚动条数值是内容像素偏移，按整行滚动时是可视序号，两者分别取对应的边界。
        QScrollBar* verticalScrollBar = tableView->verticalScrollBar();
        const int scrollableRow = rowBandActive() ? firstScrollableLogicalRow() : -1;
        int verticalMinimum = 0;
        if (scrollableRow >= 0 && tableView->verticalHeader() != nullptr)
        {
            const int boundary =
                tableView->verticalScrollMode() == QAbstractItemView::ScrollPerPixel
                ? tableView->verticalHeader()->sectionPosition(scrollableRow)
                : m_rowEndVisual;
            verticalMinimum = std::clamp(boundary, 0, verticalScrollBar->maximum());
        }
        if (verticalScrollBar->minimum() != verticalMinimum)
        {
            verticalScrollBar->setMinimum(verticalMinimum);
        }

        QScrollBar* horizontalScrollBar = tableView->horizontalScrollBar();
        const int scrollableColumn = columnBandActive() ? firstScrollableLogicalColumn() : -1;
        int horizontalMinimum = 0;
        if (scrollableColumn >= 0 && tableView->horizontalHeader() != nullptr)
        {
            const int boundary =
                tableView->horizontalScrollMode() == QAbstractItemView::ScrollPerPixel
                ? tableView->horizontalHeader()->sectionPosition(scrollableColumn)
                : m_columnEndVisual;
            horizontalMinimum = std::clamp(boundary, 0, horizontalScrollBar->maximum());
        }
        if (horizontalScrollBar->minimum() != horizontalMinimum)
        {
            horizontalScrollBar->setMinimum(horizontalMinimum);
        }
    }

    void TableFrozenPaneController::refreshGeometry()
    {
        if (m_refreshing)
        {
            return;
        }
        if (m_targetTable.isNull() ||
            m_targetTable->viewport() == nullptr ||
            m_targetTable->model() == nullptr)
        {
            destroyPanes();
            m_appliedFrozenWidth = 0;
            m_appliedFrozenHeight = 0;
            return;
        }

        m_refreshing = true;

        if (m_targetModel != m_targetTable->model())
        {
            // 业务代码整体换掉模型后，按可视序号记录的锚点已经指向别的数据了，直接解冻。
            disconnectTarget();
            destroyPanes();
            m_rowAnchorVisual = 0;
            m_rowEndVisual = 0;
            m_columnAnchorVisual = 0;
            m_columnEndVisual = 0;
            m_targetModel = m_targetTable->model();
            connectTarget();
        }

        clampBandsToModel();

        if (TableActionBarHost* host = TableActionBarHostFor(m_targetTable.data()))
        {
            host->setFrozenPaneReservation(frozenColumnsWidth(), frozenRowsHeight());
            const QSize reservation = host->frozenPaneReservation();
            m_appliedFrozenWidth = reservation.width();
            m_appliedFrozenHeight = reservation.height();
        }
        else
        {
            // 普通 QTableView 无法预留视口，强行叠加只会遮住数据，这里直接放弃冻结。
            m_rowAnchorVisual = 0;
            m_rowEndVisual = 0;
            m_columnAnchorVisual = 0;
            m_columnEndVisual = 0;
            m_appliedFrozenWidth = 0;
            m_appliedFrozenHeight = 0;
        }

        ensurePanes();
        layoutPanes();
        applySourceScrollLimits();
        syncPanes();
        m_refreshing = false;
    }

    int TableFrozenPaneController::rowsBandHeight(
        const int anchorVisual,
        const int endVisual) const
    {
        QTableView* tableView = m_targetTable.data();
        if (tableView == nullptr || tableView->verticalHeader() == nullptr)
        {
            return 0;
        }

        int height = 0;
        const int sectionCount = tableView->verticalHeader()->count();
        for (int visualIndex = std::max(0, anchorVisual);
            visualIndex < std::min(endVisual, sectionCount);
            ++visualIndex)
        {
            const int logicalIndex = tableView->verticalHeader()->logicalIndex(visualIndex);
            if (logicalIndex >= 0 && !tableView->isRowHidden(logicalIndex))
            {
                height += tableView->rowHeight(logicalIndex);
            }
        }
        return height;
    }

    int TableFrozenPaneController::columnsBandWidth(
        const int anchorVisual,
        const int endVisual) const
    {
        QTableView* tableView = m_targetTable.data();
        if (tableView == nullptr || tableView->horizontalHeader() == nullptr)
        {
            return 0;
        }

        int width = 0;
        const int sectionCount = tableView->horizontalHeader()->count();
        for (int visualIndex = std::max(0, anchorVisual);
            visualIndex < std::min(endVisual, sectionCount);
            ++visualIndex)
        {
            const int logicalIndex = tableView->horizontalHeader()->logicalIndex(visualIndex);
            if (logicalIndex >= 0 && !tableView->isColumnHidden(logicalIndex))
            {
                width += tableView->columnWidth(logicalIndex);
            }
        }
        return width;
    }

    int TableFrozenPaneController::frozenRowsHeight() const
    {
        return rowsBandHeight(m_rowAnchorVisual, m_rowEndVisual);
    }

    int TableFrozenPaneController::frozenColumnsWidth() const
    {
        return columnsBandWidth(m_columnAnchorVisual, m_columnEndVisual);
    }

    int TableFrozenPaneController::firstBandLogicalRow() const
    {
        return logicalRowInRange(m_rowAnchorVisual, m_rowEndVisual, true);
    }

    int TableFrozenPaneController::lastBandLogicalRow() const
    {
        return logicalRowInRange(m_rowAnchorVisual, m_rowEndVisual, false);
    }

    int TableFrozenPaneController::firstBandLogicalColumn() const
    {
        return logicalColumnInRange(m_columnAnchorVisual, m_columnEndVisual, true);
    }

    int TableFrozenPaneController::firstScrollableLogicalRow() const
    {
        QTableView* tableView = m_targetTable.data();
        if (tableView == nullptr || tableView->verticalHeader() == nullptr)
        {
            return -1;
        }
        return logicalRowInRange(m_rowEndVisual, tableView->verticalHeader()->count(), true);
    }

    int TableFrozenPaneController::firstScrollableLogicalColumn() const
    {
        QTableView* tableView = m_targetTable.data();
        if (tableView == nullptr || tableView->horizontalHeader() == nullptr)
        {
            return -1;
        }
        return logicalColumnInRange(m_columnEndVisual, tableView->horizontalHeader()->count(), true);
    }

    int TableFrozenPaneController::logicalRowInRange(
        const int anchorVisual,
        const int endVisual,
        const bool takeFirst) const
    {
        QTableView* tableView = m_targetTable.data();
        if (tableView == nullptr || tableView->verticalHeader() == nullptr)
        {
            return -1;
        }

        const int sectionCount = tableView->verticalHeader()->count();
        int result = -1;
        for (int visualIndex = std::max(0, anchorVisual);
            visualIndex < std::min(endVisual, sectionCount);
            ++visualIndex)
        {
            const int logicalIndex = tableView->verticalHeader()->logicalIndex(visualIndex);
            if (logicalIndex < 0 || tableView->isRowHidden(logicalIndex))
            {
                continue;
            }
            result = logicalIndex;
            if (takeFirst)
            {
                break;
            }
        }
        return result;
    }

    int TableFrozenPaneController::logicalColumnInRange(
        const int anchorVisual,
        const int endVisual,
        const bool takeFirst) const
    {
        QTableView* tableView = m_targetTable.data();
        if (tableView == nullptr || tableView->horizontalHeader() == nullptr)
        {
            return -1;
        }

        const int sectionCount = tableView->horizontalHeader()->count();
        int result = -1;
        for (int visualIndex = std::max(0, anchorVisual);
            visualIndex < std::min(endVisual, sectionCount);
            ++visualIndex)
        {
            const int logicalIndex = tableView->horizontalHeader()->logicalIndex(visualIndex);
            if (logicalIndex < 0 || tableView->isColumnHidden(logicalIndex))
            {
                continue;
            }
            result = logicalIndex;
            if (takeFirst)
            {
                break;
            }
        }
        return result;
    }

    int TableFrozenPaneController::topVisibleVisualRow() const
    {
        QTableView* tableView = m_targetTable.data();
        if (tableView == nullptr || tableView->verticalHeader() == nullptr)
        {
            return -1;
        }

        int logicalRow = tableView->rowAt(0);
        if (logicalRow < 0)
        {
            logicalRow = logicalRowInRange(0, tableView->verticalHeader()->count(), true);
        }
        return logicalRow >= 0 ? tableView->verticalHeader()->visualIndex(logicalRow) : -1;
    }

    int TableFrozenPaneController::leftVisibleVisualColumn() const
    {
        QTableView* tableView = m_targetTable.data();
        if (tableView == nullptr || tableView->horizontalHeader() == nullptr)
        {
            return -1;
        }

        int logicalColumn = tableView->columnAt(0);
        if (logicalColumn < 0)
        {
            logicalColumn = logicalColumnInRange(0, tableView->horizontalHeader()->count(), true);
        }
        return logicalColumn >= 0
            ? tableView->horizontalHeader()->visualIndex(logicalColumn)
            : -1;
    }

    bool TableFrozenPaneController::rowBandActive() const
    {
        return m_rowEndVisual > m_rowAnchorVisual && frozenRowsHeight() > 0;
    }

    bool TableFrozenPaneController::columnBandActive() const
    {
        return m_columnEndVisual > m_columnAnchorVisual && frozenColumnsWidth() > 0;
    }
}
