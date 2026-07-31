#include "TableFreezeSupport.h"

#include <QCoreApplication>
#include <QHeaderView>
#include <QItemSelectionModel>
#include <QPalette>
#include <QScrollBar>
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

            // 冻结区域自身不滚动；把滚轮输入交还主表，随后由控制器同步覆盖视图。
            QCoreApplication::sendEvent(m_sourceTable->viewport(), eventObject);
        }

    private:
        QPointer<QTableView> m_sourceTable;
    };
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

    void TableFrozenPaneController::setTargetTable(QTableView* tableView)
    {
        if (m_targetTable == tableView)
        {
            refreshGeometry();
            return;
        }

        disconnectTarget();
        destroyOverlayViews();
        m_targetTable = tableView;
        m_targetModel = tableView != nullptr ? tableView->model() : nullptr;
        m_lastRowCount = -1;
        m_lastColumnCount = -1;
        connectTarget();
        refreshGeometry(true);
    }

    QTableView* TableFrozenPaneController::targetTable() const
    {
        return m_targetTable.data();
    }

    void TableFrozenPaneController::setFrozenRowSectionCount(const int count)
    {
        const int normalizedCount = std::max(0, count);
        if (m_frozenRowSectionCount == normalizedCount)
        {
            return;
        }
        m_frozenRowSectionCount = normalizedCount;
        refreshGeometry(true);
    }

    void TableFrozenPaneController::setFrozenColumnSectionCount(const int count)
    {
        const int normalizedCount = std::max(0, count);
        if (m_frozenColumnSectionCount == normalizedCount)
        {
            return;
        }
        m_frozenColumnSectionCount = normalizedCount;
        refreshGeometry(true);
    }

    int TableFrozenPaneController::frozenRowSectionCount() const
    {
        return m_frozenRowSectionCount;
    }

    int TableFrozenPaneController::frozenColumnSectionCount() const
    {
        return m_frozenColumnSectionCount;
    }

    void TableFrozenPaneController::clearFrozenPanes()
    {
        m_frozenRowSectionCount = 0;
        m_frozenColumnSectionCount = 0;
        destroyOverlayViews();
    }

    void TableFrozenPaneController::disconnectTarget()
    {
        if (!m_targetTable.isNull())
        {
            QObject::disconnect(m_targetTable, nullptr, this, nullptr);
            QObject::disconnect(m_targetTable->horizontalHeader(), nullptr, this, nullptr);
            QObject::disconnect(m_targetTable->verticalHeader(), nullptr, this, nullptr);
            QObject::disconnect(m_targetTable->horizontalScrollBar(), nullptr, this, nullptr);
            QObject::disconnect(m_targetTable->verticalScrollBar(), nullptr, this, nullptr);
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

        connect(
            m_targetTable->horizontalScrollBar(),
            &QScrollBar::valueChanged,
            this,
            [this]() { syncScrollBars(); });
        connect(
            m_targetTable->verticalScrollBar(),
            &QScrollBar::valueChanged,
            this,
            [this]() { syncScrollBars(); });
        connect(
            m_targetTable->horizontalHeader(),
            &QHeaderView::sectionResized,
            this,
            [this]() { scheduleSectionRefresh(); });
        connect(
            m_targetTable->verticalHeader(),
            &QHeaderView::sectionResized,
            this,
            [this]() { scheduleSectionRefresh(); });
        connect(
            m_targetTable->horizontalHeader(),
            &QHeaderView::sectionMoved,
            this,
            [this]() { scheduleSectionRefresh(); });
        connect(
            m_targetTable->verticalHeader(),
            &QHeaderView::sectionMoved,
            this,
            [this]() { scheduleSectionRefresh(); });

        if (!m_targetModel.isNull())
        {
            connect(
                m_targetModel,
                &QAbstractItemModel::modelReset,
                this,
                [this]() { scheduleSectionRefresh(); });
            connect(
                m_targetModel,
                &QAbstractItemModel::rowsInserted,
                this,
                [this]() { scheduleSectionRefresh(); });
            connect(
                m_targetModel,
                &QAbstractItemModel::rowsRemoved,
                this,
                [this]() { scheduleSectionRefresh(); });
            connect(
                m_targetModel,
                &QAbstractItemModel::columnsInserted,
                this,
                [this]() { scheduleSectionRefresh(); });
            connect(
                m_targetModel,
                &QAbstractItemModel::columnsRemoved,
                this,
                [this]() { scheduleSectionRefresh(); });
            connect(
                m_targetModel,
                &QAbstractItemModel::layoutChanged,
                this,
                [this]() { refreshGeometry(); });
        }
    }

    void TableFrozenPaneController::scheduleSectionRefresh()
    {
        if (m_sectionRefreshScheduled)
        {
            return;
        }
        m_sectionRefreshScheduled = true;
        QTimer::singleShot(0, this, [this]()
            {
                m_sectionRefreshScheduled = false;
                refreshGeometry(true);
            });
    }

    void TableFrozenPaneController::ensureOverlayViews()
    {
        if (m_targetTable.isNull() || m_targetTable->model() == nullptr ||
            (m_frozenRowSectionCount <= 0 && m_frozenColumnSectionCount <= 0))
        {
            destroyOverlayViews();
            return;
        }

        auto createOverlay = [this](QPointer<QTableView>& guardedView)
        {
            if (!guardedView.isNull())
            {
                return;
            }
            auto* overlay = new FrozenPaneTableView(
                m_targetTable.data(),
                m_targetTable->viewport());
            guardedView = overlay;
            configureOverlayView(overlay);
        };

        if (m_frozenRowSectionCount > 0)
        {
            createOverlay(m_topOverlay);
        }
        if (m_frozenColumnSectionCount > 0)
        {
            createOverlay(m_leftOverlay);
        }
        if (m_frozenRowSectionCount > 0 && m_frozenColumnSectionCount > 0)
        {
            createOverlay(m_cornerOverlay);
        }
    }

    void TableFrozenPaneController::destroyOverlayViews()
    {
        for (QPointer<QTableView>* guardedView :
            { &m_topOverlay, &m_leftOverlay, &m_cornerOverlay })
        {
            if (!guardedView->isNull())
            {
                guardedView->data()->hide();
                guardedView->data()->deleteLater();
                guardedView->clear();
            }
        }
    }

    void TableFrozenPaneController::configureOverlayView(QTableView* overlayView)
    {
        if (overlayView == nullptr || m_targetTable.isNull() ||
            m_targetTable->model() == nullptr)
        {
            return;
        }

        QTableView* sourceTable = m_targetTable.data();
        overlayView->setProperty(kFrozenPaneAuxiliaryProperty, true);
        overlayView->setProperty(
            kFrozenPaneSourceProperty,
            QVariant::fromValue(static_cast<QObject*>(sourceTable)));
        overlayView->setModel(sourceTable->model());
        if (sourceTable->selectionModel() != nullptr)
        {
            overlayView->setSelectionModel(sourceTable->selectionModel());
        }
        overlayView->setSelectionMode(sourceTable->selectionMode());
        overlayView->setSelectionBehavior(sourceTable->selectionBehavior());
        overlayView->setEditTriggers(sourceTable->editTriggers());
        overlayView->setVerticalScrollMode(sourceTable->verticalScrollMode());
        overlayView->setHorizontalScrollMode(sourceTable->horizontalScrollMode());
        overlayView->setVerticalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
        overlayView->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
        overlayView->setAlternatingRowColors(sourceTable->alternatingRowColors());
        overlayView->setShowGrid(sourceTable->showGrid());
        overlayView->setGridStyle(sourceTable->gridStyle());
        overlayView->setTextElideMode(sourceTable->textElideMode());
        overlayView->setWordWrap(sourceTable->wordWrap());
        overlayView->setFrameShape(QFrame::NoFrame);
        overlayView->setFont(sourceTable->font());
        overlayView->setPalette(sourceTable->palette());
        overlayView->setAutoFillBackground(true);
        overlayView->horizontalHeader()->hide();
        overlayView->verticalHeader()->hide();
        overlayView->viewport()->setAutoFillBackground(true);
        overlayView->viewport()->setPalette(sourceTable->viewport()->palette());
    }

    void TableFrozenPaneController::rebuildSectionVisibilityAndSizes()
    {
        if (m_targetTable.isNull() || m_targetTable->model() == nullptr)
        {
            return;
        }

        QTableView* sourceTable = m_targetTable.data();
        const int rowCount = sourceTable->model()->rowCount();
        const int columnCount = sourceTable->model()->columnCount();
        const int frozenRows = std::clamp(m_frozenRowSectionCount, 0, rowCount);
        const int frozenColumns = std::clamp(m_frozenColumnSectionCount, 0, columnCount);

        for (int logicalRow = 0; logicalRow < rowCount; ++logicalRow)
        {
            const int visualRow = sourceTable->verticalHeader()->visualIndex(logicalRow);
            const bool sourceHidden = sourceTable->isRowHidden(logicalRow);
            const bool inFrozenRows = visualRow >= 0 && visualRow < frozenRows;
            const int rowHeight = sourceTable->rowHeight(logicalRow);
            if (!m_topOverlay.isNull())
            {
                m_topOverlay->setRowHeight(logicalRow, rowHeight);
                m_topOverlay->setRowHidden(logicalRow, sourceHidden || !inFrozenRows);
            }
            if (!m_leftOverlay.isNull())
            {
                m_leftOverlay->setRowHeight(logicalRow, rowHeight);
                m_leftOverlay->setRowHidden(logicalRow, sourceHidden || inFrozenRows);
            }
            if (!m_cornerOverlay.isNull())
            {
                m_cornerOverlay->setRowHeight(logicalRow, rowHeight);
                m_cornerOverlay->setRowHidden(logicalRow, sourceHidden || !inFrozenRows);
            }
        }

        for (int logicalColumn = 0; logicalColumn < columnCount; ++logicalColumn)
        {
            const int visualColumn = sourceTable->horizontalHeader()->visualIndex(logicalColumn);
            const bool sourceHidden = sourceTable->isColumnHidden(logicalColumn);
            const bool inFrozenColumns =
                visualColumn >= 0 && visualColumn < frozenColumns;
            const int columnWidth = sourceTable->columnWidth(logicalColumn);
            if (!m_topOverlay.isNull())
            {
                m_topOverlay->setColumnWidth(logicalColumn, columnWidth);
                m_topOverlay->setColumnHidden(logicalColumn, sourceHidden);
            }
            if (!m_leftOverlay.isNull())
            {
                m_leftOverlay->setColumnWidth(logicalColumn, columnWidth);
                m_leftOverlay->setColumnHidden(
                    logicalColumn,
                    sourceHidden || !inFrozenColumns);
            }
            if (!m_cornerOverlay.isNull())
            {
                m_cornerOverlay->setColumnWidth(logicalColumn, columnWidth);
                m_cornerOverlay->setColumnHidden(
                    logicalColumn,
                    sourceHidden || !inFrozenColumns);
            }
        }
    }

    int TableFrozenPaneController::frozenRowsHeight() const
    {
        if (m_targetTable.isNull() || m_targetTable->model() == nullptr)
        {
            return 0;
        }

        int height = 0;
        const int sectionCount = std::min(
            m_frozenRowSectionCount,
            m_targetTable->verticalHeader()->count());
        for (int visualRow = 0; visualRow < sectionCount; ++visualRow)
        {
            const int logicalRow = m_targetTable->verticalHeader()->logicalIndex(visualRow);
            if (logicalRow >= 0 && !m_targetTable->isRowHidden(logicalRow))
            {
                height += m_targetTable->rowHeight(logicalRow);
            }
        }
        return height;
    }

    int TableFrozenPaneController::frozenColumnsWidth() const
    {
        if (m_targetTable.isNull() || m_targetTable->model() == nullptr)
        {
            return 0;
        }

        int width = 0;
        const int sectionCount = std::min(
            m_frozenColumnSectionCount,
            m_targetTable->horizontalHeader()->count());
        for (int visualColumn = 0; visualColumn < sectionCount; ++visualColumn)
        {
            const int logicalColumn =
                m_targetTable->horizontalHeader()->logicalIndex(visualColumn);
            if (logicalColumn >= 0 && !m_targetTable->isColumnHidden(logicalColumn))
            {
                width += m_targetTable->columnWidth(logicalColumn);
            }
        }
        return width;
    }

    void TableFrozenPaneController::syncScrollBars()
    {
        if (m_targetTable.isNull())
        {
            return;
        }
        if (!m_topOverlay.isNull())
        {
            m_topOverlay->horizontalScrollBar()->setValue(
                m_targetTable->horizontalScrollBar()->value());
        }
        if (!m_leftOverlay.isNull())
        {
            m_leftOverlay->verticalScrollBar()->setValue(
                m_targetTable->verticalScrollBar()->value());
        }
    }

    void TableFrozenPaneController::refreshGeometry(const bool rebuildSections)
    {
        if (m_targetTable.isNull() || m_targetTable->viewport() == nullptr ||
            m_targetTable->model() == nullptr)
        {
            destroyOverlayViews();
            return;
        }

        if (m_targetModel != m_targetTable->model())
        {
            disconnectTarget();
            destroyOverlayViews();
            m_targetModel = m_targetTable->model();
            m_lastRowCount = -1;
            m_lastColumnCount = -1;
            connectTarget();
        }

        ensureOverlayViews();
        const int rowCount = m_targetTable->model()->rowCount();
        const int columnCount = m_targetTable->model()->columnCount();
        const bool countsChanged =
            rowCount != m_lastRowCount || columnCount != m_lastColumnCount;
        if (rebuildSections || countsChanged)
        {
            rebuildSectionVisibilityAndSizes();
            m_lastRowCount = rowCount;
            m_lastColumnCount = columnCount;
        }

        const QRect viewportRect = m_targetTable->viewport()->rect();
        const int topHeight = std::clamp(
            frozenRowsHeight(),
            0,
            viewportRect.height());
        const int leftWidth = std::clamp(
            frozenColumnsWidth(),
            0,
            viewportRect.width());

        if (!m_topOverlay.isNull())
        {
            m_topOverlay->setGeometry(0, 0, viewportRect.width(), topHeight);
            m_topOverlay->setVisible(topHeight > 0);
        }
        if (!m_leftOverlay.isNull())
        {
            m_leftOverlay->setGeometry(
                0,
                topHeight,
                leftWidth,
                std::max(0, viewportRect.height() - topHeight));
            m_leftOverlay->setVisible(
                leftWidth > 0 && viewportRect.height() > topHeight);
        }
        if (!m_cornerOverlay.isNull())
        {
            m_cornerOverlay->setGeometry(0, 0, leftWidth, topHeight);
            m_cornerOverlay->setVisible(leftWidth > 0 && topHeight > 0);
        }

        syncScrollBars();
        if (!m_topOverlay.isNull()) m_topOverlay->raise();
        if (!m_leftOverlay.isNull()) m_leftOverlay->raise();
        if (!m_cornerOverlay.isNull()) m_cornerOverlay->raise();
    }
}
