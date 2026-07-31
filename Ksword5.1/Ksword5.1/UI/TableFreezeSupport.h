#pragma once

#include "TableSnapshotCompare.h"

#include <QAbstractTableModel>
#include <QObject>
#include <QPointer>

class QTableView;

namespace ks::ui
{
    // TablePausedSnapshotModel 作用：
    // - 把停止刷新时捕获的 TableSnapshot 暴露为只读表格模型；
    // - 模型完全独立于实时业务模型，后台刷新不会改变当前显示内容。
    class TablePausedSnapshotModel final : public QAbstractTableModel
    {
    public:
        explicit TablePausedSnapshotModel(
            TableSnapshot snapshot,
            QObject* parent = nullptr);

        const TableSnapshot& snapshot() const;

        int rowCount(const QModelIndex& parent = QModelIndex()) const override;
        int columnCount(const QModelIndex& parent = QModelIndex()) const override;
        QVariant data(const QModelIndex& index, int role = Qt::DisplayRole) const override;
        QVariant headerData(
            int section,
            Qt::Orientation orientation,
            int role = Qt::DisplayRole) const override;
        Qt::ItemFlags flags(const QModelIndex& index) const override;

    private:
        TableSnapshot m_snapshot;
    };

    // TableFrozenPaneController 作用：
    // - 在目标表格视口上方叠加顶部、左侧和交叉区域三个共享模型视图；
    // - 以可视行/列顺序冻结指定数量的窗格，并与原表滚动、选择及尺寸保持同步；
    // - 切换实时视图、停止刷新快照视图时保留冻结数量并重新绑定目标表格。
    class TableFrozenPaneController final : public QObject
    {
    public:
        explicit TableFrozenPaneController(QObject* parent = nullptr);

        void setTargetTable(QTableView* tableView);
        QTableView* targetTable() const;

        void setFrozenRowSectionCount(int count);
        void setFrozenColumnSectionCount(int count);
        int frozenRowSectionCount() const;
        int frozenColumnSectionCount() const;
        void clearFrozenPanes();

        void refreshGeometry(bool rebuildSections = false);

    private:
        void disconnectTarget();
        void connectTarget();
        void scheduleSectionRefresh();
        void ensureOverlayViews();
        void destroyOverlayViews();
        void configureOverlayView(QTableView* overlayView);
        void rebuildSectionVisibilityAndSizes();
        void syncScrollBars();
        int frozenRowsHeight() const;
        int frozenColumnsWidth() const;

        QPointer<QTableView> m_targetTable;
        QPointer<QAbstractItemModel> m_targetModel;
        QPointer<QTableView> m_topOverlay;
        QPointer<QTableView> m_leftOverlay;
        QPointer<QTableView> m_cornerOverlay;
        int m_frozenRowSectionCount = 0;
        int m_frozenColumnSectionCount = 0;
        int m_lastRowCount = -1;
        int m_lastColumnCount = -1;
        bool m_sectionRefreshScheduled = false;
    };
}
