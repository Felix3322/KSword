#pragma once

#include "TableSnapshotCompare.h"

#include <QAbstractTableModel>
#include <QObject>
#include <QPointer>

class QEvent;
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
    // - 提供与 Excel「冻结拆分窗格」一致的语义：被冻结的行钉在列表头正下方、被冻结的列钉在
    //   行表头正右侧，滚动区域从冻结区之后开始，冻结区之前的行列在解冻前不再可达；
    // - 冻结区不是浮在视口上的贴图，而是通过 TableActionBarHost 把视口切小后单独占位，
    //   因此滚动内容不会被冻结区遮住，也不会出现同一行既在冻结区又在滚动区的重影；
    // - 冻结锚点取“执行冻结时视口顶部的那一行/最左的那一列”，所以对着第 800 行冻结不会把
    //   前 800 行全部钉上来占满整屏；冻结区还会被限制在可用尺寸的一半以内；
    // - 目标表格必须实现 TableActionBarHost（VisibleTableWidget / TableActionTableView 等），
    //   普通 QTableView 无法预留视口，canFreeze() 会返回 false。
    class TableFrozenPaneController final : public QObject
    {
    public:
        explicit TableFrozenPaneController(QObject* parent = nullptr);
        ~TableFrozenPaneController() override;

        void setTargetTable(QTableView* tableView);
        QTableView* targetTable() const;

        // canFreeze 作用：目标表格是否具备视口预留能力，决定冻结菜单是否可用。
        bool canFreeze() const;

        // freezeRowsThroughVisualRow 作用：
        // - 把「当前视口顶部行」到 lastVisualRow（含）之间的可视行冻结到列表头下方；
        // - 返回实际冻结的行数，0 表示尺寸不足或参数无效，未做任何改动。
        int freezeRowsThroughVisualRow(int lastVisualRow);
        int freezeColumnsThroughVisualColumn(int lastVisualColumn);

        void clearFrozenRows();
        void clearFrozenColumns();
        void clearFrozenPanes();

        int frozenRowCount() const;
        int frozenColumnCount() const;

        void refreshGeometry();

    protected:
        bool eventFilter(QObject* watchedObject, QEvent* eventObject) override;

    private:
        void disconnectTarget();
        void connectTarget();
        void scheduleRefresh();
        void releaseTarget();
        void destroyPanes();
        void ensurePanes();
        QTableView* createPane(QPointer<QTableView>& guardedPane);
        void configurePane(QTableView* pane, bool showHorizontalHeader, bool showVerticalHeader);
        void bridgeFrozenHeader(QTableView* pane);
        void mirrorColumnLayout(QTableView* pane);
        void mirrorRowLayout(QTableView* pane, int firstLogicalRow, int lastLogicalRow);
        void mirrorVisibleRowLayout(QTableView* pane);
        void clampBandsToModel();
        void layoutPanes();
        void syncPanes();
        void setPaneVerticalToRow(QTableView* pane, int logicalRow);
        void setPaneHorizontalToColumn(QTableView* pane, int logicalColumn);
        void setPaneVerticalToSource(QTableView* pane);
        void setPaneHorizontalToSource(QTableView* pane);
        void applySourceScrollLimits();

        int rowsBandHeight(int anchorVisual, int endVisual) const;
        int columnsBandWidth(int anchorVisual, int endVisual) const;
        int frozenRowsHeight() const;
        int frozenColumnsWidth() const;
        int logicalRowInRange(int anchorVisual, int endVisual, bool takeFirst) const;
        int logicalColumnInRange(int anchorVisual, int endVisual, bool takeFirst) const;
        int firstBandLogicalRow() const;
        int lastBandLogicalRow() const;
        int firstBandLogicalColumn() const;
        int firstScrollableLogicalRow() const;
        int firstScrollableLogicalColumn() const;
        int topVisibleVisualRow() const;
        int leftVisibleVisualColumn() const;
        bool rowBandActive() const;
        bool columnBandActive() const;

        QPointer<QTableView> m_targetTable;
        QPointer<QAbstractItemModel> m_targetModel;
        QPointer<QTableView> m_topPane;
        QPointer<QTableView> m_leftPane;
        QPointer<QTableView> m_cornerPane;
        // 冻结区按“可视序号左闭右开区间”描述，anchor==end 表示该方向未冻结。
        int m_rowAnchorVisual = 0;
        int m_rowEndVisual = 0;
        int m_columnAnchorVisual = 0;
        int m_columnEndVisual = 0;
        int m_appliedFrozenWidth = 0;
        int m_appliedFrozenHeight = 0;
        bool m_refreshing = false;
        bool m_refreshScheduled = false;
        bool m_mirroringSections = false;
    };
}
