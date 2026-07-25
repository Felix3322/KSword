#pragma once

#include <QAbstractButton>
#include <QAbstractItemModel>
#include <QHeaderView>
#include <QList>
#include <QMargins>
#include <QModelIndex>
#include <QPaintEvent>
#include <QPointer>
#include <QRect>
#include <QScrollBar>
#include <QSignalBlocker>
#include <QTableView>
#include <QTableWidget>
#include <QTimer>
#include <QVariant>

#include <algorithm>
#include <utility>

namespace ks::ui
{
    // Implemented by table subclasses that can reserve a strip immediately above the column
    // header. The action widget remains owned by its caller; this interface only manages the
    // table's layout reservation and supplies the matching geometry for that widget.
    class TableActionBarHost
    {
    public:
        virtual ~TableActionBarHost() = default;

        virtual void setTopActionBarHeight(int height) = 0;
        virtual int topActionBarHeight() const = 0;
        virtual QRect topActionBarGeometry() const = 0;
    };

    namespace visible_table_detail
    {
        inline constexpr char ComparisonSourceActiveProperty[] =
            "KSWORD_TABLE_INTERACTION_COMPARISON_SOURCE_ACTIVE";

        // QTableView owns its viewport margins and recalculates them whenever its geometry is
        // updated. Keep the action-bar adjustment in a small reusable helper so QTableWidget and
        // plain QTableView hosts receive exactly the same table/header/scrollbar layout.
        class TableActionBarLayout final
        {
        public:
            bool setHeight(const int height)
            {
                const int normalizedHeight = std::max(0, height);
                if (m_height == normalizedHeight)
                {
                    return false;
                }

                m_height = normalizedHeight;
                return true;
            }

            int height() const
            {
                return m_height;
            }

            QRect geometry(const QTableView* tableView) const
            {
                if (tableView == nullptr || tableView->viewport() == nullptr || m_height <= 0)
                {
                    return {};
                }

                const QRect viewportGeometry = tableView->viewport()->geometry();
                int left = viewportGeometry.left();
                int right = viewportGeometry.right();
                if (const QHeaderView* verticalHeader = tableView->verticalHeader();
                    verticalHeader != nullptr && !verticalHeader->isHidden())
                {
                    left = std::min(left, verticalHeader->geometry().left());
                    right = std::max(right, verticalHeader->geometry().right());
                }

                const QHeaderView* horizontalHeader = tableView->horizontalHeader();
                const int headerHeight = horizontalHeader != nullptr && !horizontalHeader->isHidden()
                    ? horizontalHeader->height()
                    : 0;
                const int top = viewportGeometry.top() - headerHeight - m_height;
                return QRect(left, top, std::max(0, right - left + 1), m_height);
            }

            // Capture this directly after QTableView::updateGeometries().  QTableView owns the
            // normal header margins and resets them on every geometry pass.  Keeping that value
            // separate prevents the action-bar height from being added repeatedly.
            void captureBaseViewportMargins(const QMargins& baseMargins)
            {
                m_baseViewportMargins = baseMargins;
            }

            // Must be called after captureBaseViewportMargins().
            QMargins adjustedViewportMargins() const
            {
                if (m_height <= 0)
                {
                    return m_baseViewportMargins;
                }

                return QMargins(
                    m_baseViewportMargins.left(),
                    m_baseViewportMargins.top() + m_height,
                    m_baseViewportMargins.right(),
                    m_baseViewportMargins.bottom());
            }

            // Call this after the owning table subclass applies adjustedViewportMargins().
            // QAbstractScrollArea::setViewportMargins is protected, so its invocation must stay
            // in that subclass rather than in this generic helper.
            void applyTableChrome(QTableView* tableView) const
            {
                if (tableView == nullptr || tableView->viewport() == nullptr || m_height <= 0)
                {
                    return;
                }

                const QRect viewportGeometry = tableView->viewport()->geometry();
                QHeaderView* horizontalHeader = tableView->horizontalHeader();
                QHeaderView* verticalHeader = tableView->verticalHeader();
                const int horizontalHeaderHeight = horizontalHeader != nullptr && !horizontalHeader->isHidden()
                    ? horizontalHeader->height()
                    : 0;
                const int verticalHeaderWidth = verticalHeader != nullptr && !verticalHeader->isHidden()
                    ? verticalHeader->width()
                    : 0;

                const int verticalHeaderLeft = tableView->isRightToLeft()
                    ? viewportGeometry.right() + 1
                    : viewportGeometry.left() - verticalHeaderWidth;
                const int horizontalHeaderTop = viewportGeometry.top() - horizontalHeaderHeight;

                // QTableView connects each header's geometriesChanged signal directly back to
                // updateGeometries(). At this point QTableView's own recursion guard has already
                // been released, so the required second header placement must not emit that
                // signal again or it loops through geometry updates until the viewport disappears.
                const QSignalBlocker horizontalHeaderSignalBlocker(horizontalHeader);
                const QSignalBlocker verticalHeaderSignalBlocker(verticalHeader);
                if (horizontalHeader != nullptr)
                {
                    horizontalHeader->setGeometry(
                        viewportGeometry.left(),
                        horizontalHeaderTop,
                        viewportGeometry.width(),
                        horizontalHeaderHeight);
                }
                if (verticalHeader != nullptr)
                {
                    verticalHeader->setGeometry(
                        verticalHeaderLeft,
                        viewportGeometry.top(),
                        verticalHeaderWidth,
                        viewportGeometry.height());
                }

                // QTableView's private corner widget is a direct QAbstractButton child. It is
                // the intersection of the two headers, so it must follow the shifted header
                // row. Table action bars are hosted in their own container rather than as a
                // direct button child.
                const QList<QAbstractButton*> directButtons = tableView->findChildren<QAbstractButton*>(
                    QString(),
                    Qt::FindDirectChildrenOnly);
                for (QAbstractButton* button : directButtons)
                {
                    if (button != nullptr)
                    {
                        button->setGeometry(
                            verticalHeaderLeft,
                            horizontalHeaderTop,
                            verticalHeaderWidth,
                            horizontalHeaderHeight);
                    }
                }
            }

        private:
            QMargins m_baseViewportMargins;
            int m_height = 0;
        };

        inline std::pair<int, int> visibleRowRange(const QTableView* tableView)
        {
            if (tableView == nullptr ||
                tableView->model() == nullptr ||
                tableView->viewport() == nullptr ||
                tableView->verticalHeader() == nullptr ||
                tableView->viewport()->height() <= 0)
            {
                return { -1, -1 };
            }

            const int rowCount = tableView->model()->rowCount();
            if (rowCount <= 0)
            {
                return { -1, -1 };
            }

            const QHeaderView* verticalHeader = tableView->verticalHeader();
            int firstRow = verticalHeader->logicalIndexAt(0);
            if (firstRow < 0)
            {
                firstRow = verticalHeader->logicalIndexAt(1);
            }
            if (firstRow < 0)
            {
                return { -1, -1 };
            }

            int lastRow = verticalHeader->logicalIndexAt(tableView->viewport()->height() - 1);
            if (lastRow < 0)
            {
                // The table is shorter than its viewport. In that case the final model row is
                // visible even though the pixel at the bottom of the viewport is empty.
                const int finalContentPixel = std::min(
                    tableView->viewport()->height() - 1,
                    verticalHeader->length() - 1);
                lastRow = verticalHeader->logicalIndexAt(finalContentPixel);
            }
            if (lastRow < 0)
            {
                lastRow = firstRow;
            }

            if (firstRow > lastRow)
            {
                std::swap(firstRow, lastRow);
            }
            return {
                std::clamp(firstRow, 0, rowCount - 1),
                std::clamp(lastRow, 0, rowCount - 1)
            };
        }

        inline void scheduleVisibleRowHeightRefresh(QTableView* tableView)
        {
            if (tableView == nullptr || tableView->property("kswordVisibleRowHeightRefreshPending").toBool())
            {
                return;
            }

            tableView->setProperty("kswordVisibleRowHeightRefreshPending", true);
            const QPointer<QTableView> guardedTable(tableView);
            QTimer::singleShot(0, tableView, [guardedTable]()
                {
                    if (guardedTable.isNull())
                    {
                        return;
                    }

                    QTableView* table = guardedTable.data();
                    table->setProperty("kswordVisibleRowHeightRefreshPending", false);
                    const auto [firstRow, lastRow] = visibleRowRange(table);
                    if (firstRow < 0 || lastRow < firstRow)
                    {
                        return;
                    }

                    for (int row = firstRow; row <= lastRow; ++row)
                    {
                        if (!table->isRowHidden(row))
                        {
                            table->resizeRowToContents(row);
                        }
                    }
                });
        }
    }

    // VisibleTableWidget keeps the complete QTableWidget model intact. In particular, every
    // off-screen item and sort role still participates in QTableWidget's normal full-data sort.
    // Only QAbstractItemView's repaint notification is clipped to rows intersecting the viewport.
    class VisibleTableWidget final : public QTableWidget
        , public TableActionBarHost
    {
    public:
        using QTableWidget::QTableWidget;

        static constexpr int LongTableRowThreshold = 64;

        void setTopActionBarHeight(const int height) override
        {
            if (!m_actionBarLayout.setHeight(height))
            {
                return;
            }

            updateGeometries();
            update();
        }

        int topActionBarHeight() const override
        {
            return m_actionBarLayout.height();
        }

        QRect topActionBarGeometry() const override
        {
            return m_actionBarLayout.geometry(this);
        }

    protected:
        void paintEvent(QPaintEvent* eventObject) override
        {
            if (property(visible_table_detail::ComparisonSourceActiveProperty).toBool())
            {
                return;
            }
            QTableWidget::paintEvent(eventObject);
        }

        void updateGeometries() override
        {
            if (m_updatingActionBarGeometry)
            {
                return;
            }

            m_updatingActionBarGeometry = true;
            QTableWidget::updateGeometries();
            m_actionBarLayout.captureBaseViewportMargins(viewportMargins());
            setViewportMargins(m_actionBarLayout.adjustedViewportMargins());
            m_actionBarLayout.applyTableChrome(this);
            m_updatingActionBarGeometry = false;
        }

        void dataChanged(
            const QModelIndex& topLeft,
            const QModelIndex& bottomRight,
            const QList<int>& roles = QList<int>()) override
        {
            if (!topLeft.isValid() ||
                !bottomRight.isValid() ||
                topLeft.parent() != bottomRight.parent() ||
                model() == nullptr ||
                model()->rowCount(topLeft.parent()) < LongTableRowThreshold ||
                property("kswordDisableVisibleRefresh").toBool())
            {
                QTableView::dataChanged(topLeft, bottomRight, roles);
                return;
            }

            // Hidden tabs need no repaint. Qt will paint their current model contents normally
            // when they become visible, so skipping this notification cannot leave stale data.
            if (viewport() == nullptr || !viewport()->isVisible())
            {
                return;
            }

            const auto [firstVisibleRow, lastVisibleRow] =
                visible_table_detail::visibleRowRange(this);
            if (firstVisibleRow < 0 ||
                lastVisibleRow < topLeft.row() ||
                firstVisibleRow > bottomRight.row())
            {
                return;
            }

            const int firstChangedVisibleRow = std::max(firstVisibleRow, topLeft.row());
            const int lastChangedVisibleRow = std::min(lastVisibleRow, bottomRight.row());
            const QModelIndex clippedTopLeft = model()->index(
                firstChangedVisibleRow,
                topLeft.column(),
                topLeft.parent());
            const QModelIndex clippedBottomRight = model()->index(
                lastChangedVisibleRow,
                bottomRight.column(),
                bottomRight.parent());
            QTableView::dataChanged(clippedTopLeft, clippedBottomRight, roles);
        }

    private:
        visible_table_detail::TableActionBarLayout m_actionBarLayout;
        bool m_updatingActionBarGeometry = false;
    };

    // Use this for flat QTableView-based pages that need the same top action-bar reservation as
    // VisibleTableWidget. Its data/model behavior is otherwise identical to QTableView.
    class TableActionTableView final : public QTableView
        , public TableActionBarHost
    {
    public:
        using QTableView::QTableView;

        void setTopActionBarHeight(const int height) override
        {
            if (!m_actionBarLayout.setHeight(height))
            {
                return;
            }

            updateGeometries();
            update();
        }

        int topActionBarHeight() const override
        {
            return m_actionBarLayout.height();
        }

        QRect topActionBarGeometry() const override
        {
            return m_actionBarLayout.geometry(this);
        }

    protected:
        void paintEvent(QPaintEvent* eventObject) override
        {
            if (property(visible_table_detail::ComparisonSourceActiveProperty).toBool())
            {
                return;
            }
            QTableView::paintEvent(eventObject);
        }

        void updateGeometries() override
        {
            if (m_updatingActionBarGeometry)
            {
                return;
            }

            m_updatingActionBarGeometry = true;
            QTableView::updateGeometries();
            m_actionBarLayout.captureBaseViewportMargins(viewportMargins());
            setViewportMargins(m_actionBarLayout.adjustedViewportMargins());
            m_actionBarLayout.applyTableChrome(this);
            m_updatingActionBarGeometry = false;
        }

    private:
        visible_table_detail::TableActionBarLayout m_actionBarLayout;
        bool m_updatingActionBarGeometry = false;
    };

    inline TableActionBarHost* TableActionBarHostFor(QTableView* tableView)
    {
        return dynamic_cast<TableActionBarHost*>(tableView);
    }

    inline const TableActionBarHost* TableActionBarHostFor(const QTableView* tableView)
    {
        return dynamic_cast<const TableActionBarHost*>(tableView);
    }

    // Enables on-demand row-height measurement for variable-height long tables. The model still
    // contains every row; scrolling only measures the rows that have entered the viewport.
    inline void InstallVisibleRowHeightRefresh(QTableView* tableView)
    {
        if (tableView == nullptr || tableView->property("kswordVisibleRowHeightRefreshInstalled").toBool())
        {
            return;
        }

        tableView->setProperty("kswordVisibleRowHeightRefreshInstalled", true);
        if (tableView->verticalHeader() != nullptr)
        {
            tableView->verticalHeader()->setSectionResizeMode(QHeaderView::Interactive);
        }

        QObject::connect(
            tableView->verticalScrollBar(),
            &QScrollBar::valueChanged,
            tableView,
            [tableView](int)
            {
                visible_table_detail::scheduleVisibleRowHeightRefresh(tableView);
            });
        visible_table_detail::scheduleVisibleRowHeightRefresh(tableView);
    }

    inline void RefreshVisibleRowHeights(QTableView* tableView)
    {
        visible_table_detail::scheduleVisibleRowHeightRefresh(tableView);
    }
}
