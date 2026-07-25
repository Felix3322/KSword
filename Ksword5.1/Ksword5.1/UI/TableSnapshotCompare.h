#pragma once

#include <QAbstractTableModel>
#include <QDateTime>
#include <QSet>
#include <QString>
#include <QStringList>
#include <QVector>

class QTableView;

namespace ks::ui
{
    // TableSnapshotColumn keeps the source-model column identity as well as the text displayed
    // in the column header.  sourceColumn lets two snapshots remain comparable after users move
    // a header section.
    struct TableSnapshotColumn
    {
        int sourceColumn = -1;
        QString headerText;
    };

    // TableSnapshotRow stores display-role text only.  The snapshot is therefore independent of
    // the source model lifetime and intentionally represents exactly what the user saw.
    struct TableSnapshotRow
    {
        int sourceRow = -1;
        QStringList values;
    };

    // TableSnapshot is an in-memory capture of a single table's visible state.
    struct TableSnapshot
    {
        QString label;
        QDateTime capturedAt;
        quint64 sequence = 0;
        QVector<TableSnapshotColumn> visibleColumns;
        QVector<TableSnapshotRow> rows;
        int sortColumn = -1;
        Qt::SortOrder sortOrder = Qt::AscendingOrder;
        QVector<int> keyColumns;
    };

    enum class TableComparisonSource
    {
        EarlierOnly,
        LaterOnly,
        Both
    };

    // TableComparisonRow values follow TableComparisonResult::columns.  changedSourceColumns is
    // populated only when stable key columns make field-level comparison safe.
    struct TableComparisonRow
    {
        TableComparisonSource source = TableComparisonSource::Both;
        QStringList values;
        QSet<int> changedSourceColumns;
    };

    struct TableComparisonResult
    {
        QVector<TableSnapshotColumn> columns;
        QVector<TableComparisonRow> rows;
        QSet<int> ignoredSourceColumns;
        bool usesStableKeys = false;
    };

    class TableSnapshotCompareEngine final
    {
    public:
        // capture collects visible columns in visual-header order and visible rows in their
        // current visual order.  It also records the optional kswordSnapshotKeyColumns property.
        static TableSnapshot capture(QTableView* tableView, const QString& label, quint64 sequence);

        // Built-in bilingual names for columns whose values normally change on every refresh.
        static QStringList defaultIgnoredColumnKeywords();

        // Returns the built-in default ignored source-model columns for one snapshot.  Callers
        // comparing two snapshots should unite the two returned sets.
        static QSet<int> defaultIgnoredColumnIndexes(const TableSnapshot& snapshot);

        // Returns source-model column numbers whose header contains any keyword.  The caller can
        // use this to render and adjust the temporary ignore-columns menu.
        static QSet<int> ignoredColumnIndexesForKeywords(
            const TableSnapshot& earlier,
            const TableSnapshot& later,
            const QStringList& keywords);

        // Compares an earlier and later snapshot.  Without usable stable keys it performs a
        // Git-style text multiset compare.  With usable declared keys it returns AB rows for the
        // same key and marks changed cells by source column.
        static TableComparisonResult compare(
            const TableSnapshot& earlier,
            const TableSnapshot& later,
            const QSet<int>& ignoredOriginalColumnIndexes,
            const QVector<int>& keyColumnIndexes = QVector<int>());

        // Converts a monotonically increasing snapshot ordinal to A..Z, AA, AB, etc.  The owner
        // must keep the ordinal monotonic even after deleting a snapshot.
        static QString snapshotLabelForOrdinal(quint64 ordinal);
    };

    // A read-only comparison view model.  Its first column is the source marker A, B or AB.
    class TableComparisonModel final : public QAbstractTableModel
    {
    public:
        explicit TableComparisonModel(QObject* parent = nullptr);
        explicit TableComparisonModel(TableComparisonResult comparison, QObject* parent = nullptr);

        void setComparison(TableComparisonResult comparison);
        const TableComparisonResult& comparison() const;

        void setShowDifferencesOnly(bool enabled);
        bool showDifferencesOnly() const;

        int rowCount(const QModelIndex& parent = QModelIndex()) const override;
        int columnCount(const QModelIndex& parent = QModelIndex()) const override;
        QVariant data(const QModelIndex& index, int role = Qt::DisplayRole) const override;
        QVariant headerData(
            int section,
            Qt::Orientation orientation,
            int role = Qt::DisplayRole) const override;
        Qt::ItemFlags flags(const QModelIndex& index) const override;

    private:
        void rebuildVisibleRows();

        TableComparisonResult m_comparison;
        QVector<int> m_visibleRows;
        bool m_showDifferencesOnly = true;
    };
}
