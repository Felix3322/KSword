#include "TableSnapshotCompare.h"

#include "../Internationalization/LanguageManager.h"

#include <QAbstractItemModel>
#include <QColor>
#include <QHash>
#include <QHeaderView>
#include <QMetaType>
#include <QRegularExpression>
#include <QTableView>
#include <QVariant>

#include <algorithm>

namespace
{
    constexpr char kSnapshotKeyColumnsProperty[] = "kswordSnapshotKeyColumns";

    QString valueForSourceColumn(
        const ks::ui::TableSnapshot& snapshot,
        const ks::ui::TableSnapshotRow& row,
        const int sourceColumn)
    {
        for (int columnIndex = 0; columnIndex < snapshot.visibleColumns.size(); ++columnIndex)
        {
            if (snapshot.visibleColumns.at(columnIndex).sourceColumn == sourceColumn)
            {
                return columnIndex < row.values.size() ? row.values.at(columnIndex) : QString();
            }
        }
        return {};
    }

    bool snapshotContainsSourceColumn(const ks::ui::TableSnapshot& snapshot, const int sourceColumn)
    {
        return std::any_of(
            snapshot.visibleColumns.cbegin(),
            snapshot.visibleColumns.cend(),
            [sourceColumn](const ks::ui::TableSnapshotColumn& column)
            {
                return column.sourceColumn == sourceColumn;
            });
    }

    QVector<ks::ui::TableSnapshotColumn> combinedColumns(
        const ks::ui::TableSnapshot& earlier,
        const ks::ui::TableSnapshot& later)
    {
        QVector<ks::ui::TableSnapshotColumn> columns;
        QSet<int> seenColumns;
        const auto appendMissingColumns = [&columns, &seenColumns](const QVector<ks::ui::TableSnapshotColumn>& source)
            {
                for (const ks::ui::TableSnapshotColumn& column : source)
                {
                    if (column.sourceColumn >= 0 && !seenColumns.contains(column.sourceColumn))
                    {
                        columns.push_back(column);
                        seenColumns.insert(column.sourceColumn);
                    }
                }
            };
        appendMissingColumns(earlier.visibleColumns);
        appendMissingColumns(later.visibleColumns);
        return columns;
    }

    QStringList outputValues(
        const ks::ui::TableSnapshot& snapshot,
        const ks::ui::TableSnapshotRow& row,
        const QVector<ks::ui::TableSnapshotColumn>& columns)
    {
        QStringList values;
        values.reserve(columns.size());
        for (const ks::ui::TableSnapshotColumn& column : columns)
        {
            values.push_back(valueForSourceColumn(snapshot, row, column.sourceColumn));
        }
        return values;
    }

    QString stableTextSignature(const QStringList& values)
    {
        QString signature;
        for (const QString& value : values)
        {
            signature += QString::number(value.size());
            signature += QLatin1Char(':');
            signature += value;
            signature += QLatin1Char('|');
        }
        return signature;
    }

    QString rowSignature(
        const ks::ui::TableSnapshot& snapshot,
        const ks::ui::TableSnapshotRow& row,
        const QVector<ks::ui::TableSnapshotColumn>& columns,
        const QSet<int>& ignoredColumns)
    {
        QStringList values;
        values.reserve(columns.size());
        for (const ks::ui::TableSnapshotColumn& column : columns)
        {
            if (!ignoredColumns.contains(column.sourceColumn))
            {
                values.push_back(valueForSourceColumn(snapshot, row, column.sourceColumn));
            }
        }
        return stableTextSignature(values);
    }

    QString rowKeySignature(
        const ks::ui::TableSnapshot& snapshot,
        const ks::ui::TableSnapshotRow& row,
        const QVector<int>& keyColumns)
    {
        QStringList values;
        values.reserve(keyColumns.size());
        for (const int sourceColumn : keyColumns)
        {
            const QString value = valueForSourceColumn(snapshot, row, sourceColumn);
            if (value.trimmed().isEmpty())
            {
                return {};
            }
            values.push_back(value);
        }
        return stableTextSignature(values);
    }

    QVector<int> usableStableKeyColumns(
        const ks::ui::TableSnapshot& earlier,
        const ks::ui::TableSnapshot& later,
        const QVector<int>& requestedKeyColumns,
        const QSet<int>& ignoredColumns)
    {
        QVector<int> keyColumns;
        const QVector<int>& candidates = requestedKeyColumns.isEmpty()
            ? earlier.keyColumns
            : requestedKeyColumns;
        for (const int sourceColumn : candidates)
        {
            if (!ignoredColumns.contains(sourceColumn) &&
                (requestedKeyColumns.isEmpty() ? later.keyColumns.contains(sourceColumn) : true) &&
                snapshotContainsSourceColumn(earlier, sourceColumn) &&
                snapshotContainsSourceColumn(later, sourceColumn))
            {
                keyColumns.push_back(sourceColumn);
            }
        }
        return keyColumns;
    }

    bool buildUniqueRowKeys(
        const ks::ui::TableSnapshot& snapshot,
        const QVector<int>& keyColumns,
        QHash<QString, int>& rowByKey)
    {
        rowByKey.clear();
        rowByKey.reserve(snapshot.rows.size());
        for (int rowIndex = 0; rowIndex < snapshot.rows.size(); ++rowIndex)
        {
            const QString key = rowKeySignature(snapshot, snapshot.rows.at(rowIndex), keyColumns);
            if (key.isEmpty() || rowByKey.contains(key))
            {
                rowByKey.clear();
                return false;
            }
            rowByKey.insert(key, rowIndex);
        }
        return true;
    }

    bool headerMatchesKeyword(const QString& header, const QString& keyword)
    {
        const QString trimmedKeyword = keyword.trimmed();
        return !trimmedKeyword.isEmpty() &&
            header.contains(trimmedKeyword, Qt::CaseInsensitive);
    }

    QVector<int> declaredKeyColumns(QTableView* tableView)
    {
        QVector<int> result;
        if (tableView == nullptr || tableView->model() == nullptr)
        {
            return result;
        }

        const QVariant rawProperty = tableView->property(kSnapshotKeyColumnsProperty);
        if (!rawProperty.isValid() || rawProperty.isNull())
        {
            return result;
        }

        QVariantList entryList;
        if (rawProperty.metaType().id() == QMetaType::QVariantList)
        {
            entryList = rawProperty.toList();
        }
        else if (rawProperty.metaType().id() == QMetaType::QStringList)
        {
            const QStringList stringList = rawProperty.toStringList();
            for (const QString& entry : stringList)
            {
                entryList.push_back(entry);
            }
        }
        else
        {
            const QString text = rawProperty.toString();
            const QStringList stringList = text.split(
                QRegularExpression(QStringLiteral("[,;|]")),
                Qt::SkipEmptyParts);
            for (const QString& entry : stringList)
            {
                entryList.push_back(entry);
            }
        }

        const QAbstractItemModel* model = tableView->model();
        for (const QVariant& entry : entryList)
        {
            bool numericColumn = false;
            const int sourceColumn = entry.toInt(&numericColumn);
            if (numericColumn && sourceColumn >= 0 && sourceColumn < model->columnCount())
            {
                if (!result.contains(sourceColumn))
                {
                    result.push_back(sourceColumn);
                }
                continue;
            }

            const QString headerName = entry.toString().trimmed();
            if (headerName.isEmpty())
            {
                continue;
            }
            for (int column = 0; column < model->columnCount(); ++column)
            {
                const QString header = model->headerData(column, Qt::Horizontal, Qt::DisplayRole).toString();
                if (header.compare(headerName, Qt::CaseInsensitive) == 0 && !result.contains(column))
                {
                    result.push_back(column);
                    break;
                }
            }
        }
        return result;
    }

    QColor earlierOnlyColor()
    {
        return QColor(255, 0, 0, 96);
    }

    QColor laterOnlyColor()
    {
        return QColor(0, 255, 0, 96);
    }

    QColor changedFieldColor()
    {
        return QColor(255, 246, 201);
    }
}

namespace ks::ui
{
    TableSnapshot TableSnapshotCompareEngine::capture(
        QTableView* tableView,
        const QString& label,
        const quint64 sequence)
    {
        TableSnapshot snapshot;
        snapshot.label = label;
        snapshot.capturedAt = QDateTime::currentDateTime();
        snapshot.sequence = sequence;
        if (tableView == nullptr || tableView->model() == nullptr)
        {
            return snapshot;
        }

        QAbstractItemModel* model = tableView->model();
        QHeaderView* horizontalHeader = tableView->horizontalHeader();
        const int columnCount = model->columnCount();
        for (int visualColumn = 0; visualColumn < columnCount; ++visualColumn)
        {
            const int sourceColumn = horizontalHeader != nullptr
                ? horizontalHeader->logicalIndex(visualColumn)
                : visualColumn;
            if (sourceColumn < 0 || sourceColumn >= columnCount || tableView->isColumnHidden(sourceColumn))
            {
                continue;
            }
            snapshot.visibleColumns.push_back({
                sourceColumn,
                model->headerData(sourceColumn, Qt::Horizontal, Qt::DisplayRole).toString()
            });
        }

        QHeaderView* verticalHeader = tableView->verticalHeader();
        const int rowCount = model->rowCount();
        snapshot.rows.reserve(rowCount);
        for (int visualRow = 0; visualRow < rowCount; ++visualRow)
        {
            const int sourceRow = verticalHeader != nullptr
                ? verticalHeader->logicalIndex(visualRow)
                : visualRow;
            if (sourceRow < 0 || sourceRow >= rowCount || tableView->isRowHidden(sourceRow))
            {
                continue;
            }

            TableSnapshotRow row;
            row.sourceRow = sourceRow;
            row.values.reserve(snapshot.visibleColumns.size());
            for (const TableSnapshotColumn& column : snapshot.visibleColumns)
            {
                row.values.push_back(model->data(model->index(sourceRow, column.sourceColumn), Qt::DisplayRole).toString());
            }
            snapshot.rows.push_back(std::move(row));
        }

        if (horizontalHeader != nullptr)
        {
            snapshot.sortColumn = horizontalHeader->sortIndicatorSection();
            snapshot.sortOrder = horizontalHeader->sortIndicatorOrder();
        }
        snapshot.keyColumns = declaredKeyColumns(tableView);
        return snapshot;
    }

    QStringList TableSnapshotCompareEngine::defaultIgnoredColumnKeywords()
    {
        return {
            QStringLiteral("序号"),
            QStringLiteral("行号"),
            QStringLiteral("时间"),
            QStringLiteral("日期"),
            QStringLiteral("Index"),
            QStringLiteral("No."),
            QStringLiteral("Sequence"),
            QStringLiteral("Time"),
            QStringLiteral("Timestamp"),
            QStringLiteral("Date")
        };
    }

    QSet<int> TableSnapshotCompareEngine::defaultIgnoredColumnIndexes(const TableSnapshot& snapshot)
    {
        QSet<int> ignoredColumns;
        const QStringList keywords = defaultIgnoredColumnKeywords();
        for (const TableSnapshotColumn& column : snapshot.visibleColumns)
        {
            for (const QString& keyword : keywords)
            {
                if (headerMatchesKeyword(column.headerText, keyword))
                {
                    ignoredColumns.insert(column.sourceColumn);
                    break;
                }
            }
        }
        return ignoredColumns;
    }

    QSet<int> TableSnapshotCompareEngine::ignoredColumnIndexesForKeywords(
        const TableSnapshot& earlier,
        const TableSnapshot& later,
        const QStringList& keywords)
    {
        QSet<int> ignoredColumns;
        const auto appendMatchingColumns = [&ignoredColumns, &keywords](
            const QVector<TableSnapshotColumn>& columns)
        {
            for (const TableSnapshotColumn& column : columns)
            {
                for (const QString& keyword : keywords)
                {
                    if (headerMatchesKeyword(column.headerText, keyword))
                    {
                        ignoredColumns.insert(column.sourceColumn);
                        break;
                    }
                }
            }
        };
        appendMatchingColumns(earlier.visibleColumns);
        appendMatchingColumns(later.visibleColumns);
        return ignoredColumns;
    }

    TableComparisonResult TableSnapshotCompareEngine::compare(
        const TableSnapshot& earlier,
        const TableSnapshot& later,
        const QSet<int>& ignoredOriginalColumnIndexes,
        const QVector<int>& keyColumnIndexes)
    {
        TableComparisonResult result;
        result.columns = combinedColumns(earlier, later);
        result.ignoredSourceColumns = ignoredOriginalColumnIndexes;

        const QVector<int> keyColumns = usableStableKeyColumns(
            earlier,
            later,
            keyColumnIndexes,
            result.ignoredSourceColumns);
        QHash<QString, int> earlierRowsByKey;
        QHash<QString, int> laterRowsByKey;
        const bool canUseStableKeys = !keyColumns.isEmpty() &&
            buildUniqueRowKeys(earlier, keyColumns, earlierRowsByKey) &&
            buildUniqueRowKeys(later, keyColumns, laterRowsByKey);

        const auto appendRow = [&result](
            const TableSnapshot& snapshot,
            const TableSnapshotRow& row,
            const TableComparisonSource source,
            QSet<int> changedSourceColumns = QSet<int>())
            {
                TableComparisonRow comparisonRow;
                comparisonRow.source = source;
                comparisonRow.values = outputValues(snapshot, row, result.columns);
                comparisonRow.changedSourceColumns = std::move(changedSourceColumns);
                result.rows.push_back(std::move(comparisonRow));
            };

        if (canUseStableKeys)
        {
            result.usesStableKeys = true;
            QSet<int> matchedLaterRows;
            for (int earlierIndex = 0; earlierIndex < earlier.rows.size(); ++earlierIndex)
            {
                const TableSnapshotRow& earlierRow = earlier.rows.at(earlierIndex);
                const QString key = rowKeySignature(earlier, earlierRow, keyColumns);
                const auto laterIterator = laterRowsByKey.constFind(key);
                if (laterIterator == laterRowsByKey.cend())
                {
                    appendRow(earlier, earlierRow, TableComparisonSource::EarlierOnly);
                    continue;
                }

                const int laterIndex = laterIterator.value();
                matchedLaterRows.insert(laterIndex);
                const TableSnapshotRow& laterRow = later.rows.at(laterIndex);
                QSet<int> changedColumns;
                for (const TableSnapshotColumn& column : result.columns)
                {
                    if (!result.ignoredSourceColumns.contains(column.sourceColumn) &&
                        valueForSourceColumn(earlier, earlierRow, column.sourceColumn) !=
                            valueForSourceColumn(later, laterRow, column.sourceColumn))
                    {
                        changedColumns.insert(column.sourceColumn);
                    }
                }
                appendRow(later, laterRow, TableComparisonSource::Both, std::move(changedColumns));
            }
            for (int laterIndex = 0; laterIndex < later.rows.size(); ++laterIndex)
            {
                if (!matchedLaterRows.contains(laterIndex))
                {
                    appendRow(later, later.rows.at(laterIndex), TableComparisonSource::LaterOnly);
                }
            }
            return result;
        }

        QHash<QString, QVector<int>> laterRowsBySignature;
        laterRowsBySignature.reserve(later.rows.size());
        for (int laterIndex = 0; laterIndex < later.rows.size(); ++laterIndex)
        {
            const QString signature = rowSignature(
                later,
                later.rows.at(laterIndex),
                result.columns,
                result.ignoredSourceColumns);
            laterRowsBySignature[signature].push_back(laterIndex);
        }

        QHash<QString, int> matchedPerSignature;
        QSet<int> matchedLaterRows;
        for (const TableSnapshotRow& earlierRow : earlier.rows)
        {
            const QString signature = rowSignature(
                earlier,
                earlierRow,
                result.columns,
                result.ignoredSourceColumns);
            const QVector<int> matches = laterRowsBySignature.value(signature);
            const int matchOffset = matchedPerSignature.value(signature);
            if (matchOffset < matches.size())
            {
                const int laterIndex = matches.at(matchOffset);
                matchedPerSignature.insert(signature, matchOffset + 1);
                matchedLaterRows.insert(laterIndex);
                appendRow(earlier, earlierRow, TableComparisonSource::Both);
            }
            else
            {
                appendRow(earlier, earlierRow, TableComparisonSource::EarlierOnly);
            }
        }
        for (int laterIndex = 0; laterIndex < later.rows.size(); ++laterIndex)
        {
            if (!matchedLaterRows.contains(laterIndex))
            {
                appendRow(later, later.rows.at(laterIndex), TableComparisonSource::LaterOnly);
            }
        }
        return result;
    }

    QString TableSnapshotCompareEngine::snapshotLabelForOrdinal(quint64 ordinal)
    {
        QString label;
        quint64 current = ordinal + 1;
        while (current > 0)
        {
            const quint64 remainder = (current - 1) % 26;
            label.prepend(QChar(QLatin1Char('A').unicode() + static_cast<ushort>(remainder)));
            current = (current - 1) / 26;
        }
        return label;
    }

    TableComparisonModel::TableComparisonModel(QObject* parent)
        : QAbstractTableModel(parent)
    {
    }

    TableComparisonModel::TableComparisonModel(TableComparisonResult comparison, QObject* parent)
        : QAbstractTableModel(parent)
        , m_comparison(std::move(comparison))
    {
        rebuildVisibleRows();
    }

    void TableComparisonModel::setComparison(TableComparisonResult comparison)
    {
        beginResetModel();
        m_comparison = std::move(comparison);
        rebuildVisibleRows();
        endResetModel();
    }

    const TableComparisonResult& TableComparisonModel::comparison() const
    {
        return m_comparison;
    }

    void TableComparisonModel::setShowDifferencesOnly(const bool enabled)
    {
        if (m_showDifferencesOnly == enabled)
        {
            return;
        }
        beginResetModel();
        m_showDifferencesOnly = enabled;
        rebuildVisibleRows();
        endResetModel();
    }

    bool TableComparisonModel::showDifferencesOnly() const
    {
        return m_showDifferencesOnly;
    }

    int TableComparisonModel::rowCount(const QModelIndex& parent) const
    {
        return parent.isValid() ? 0 : m_visibleRows.size();
    }

    int TableComparisonModel::columnCount(const QModelIndex& parent) const
    {
        return parent.isValid() ? 0 : m_comparison.columns.size() + 1;
    }

    QVariant TableComparisonModel::data(const QModelIndex& index, const int role) const
    {
        if (!index.isValid() || index.row() < 0 || index.row() >= m_visibleRows.size())
        {
            return {};
        }

        const TableComparisonRow& row = m_comparison.rows.at(m_visibleRows.at(index.row()));
        if (role == Qt::DisplayRole)
        {
            if (index.column() == 0)
            {
                switch (row.source)
                {
                case TableComparisonSource::EarlierOnly:
                    return QStringLiteral("A");
                case TableComparisonSource::LaterOnly:
                    return QStringLiteral("B");
                case TableComparisonSource::Both:
                    return QStringLiteral("AB");
                }
            }

            const int valueIndex = index.column() - 1;
            return valueIndex >= 0 && valueIndex < row.values.size() ? row.values.at(valueIndex) : QVariant();
        }

        if (role == Qt::BackgroundRole)
        {
            if (row.source == TableComparisonSource::EarlierOnly)
            {
                return earlierOnlyColor();
            }
            if (row.source == TableComparisonSource::LaterOnly)
            {
                return laterOnlyColor();
            }
            if (index.column() > 0)
            {
                const int sourceIndex = index.column() - 1;
                if (sourceIndex >= 0 && sourceIndex < m_comparison.columns.size() &&
                    row.changedSourceColumns.contains(m_comparison.columns.at(sourceIndex).sourceColumn))
                {
                    return changedFieldColor();
                }
            }
        }
        return {};
    }

    QVariant TableComparisonModel::headerData(
        const int section,
        const Qt::Orientation orientation,
        const int role) const
    {
        if (orientation != Qt::Horizontal || role != Qt::DisplayRole || section < 0)
        {
            return {};
        }
        if (section == 0)
        {
            return ks::i18n::sourceText(QStringLiteral("来源"));
        }

        const int columnIndex = section - 1;
        return columnIndex >= 0 && columnIndex < m_comparison.columns.size()
            ? QVariant(ks::i18n::displayText(m_comparison.columns.at(columnIndex).headerText))
            : QVariant();
    }

    Qt::ItemFlags TableComparisonModel::flags(const QModelIndex& index) const
    {
        return index.isValid() ? (Qt::ItemIsEnabled | Qt::ItemIsSelectable) : Qt::NoItemFlags;
    }

    void TableComparisonModel::rebuildVisibleRows()
    {
        m_visibleRows.clear();
        m_visibleRows.reserve(m_comparison.rows.size());
        for (int rowIndex = 0; rowIndex < m_comparison.rows.size(); ++rowIndex)
        {
            const TableComparisonRow& row = m_comparison.rows.at(rowIndex);
            if (!m_showDifferencesOnly || row.source != TableComparisonSource::Both ||
                !row.changedSourceColumns.isEmpty())
            {
                m_visibleRows.push_back(rowIndex);
            }
        }
    }
}
