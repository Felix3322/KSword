#include "WindowGlobalHotkeyTab.h"

#include "../Framework.h"
#include "../Internationalization/LanguageManager.h"
#include "../ProcessDock/ProcessHotkeyEnumerator.h"
#include "../UI/TableInteractionSupport.h"
#include "../UI/VisibleTableWidget.h"
#include "../ksword/process/process.h"
#include "../theme.h"

#include <QAbstractItemView>
#include <QAction>
#include <QApplication>
#include <QClipboard>
#include <QHeaderView>
#include <QHBoxLayout>
#include <QIcon>
#include <QLabel>
#include <QLineEdit>
#include <QMenu>
#include <QMetaObject>
#include <QPointer>
#include <QPushButton>
#include <QShowEvent>
#include <QTableWidget>
#include <QTableWidgetItem>
#include <QVBoxLayout>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <string>
#include <thread>
#include <unordered_set>
#include <utility>
#include <vector>

namespace
{
    enum AllHotkeyColumn : int
    {
        ColumnHotkey = 0,
        ColumnProcess,
        ColumnPid,
        ColumnTid,
        ColumnSource,
        ColumnHotkeyId,
        ColumnVkModifiers,
        ColumnObject,
        ColumnDetail,
        ColumnCount
    };

    QString allHotkeyText(const char* contextKey, const QString& sourceText)
    {
        return ks::i18n::contextText(QString::fromLatin1(contextKey), sourceText);
    }

    QString hex32(const std::uint32_t value, const int width = 0)
    {
        return QStringLiteral("0x%1")
            .arg(value, width, 16, QLatin1Char('0'))
            .toUpper();
    }

    QVector<QStringList> formatRows(const std::vector<ks::process::UserModeHotkeyRecord>& records)
    {
        QVector<QStringList> rows;
        rows.reserve(static_cast<qsizetype>(records.size()));
        for (const ks::process::UserModeHotkeyRecord& record : records)
        {
            rows.push_back(QStringList{
                record.hotkeyText,
                record.processName,
                QString::number(record.processId),
                record.threadId == 0U ? QStringLiteral("-") : QString::number(record.threadId),
                record.sourceText,
                record.hotkeyId == 0U ? QStringLiteral("0") : hex32(record.hotkeyId),
                QStringLiteral("VK=0x%1 MOD=0x%2")
                    .arg(record.virtualKey, 2, 16, QLatin1Char('0'))
                    .arg(record.modifiers, 4, 16, QLatin1Char('0'))
                    .toUpper(),
                record.objectText,
                record.detailText });
        }
        return rows;
    }

    std::vector<ks::process::UserModeHotkeyProcessTarget> collectProcessTargets()
    {
        const std::vector<ks::process::ProcessRecord> processRecords =
            ks::process::EnumerateProcesses(ks::process::ProcessEnumStrategy::Auto);

        std::unordered_set<std::uint32_t> processIds;
        std::vector<ks::process::UserModeHotkeyProcessTarget> targets;
        targets.reserve(processRecords.size());
        for (const ks::process::ProcessRecord& processRecord : processRecords)
        {
            if (processRecord.pid == 0U || !processIds.insert(processRecord.pid).second)
            {
                continue;
            }

            targets.push_back(ks::process::UserModeHotkeyProcessTarget{
                processRecord.pid,
                QString::fromStdString(processRecord.processName),
                QString::fromStdString(processRecord.imagePath) });
        }
        return targets;
    }

    QTableWidgetItem* readOnlyItem(const QString& text)
    {
        auto* item = new QTableWidgetItem(text);
        item->setFlags(item->flags() & ~Qt::ItemIsEditable);
        item->setToolTip(text);
        return item;
    }
}

WindowGlobalHotkeyTab::WindowGlobalHotkeyTab(QWidget* parent)
    : QWidget(parent)
{
    initializeUi();
}

void WindowGlobalHotkeyTab::showEvent(QShowEvent* event)
{
    QWidget::showEvent(event);
    if (!m_firstRefreshStarted)
    {
        m_firstRefreshStarted = true;
        QMetaObject::invokeMethod(this, [this]() { refreshAsync(); }, Qt::QueuedConnection);
    }
}

void WindowGlobalHotkeyTab::initializeUi()
{
    auto* rootLayout = new QVBoxLayout(this);
    rootLayout->setContentsMargins(6, 6, 6, 6);
    rootLayout->setSpacing(5);

    auto* toolbar = new QHBoxLayout();
    m_refreshButton = new QPushButton(
        allHotkeyText("window.global_hotkey.refresh", QStringLiteral("刷新全部热键")),
        this);
    m_refreshButton->setStyleSheet(KswordTheme::ThemedButtonStyle());
    m_filterEdit = new QLineEdit(this);
    m_filterEdit->setClearButtonEnabled(true);
    m_filterEdit->setPlaceholderText(allHotkeyText(
        "window.global_hotkey.filter.placeholder",
        QStringLiteral("按热键、进程、PID/TID、来源、对象或详情筛选")));
    toolbar->addWidget(m_refreshButton);
    toolbar->addWidget(m_filterEdit, 1);
    rootLayout->addLayout(toolbar);

    m_statusLabel = new QLabel(
        allHotkeyText("window.global_hotkey.summary.waiting", QStringLiteral("状态：等待刷新")),
        this);
    m_statusLabel->setWordWrap(true);
    m_statusLabel->setStyleSheet(QStringLiteral("color:%1;font-weight:600;").arg(KswordTheme::TextSecondaryHex()));
    rootLayout->addWidget(m_statusLabel);

    m_table = new ks::ui::VisibleTableWidget(this);
    m_table->setColumnCount(ColumnCount);
    m_table->setHorizontalHeaderLabels({
        allHotkeyText("window.global_hotkey.header.hotkey", QStringLiteral("热键")),
        allHotkeyText("window.global_hotkey.header.process", QStringLiteral("进程")),
        allHotkeyText("window.global_hotkey.header.pid", QStringLiteral("PID")),
        allHotkeyText("window.global_hotkey.header.tid", QStringLiteral("TID")),
        allHotkeyText("window.global_hotkey.header.source", QStringLiteral("来源")),
        allHotkeyText("window.global_hotkey.header.id", QStringLiteral("热键 ID")),
        allHotkeyText("window.global_hotkey.header.vk_mod", QStringLiteral("VK / Mod")),
        allHotkeyText("window.global_hotkey.header.object", QStringLiteral("热键对象")),
        allHotkeyText("window.global_hotkey.header.detail", QStringLiteral("详情")) });
    m_table->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_table->setSelectionMode(QAbstractItemView::ExtendedSelection);
    m_table->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_table->setAlternatingRowColors(true);
    m_table->setSortingEnabled(true);
    m_table->setContextMenuPolicy(Qt::CustomContextMenu);
    m_table->verticalHeader()->setVisible(false);
    m_table->horizontalHeader()->setSectionResizeMode(QHeaderView::Interactive);
    m_table->horizontalHeader()->setStretchLastSection(true);
    m_table->setStyleSheet(QStringLiteral(
        "QTableWidget{background:transparent;color:%1;}"
        "QHeaderView::section{color:%2;background:transparent;border:1px solid %3;font-weight:600;}")
        .arg(KswordTheme::TextPrimaryHex())
        .arg(KswordTheme::PrimaryBlueHex)
        .arg(KswordTheme::BorderHex()));
    rootLayout->addWidget(m_table, 1);

    connect(m_refreshButton, &QPushButton::clicked, this, [this]() { refreshAsync(); });
    connect(m_filterEdit, &QLineEdit::textChanged, this, [this](const QString&) { rebuildTable(); });
    connect(m_table, &QTableWidget::customContextMenuRequested, this, [this](const QPoint& position) { showCopyMenu(position); });
}

void WindowGlobalHotkeyTab::refreshAsync()
{
    if (m_refreshing)
    {
        return;
    }

    m_refreshing = true;
    m_firstRefreshStarted = true;
    const std::uint64_t ticket = ++m_refreshTicket;
    m_rows.clear();
    m_scannedProcessCount = 0U;
    m_totalProcessCount = 0U;
    m_diagnosticProcessCount = 0U;
    m_refreshButton->setEnabled(false);
    m_statusLabel->setText(allHotkeyText(
        "window.global_hotkey.summary.refreshing",
        QStringLiteral("状态：正在扫描全部进程的热键...")));
    rebuildTable();

    m_progressTaskId = kPro.add(
        allHotkeyText("window.global_hotkey.tab", QStringLiteral("全部热键")).toStdString(),
        allHotkeyText(
            "window.global_hotkey.progress.enumerating",
            QStringLiteral("正在枚举进程")).toStdString());
    kPro.set(m_progressTaskId, allHotkeyText(
        "window.global_hotkey.progress.enumerating",
        QStringLiteral("正在枚举进程")).toStdString(), 0, 0.0f);

    QPointer<WindowGlobalHotkeyTab> safeThis(this);
    std::thread([safeThis, ticket]()
    {
        const auto beginTime = std::chrono::steady_clock::now();
        const std::vector<ks::process::UserModeHotkeyProcessTarget> targets = collectProcessTargets();
        if (safeThis == nullptr)
        {
            return;
        }

        const std::uint32_t totalProcessCount = static_cast<std::uint32_t>(targets.size());
        QMetaObject::invokeMethod(safeThis, [safeThis, ticket, totalProcessCount]()
        {
            if (safeThis == nullptr || safeThis->m_refreshTicket != ticket)
            {
                return;
            }

            safeThis->m_totalProcessCount = totalProcessCount;
            safeThis->m_statusLabel->setText(allHotkeyText(
                "window.global_hotkey.summary.indexing_shortcuts",
                QStringLiteral("状态：已找到 %1 个进程，正在读取快捷方式索引...")).arg(totalProcessCount));
            if (safeThis->m_progressTaskId != 0)
            {
                kPro.set(
                    safeThis->m_progressTaskId,
                    allHotkeyText(
                        "window.global_hotkey.progress.indexing_shortcuts",
                        QStringLiteral("正在读取快捷方式索引")).toStdString(),
                    0,
                    0.0f);
            }
        }, Qt::QueuedConnection);

        ks::process::EnumerateUserModeHotkeysForProcesses(
            targets,
            [safeThis, ticket](ks::process::UserModeHotkeyBatchProgress progress)
            {
                if (safeThis == nullptr)
                {
                    return;
                }

                const QVector<QStringList> rows = formatRows(progress.records);
                const bool hasDiagnostic = progress.diagnosticText.contains(QLatin1Char('|'));
                QMetaObject::invokeMethod(
                    safeThis,
                    [safeThis,
                     ticket,
                     rows,
                     completedProcessCount = progress.completedProcessCount,
                     totalProcessCount = progress.totalProcessCount,
                     processName = std::move(progress.processName),
                     hasDiagnostic]() mutable
                    {
                        if (safeThis != nullptr)
                        {
                            safeThis->appendSnapshotRows(
                                ticket,
                                std::move(rows),
                                completedProcessCount,
                                totalProcessCount,
                                processName,
                                hasDiagnostic);
                        }
                    },
                    Qt::QueuedConnection);
            });

        const qint64 elapsedMs = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - beginTime).count();
        if (safeThis != nullptr)
        {
            QMetaObject::invokeMethod(safeThis, [safeThis, ticket, elapsedMs]()
            {
                if (safeThis != nullptr)
                {
                    safeThis->finishRefresh(ticket, elapsedMs);
                }
            }, Qt::QueuedConnection);
        }
    }).detach();
}

void WindowGlobalHotkeyTab::appendSnapshotRows(
    const std::uint64_t ticket,
    QVector<QStringList> rows,
    const std::uint32_t completedProcessCount,
    const std::uint32_t totalProcessCount,
    const QString& processName,
    const bool hasDiagnostic)
{
    if (ticket != m_refreshTicket || !m_refreshing)
    {
        return;
    }

    m_scannedProcessCount = std::max(m_scannedProcessCount, completedProcessCount);
    m_totalProcessCount = std::max(m_totalProcessCount, totalProcessCount);
    if (hasDiagnostic)
    {
        ++m_diagnosticProcessCount;
    }

    if (!rows.isEmpty())
    {
        m_rows += std::move(rows);
        rebuildTable();
    }

    const QString currentProcessName = processName.trimmed().isEmpty()
        ? allHotkeyText("window.global_hotkey.process.unknown", QStringLiteral("<未知进程>"))
        : processName;
    m_statusLabel->setText(allHotkeyText(
        "window.global_hotkey.summary.progress",
        QStringLiteral("状态：已扫描 %1 / %2 个进程，已发现 %3 条热键。"))
        .arg(m_scannedProcessCount)
        .arg(m_totalProcessCount)
        .arg(m_rows.size()));
    if (m_progressTaskId != 0)
    {
        const float progress = m_totalProcessCount == 0U
            ? 0.0f
            : static_cast<float>(m_scannedProcessCount) / static_cast<float>(m_totalProcessCount);
        kPro.set(
            m_progressTaskId,
            allHotkeyText(
                "window.global_hotkey.progress.scanning",
                QStringLiteral("正在扫描 %1（%2/%3）"))
                .arg(currentProcessName)
                .arg(m_scannedProcessCount)
                .arg(m_totalProcessCount)
                .toStdString(),
            static_cast<int>(m_scannedProcessCount),
            progress);
    }
}

void WindowGlobalHotkeyTab::finishRefresh(const std::uint64_t ticket, const qint64 elapsedMs)
{
    if (ticket != m_refreshTicket)
    {
        return;
    }

    m_refreshing = false;
    m_refreshButton->setEnabled(true);
    m_statusLabel->setText(allHotkeyText(
        "window.global_hotkey.summary.completed",
        QStringLiteral("状态：已扫描 %1 个进程，发现 %2 条热键，耗时 %3 ms。%4"))
        .arg(m_scannedProcessCount)
        .arg(m_rows.size())
        .arg(elapsedMs)
        .arg(m_diagnosticProcessCount == 0U
            ? QString()
            : allHotkeyText(
                "window.global_hotkey.summary.diagnostics",
                QStringLiteral("%1 个进程的扫描包含诊断信息。")).arg(m_diagnosticProcessCount)));

    const int progressTaskId = m_progressTaskId;
    m_progressTaskId = 0;
    if (progressTaskId != 0)
    {
        kPro.set(
            progressTaskId,
            allHotkeyText(
                "window.global_hotkey.progress.completed",
                QStringLiteral("全部热键扫描完成")).toStdString(),
            100,
            1.0f);
    }
}

void WindowGlobalHotkeyTab::rebuildTable()
{
    const QString keyword = m_filterEdit->text().trimmed();
    m_table->setSortingEnabled(false);
    m_table->setRowCount(0);
    for (const QStringList& sourceRow : m_rows)
    {
        if (sourceRow.size() < ColumnCount ||
            (!keyword.isEmpty() && !sourceRow.join(QLatin1Char(' ')).contains(keyword, Qt::CaseInsensitive)))
        {
            continue;
        }

        const int tableRow = m_table->rowCount();
        m_table->insertRow(tableRow);
        for (int column = 0; column < ColumnCount; ++column)
        {
            m_table->setItem(tableRow, column, readOnlyItem(sourceRow.at(column)));
        }
    }
    m_table->setSortingEnabled(true);
    m_table->resizeColumnsToContents();
}

QString WindowGlobalHotkeyTab::rowClipboardText(
    QTableWidget* table,
    const int row,
    const bool includeHeader)
{
    if (table == nullptr || row < 0 || row >= table->rowCount())
    {
        return {};
    }

    QStringList lines;
    if (includeHeader)
    {
        QStringList headers;
        for (int column = 0; column < table->columnCount(); ++column)
        {
            headers << (table->horizontalHeaderItem(column) == nullptr
                ? QString()
                : table->horizontalHeaderItem(column)->text());
        }
        lines << headers.join(QLatin1Char('\t'));
    }

    QStringList values;
    for (int column = 0; column < table->columnCount(); ++column)
    {
        values << (table->item(row, column) == nullptr ? QString() : table->item(row, column)->text());
    }
    lines << values.join(QLatin1Char('\t'));
    return lines.join(QLatin1Char('\n'));
}

void WindowGlobalHotkeyTab::showCopyMenu(const QPoint& position)
{
    const QModelIndex index = m_table->indexAt(position);
    const int row = index.isValid() ? index.row() : m_table->currentRow();
    QMenu menu(this);
    QAction* copyCell = menu.addAction(allHotkeyText("window.global_hotkey.copy.cell", QStringLiteral("复制单元格")));
    QAction* copyRow = menu.addAction(allHotkeyText("window.global_hotkey.copy.row", QStringLiteral("复制当前行")));
    QAction* copyAll = menu.addAction(allHotkeyText("window.global_hotkey.copy.all", QStringLiteral("复制全部行")));
    const QTableWidgetItem* processIdItem = row >= 0 ? m_table->item(row, ColumnPid) : nullptr;
    bool processIdOk = false;
    const quint32 processId = processIdItem != nullptr
        ? processIdItem->text().trimmed().toUInt(&processIdOk, 10)
        : 0U;
    QAction* openProcessAction = menu.addAction(
        QIcon(QStringLiteral(":/Icon/process_details.svg")),
        allHotkeyText("window.global_hotkey.open_process", QStringLiteral("转到进程详细信息")));
    copyCell->setEnabled(index.isValid());
    copyRow->setEnabled(row >= 0);
    copyAll->setEnabled(m_table->rowCount() > 0);
    openProcessAction->setEnabled(processIdOk && processId != 0U);

    QAction* selected = menu.exec(m_table->viewport()->mapToGlobal(position));
    if (selected == copyCell && index.isValid())
    {
        const QTableWidgetItem* item = m_table->item(index.row(), index.column());
        QApplication::clipboard()->setText(item == nullptr ? QString() : item->text());
    }
    else if (selected == copyRow)
    {
        QApplication::clipboard()->setText(rowClipboardText(m_table, row, true));
    }
    else if (selected == copyAll)
    {
        QStringList lines;
        for (int tableRow = 0; tableRow < m_table->rowCount(); ++tableRow)
        {
            lines << rowClipboardText(m_table, tableRow, tableRow == 0);
        }
        QApplication::clipboard()->setText(lines.join(QLatin1Char('\n')));
    }
    else if (selected == openProcessAction)
    {
        ks::ui::OpenProcessDetailByPid(processId);
    }
}
