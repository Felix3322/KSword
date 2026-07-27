#pragma once

#include <QStringList>
#include <QVector>
#include <QWidget>

#include <cstdint>

class QLabel;
class QLineEdit;
class QPoint;
class QPushButton;
class QShowEvent;
class QTableWidget;

// WindowGlobalHotkeyTab：只读汇总全部进程可由 R3 读取的热键。
class WindowGlobalHotkeyTab final : public QWidget
{
public:
    explicit WindowGlobalHotkeyTab(QWidget* parent = nullptr);
    ~WindowGlobalHotkeyTab() override = default;

protected:
    void showEvent(QShowEvent* event) override;

private:
    void initializeUi();
    void refreshAsync();
    void appendSnapshotRows(
        std::uint64_t ticket,
        QVector<QStringList> rows,
        std::uint32_t completedProcessCount,
        std::uint32_t totalProcessCount,
        const QString& processName,
        bool hasDiagnostic);
    void finishRefresh(std::uint64_t ticket, qint64 elapsedMs);
    void rebuildTable();
    void showCopyMenu(const QPoint& position);
    static QString rowClipboardText(QTableWidget* table, int row, bool includeHeader);

    QLineEdit* m_filterEdit = nullptr;
    QPushButton* m_refreshButton = nullptr;
    QLabel* m_statusLabel = nullptr;
    QTableWidget* m_table = nullptr;
    QVector<QStringList> m_rows;
    bool m_refreshing = false;
    bool m_firstRefreshStarted = false;
    std::uint64_t m_refreshTicket = 0;
    std::uint32_t m_scannedProcessCount = 0;
    std::uint32_t m_totalProcessCount = 0;
    std::uint32_t m_diagnosticProcessCount = 0;
    int m_progressTaskId = 0;
};
