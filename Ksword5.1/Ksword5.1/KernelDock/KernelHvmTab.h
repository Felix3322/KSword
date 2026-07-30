#pragma once

#include "../ArkDriverClient/ArkDriverTypes.h"

#include <QWidget>

#include <cstdint>

class QCheckBox;
class QLabel;
class QPushButton;
class QShowEvent;
class QTableWidget;
class QTextEdit;

// KernelHvmTab presents VT-x/EPT capability, reversible resource preparation,
// per-CPU VMXON/VMXOFF validation, and teardown without implying VMLAUNCH.
class KernelHvmTab final : public QWidget
{
public:
    explicit KernelHvmTab(QWidget* parent = nullptr);
    ~KernelHvmTab() override = default;

protected:
    void showEvent(QShowEvent* event) override;

private:
    void initializeUi();
    void refreshAsync();
    void applyStatus(ksword::ark::HvmStatusResult result);
    void runControlAsync(unsigned long command, bool force);
    void applyControl(
        unsigned long command,
        ksword::ark::HvmControlResult control,
        ksword::ark::HvmStatusResult status);
    void prepareBackend();
    void selfTestBackend();
    void teardownBackend();
    bool confirmTyped(const QString& warning, const QString& phrase);
    void updateButtons();
    QString buildDetail(
        const KSWORD_ARK_QUERY_HVM_RESPONSE& response) const;
    static QString featureText(std::uint64_t flags);
    static QString stateText(std::uint32_t flags);
    static QString ntStatusText(long status);
    static QString fixedAscii(const char* text, int capacity);

    QLabel* m_warningLabel = nullptr;
    QLabel* m_statusLabel = nullptr;
    QLabel* m_summaryLabel = nullptr;
    QPushButton* m_refreshButton = nullptr;
    QPushButton* m_prepareButton = nullptr;
    QPushButton* m_selfTestButton = nullptr;
    QPushButton* m_teardownButton = nullptr;
    QCheckBox* m_allowNestedCheck = nullptr;
    QTableWidget* m_cpuTable = nullptr;
    QTextEdit* m_detailEdit = nullptr;
    KSWORD_ARK_QUERY_HVM_RESPONSE m_snapshot{};
    bool m_firstRefreshStarted = false;
    bool m_operationRunning = false;
    bool m_supported = false;
};
