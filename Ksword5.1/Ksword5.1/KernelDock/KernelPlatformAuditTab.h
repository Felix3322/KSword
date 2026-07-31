#pragma once

#include "../ArkDriverClient/ArkDriverTypes.h"

#include <QWidget>

#include <mutex>
#include <thread>
#include <vector>

class QEvent;
class QLabel;
class QLineEdit;
class QPushButton;
class QShowEvent;
class QTabWidget;
class QTableWidget;

// KernelPlatformAuditTab：
// - Hal 模式提供四个明确的 HAL 子表；
// - Wdf 模式提供 KMDF 函数表和本驱动回调表；
// - 所有数据都来自 ArkDriverClient 的只读、失败关闭协议。
class KernelPlatformAuditTab final : public QWidget
{
public:
    enum class Mode
    {
        Hal,
        Wdf
    };

    explicit KernelPlatformAuditTab(Mode mode, QWidget* parent = nullptr);
    ~KernelPlatformAuditTab() override;

protected:
    void changeEvent(QEvent* event) override;
    void showEvent(QShowEvent* event) override;

private:
    struct Page
    {
        unsigned long scope = 0;
        QTableWidget* table = nullptr;
    };

    void initializeUi();
    void retranslateUi();
    void addPage(unsigned long scope, const QString& title);
    void refreshAsync();
    void applyResult(ksword::ark::PlatformAuditResult result);
    void populatePage(Page& page, const ksword::ark::PlatformAuditResult& result);
    void setColumnGroup(int groupIndex);
    void applyColumnGroup();
    void updateColumnGroupButtons();
    void applyFilter();

    static QString fixedWide(const wchar_t* text, int capacity);
    static QString addressText(unsigned long long address);
    static QString statusText(unsigned long status, long lastStatus);
    static QString hookText(unsigned long hookStatus);
    static QString signatureText(unsigned long signatureId);
    static QString detailText(const KSWORD_ARK_PLATFORM_AUDIT_ENTRY& entry);
    static QString companyNameForModule(const QString& modulePath);

    Mode m_mode;
    QTabWidget* m_innerTabs = nullptr;
    QPushButton* m_refreshButton = nullptr;
    QPushButton* m_columnGroupAButton = nullptr;
    QPushButton* m_columnGroupBButton = nullptr;
    QPushButton* m_columnGroupCButton = nullptr;
    QLineEdit* m_filterEdit = nullptr;
    QLabel* m_statusLabel = nullptr;
    std::vector<Page> m_pages;
    ksword::ark::PlatformAuditResult m_lastResult;
    std::thread m_refreshThread;
    std::mutex m_refreshMutex;
    bool m_closing = false;
    bool m_firstRefreshStarted = false;
    bool m_refreshRunning = false;
    bool m_hasResult = false;
    int m_columnGroupIndex = 0;
};
