#pragma once

#include "../ArkDriverClient/ArkDriverTypes.h"

#include <QWidget>

#include <mutex>
#include <thread>

class QEvent;
class QLabel;
class QLineEdit;
class QPushButton;
class QShowEvent;
class QTableWidget;

// HardwareI8042AuditPage：
// - 只调用专用 i8042prt 审计协议，不拼接全局 CallbackEnum 或回放内部 IOCTL；
// - 所有版本都显示公开 I/O 管理器设备枚举，精确描述符仅控制私有扩展读取；
// - 只展示端点指针与归属，不读取按键、扫描码、鼠标移动或 HID 报告。
class HardwareI8042AuditPage final : public QWidget
{
public:
    explicit HardwareI8042AuditPage(QWidget* parent = nullptr);
    ~HardwareI8042AuditPage() override;

protected:
    void changeEvent(QEvent* event) override;
    void showEvent(QShowEvent* event) override;

private:
    void initializeUi();
    void retranslateUi();
    void refreshAsync();
    void applyResult(ksword::ark::I8042AuditResult result);
    void renderResult(const ksword::ark::I8042AuditResult& result);
    void appendEntry(const KSWORD_ARK_I8042_AUDIT_ENTRY& entry);
    void setColumnGroup(int groupIndex);
    void applyColumnGroup();
    void updateColumnGroupButtons();
    void applyFilter();

    static QString fixedWide(const wchar_t* text, int capacity);
    static QString addressText(std::uint64_t address);
    static QString deviceKindText(std::uint32_t value);
    static QString endpointText(std::uint32_t value);
    static QString yesNoText(bool value, bool present);
    static QString verdictText(std::uint32_t value);
    static QString statusText(std::uint32_t value, std::int32_t lastStatus);
    static QString detailText(const KSWORD_ARK_I8042_AUDIT_ENTRY& entry);

    QPushButton* m_refreshButton = nullptr;
    QPushButton* m_columnGroupAButton = nullptr;
    QPushButton* m_columnGroupBButton = nullptr;
    QPushButton* m_columnGroupCButton = nullptr;
    QLineEdit* m_filterEdit = nullptr;
    QLabel* m_statusLabel = nullptr;
    QTableWidget* m_table = nullptr;
    std::thread m_refreshThread;
    std::mutex m_refreshMutex;
    bool m_closing = false;
    bool m_firstRefreshStarted = false;
    bool m_refreshRunning = false;
    bool m_hasResult = false;
    int m_columnGroupIndex = 0;
    ksword::ark::I8042AuditResult m_lastResult;
};
