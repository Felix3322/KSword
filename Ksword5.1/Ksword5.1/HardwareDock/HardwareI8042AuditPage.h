#pragma once

#include "../ArkDriverClient/ArkDriverTypes.h"

#include <QWidget>

#include <vector>

class QComboBox;
class QLabel;
class QLineEdit;
class QPushButton;
class QShowEvent;
class QTableWidget;

// HardwareI8042AuditPage：
// - 组合现有 DriverObject、InputStack 与 CallbackEnum 只读协议；
// - 展示 i8042prt 及其键鼠类/HID 邻接驱动，不引入任何私有对象偏移；
// - 本页不读取按键、扫描码、鼠标移动或输入报告。
class HardwareI8042AuditPage final : public QWidget
{
public:
    explicit HardwareI8042AuditPage(QWidget* parent = nullptr);
    ~HardwareI8042AuditPage() override = default;

protected:
    void showEvent(QShowEvent* event) override;

private:
    struct Snapshot
    {
        std::vector<ksword::ark::DriverObjectQueryResult> drivers;
        ksword::ark::DeviceAuditResult inputStack;
        ksword::ark::CallbackEnumResult callbacks;
    };

    void initializeUi();
    void refreshAsync();
    void applySnapshot(Snapshot snapshot);
    void appendDriverRows(const ksword::ark::DriverObjectQueryResult& result);
    void appendInputRows(const ksword::ark::DeviceAuditResult& result);
    void appendCallbackRows(const ksword::ark::CallbackEnumResult& result);
    void appendRow(const QStringList& cells);
    void applyColumnGroup();
    void applyFilter();

    static QString addressText(std::uint64_t address);
    static QString majorFunctionText(std::uint32_t majorFunction);
    static QString fixedWide(const wchar_t* text, int capacity);

    QPushButton* m_refreshButton = nullptr;
    QComboBox* m_columnGroupCombo = nullptr;
    QLineEdit* m_filterEdit = nullptr;
    QLabel* m_statusLabel = nullptr;
    QTableWidget* m_table = nullptr;
    bool m_firstRefreshStarted = false;
    bool m_refreshRunning = false;
};
