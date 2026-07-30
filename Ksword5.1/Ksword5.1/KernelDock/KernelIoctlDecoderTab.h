#pragma once

#include <QWidget>

#include <cstdint>

class QLabel;
class QLineEdit;
class KernelIoctlBitLayoutWidget;

// KernelIoctlDecoderTab：
// - 作用：把 32 位 Windows IOCTL 控制码拆解为 Device、Function、Access 和 Method；
// - 调用：作为 KernelDock“I/O 管理”页的 IOCTLS 子页直接创建；
// - 输入输出：用户输入十六进制控制码，页面同步输出字段值与 CTL_CODE 位布局。
class KernelIoctlDecoderTab final : public QWidget
{
public:
    // 构造函数：
    // - 输入 parent：Qt 父控件；
    // - 处理：创建十六进制输入、只读解析字段和位布局图；
    // - 返回：无显式返回值，构造完成后控件可直接加入 QTabWidget。
    explicit KernelIoctlDecoderTab(QWidget* parent = nullptr);
    ~KernelIoctlDecoderTab() override = default;

private:
    // initializeUi：
    // - 输入：无；
    // - 处理：按参考图建立左侧字段表单和右侧 CTL_CODE 位布局；
    // - 返回：无。
    void initializeUi();

    // updateDecodedFields：
    // - 输入 inputText：允许带 0x 前缀的 1 至 8 位十六进制文本；
    // - 处理：校验并拆解四个 CTL_CODE 字段，同时刷新状态和位布局；
    // - 返回：无。
    void updateDecodedFields(const QString& inputText);

    // normalizeInput：
    // - 输入：读取当前输入框；
    // - 处理：编辑完成时把合法值统一格式化为 0x 加八位大写十六进制；
    // - 返回：无。
    void normalizeInput();

    // formatNumericField：
    // - 输入 value：字段数值，hexWidth：十六进制显示宽度；
    // - 处理：同时生成十六进制与十进制文本；
    // - 返回：适合只读字段显示的字符串。
    static QString formatNumericField(std::uint32_t value, int hexWidth);

    // accessName：
    // - 输入 accessValue：CTL_CODE 的两位 Access 值；
    // - 返回：对应 FILE_*_ACCESS 常量名。
    static QString accessName(std::uint32_t accessValue);

    // methodName：
    // - 输入 methodValue：CTL_CODE 的两位 Method 值；
    // - 返回：对应 METHOD_* 常量名。
    static QString methodName(std::uint32_t methodValue);

    QLineEdit* m_codeEdit = nullptr;         // m_codeEdit：用户输入的 32 位十六进制 IOCTL。
    QLineEdit* m_deviceEdit = nullptr;       // m_deviceEdit：DeviceType 位段解析结果。
    QLineEdit* m_functionEdit = nullptr;     // m_functionEdit：Function 位段解析结果。
    QLineEdit* m_accessEdit = nullptr;       // m_accessEdit：Access 位段及常量名。
    QLineEdit* m_methodEdit = nullptr;       // m_methodEdit：Method 位段及常量名。
    QLabel* m_statusLabel = nullptr;         // m_statusLabel：输入状态与 Common/Custom 位提示。
    KernelIoctlBitLayoutWidget* m_bitLayoutWidget = nullptr; // m_bitLayoutWidget：CTL_CODE 位布局图。
};
