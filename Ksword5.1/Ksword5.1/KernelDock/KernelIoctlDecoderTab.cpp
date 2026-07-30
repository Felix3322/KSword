#include "KernelIoctlDecoderTab.h"

#include "KernelDock.h"
#include "../theme.h"

#include <QFormLayout>
#include <QGroupBox>
#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QPaintEvent>
#include <QPainter>
#include <QRegularExpression>
#include <QRegularExpressionValidator>
#include <QSignalBlocker>
#include <QVBoxLayout>

#include <array>

using ksword::kernel_dock_internal::kernelText;

// KernelIoctlBitLayoutWidget：
// - 作用：按 CTL_CODE 的 1/15/2/1/11/2 位分区绘制 Common、Device、Access、
//   Custom、Function、Method，与 issue 参考图的 32 位布局保持一致；
// - 输入输出：setCode 接收解析状态，paintEvent 只负责主题化只读展示。
class KernelIoctlBitLayoutWidget final : public QWidget
{
public:
    explicit KernelIoctlBitLayoutWidget(QWidget* parent = nullptr)
        : QWidget(parent)
    {
        setMinimumSize(560, 180);
        setToolTip(kernelText(
            "kernel.ioctl_decoder.layout.tooltip",
            QStringLiteral("CTL_CODE：Common[31]、Device[30:16]、Access[15:14]、Custom[13]、Function[12:2]、Method[1:0]")));
    }

    // setCode：
    // - 输入 codeValue：32 位控制码，valid：当前输入是否完整合法；
    // - 处理：缓存状态并请求重绘；
    // - 返回：无。
    void setCode(const std::uint32_t codeValue, const bool valid)
    {
        if (m_codeValue == codeValue && m_valid == valid)
        {
            return;
        }
        m_codeValue = codeValue;
        m_valid = valid;
        update();
    }

protected:
    // paintEvent：
    // - 输入 event：Qt 绘制事件，事件本身无需额外读取；
    // - 处理：绘制比例位段、当前值、图例以及 Common/Custom 标志；
    // - 返回：无。
    void paintEvent(QPaintEvent* event) override
    {
        Q_UNUSED(event);

        // painter 负责全部矢量绘制；启用抗锯齿避免缩放后边框发虚。
        QPainter painter(this);
        painter.setRenderHint(QPainter::Antialiasing, true);
        painter.fillRect(rect(), KswordTheme::SurfaceColor());

        // diagramRect 保留顶部位号和底部图例空间，中间矩形严格按位宽比例分配。
        const QRectF diagramRect = QRectF(rect()).adjusted(18.0, 34.0, -18.0, -86.0);
        if (diagramRect.width() <= 0.0 || diagramRect.height() <= 0.0)
        {
            return;
        }

        struct Segment
        {
            int highBit = 0;              // highBit：当前区段最高位。
            int lowBit = 0;               // lowBit：当前区段最低位。
            int bitCount = 0;             // bitCount：用于按 32 位总宽度分配像素。
            std::uint32_t value = 0U;     // value：从控制码提取的当前区段值。
            QString labelText;            // labelText：主题语言下的区段名称。
            QColor accentColor;           // accentColor：区分六个位段的主题强调色。
        };

        // segments 严格按参考图从 bit 31 排到 bit 0；Common/Custom 单列，
        // Device 与 Function 在图中展示其剩余位，而左侧表单仍展示 CTL_CODE 宏的完整字段。
        const std::array<Segment, 6> segments = {{
            { 31, 31, 1, (m_codeValue >> 31U) & 0x1U,
                kernelText("kernel.ioctl_decoder.flag.common", QStringLiteral("Common")),
                KswordTheme::AccentColor(KswordTheme::AccentRole::Red) },
            { 30, 16, 15, (m_codeValue >> 16U) & 0x7FFFU,
                kernelText("kernel.ioctl_decoder.field.device", QStringLiteral("Device")),
                KswordTheme::PrimaryAccentColor() },
            { 15, 14, 2, (m_codeValue >> 14U) & 0x3U,
                kernelText("kernel.ioctl_decoder.field.access", QStringLiteral("Access")),
                KswordTheme::AccentColor(KswordTheme::AccentRole::Green) },
            { 13, 13, 1, (m_codeValue >> 13U) & 0x1U,
                kernelText("kernel.ioctl_decoder.flag.custom", QStringLiteral("Custom")),
                KswordTheme::AccentColor(KswordTheme::AccentRole::Yellow) },
            { 12, 2, 11, (m_codeValue >> 2U) & 0x7FFU,
                kernelText("kernel.ioctl_decoder.field.function", QStringLiteral("Function")),
                KswordTheme::AccentColor(KswordTheme::AccentRole::Orange) },
            { 1, 0, 2, m_codeValue & 0x3U,
                kernelText("kernel.ioctl_decoder.field.method", QStringLiteral("Method")),
                KswordTheme::AccentColor(KswordTheme::AccentRole::Purple) }
        }};

        // valueFont 仅用于位段中的十六进制结果，窄区段仍保持紧凑可读。
        QFont valueFont = painter.font();
        valueFont.setBold(true);
        valueFont.setPointSizeF(qMax(8.0, valueFont.pointSizeF() - 1.0));
        painter.setFont(valueFont);

        qreal cursorX = diagramRect.left();
        for (std::size_t index = 0U; index < segments.size(); ++index)
        {
            const Segment& segment = segments[index];
            const qreal segmentWidth = index + 1U == segments.size()
                ? diagramRect.right() - cursorX
                : diagramRect.width() * static_cast<qreal>(segment.bitCount) / 32.0;
            const QRectF segmentRect(cursorX, diagramRect.top(), segmentWidth, diagramRect.height());

            // 无合法输入时保留结构图但降低填充强度，避免把零值误认为真实解析结果。
            const int fillAlpha = m_valid ? 64 : 24;
            painter.setPen(QPen(segment.accentColor, 1.5));
            painter.setBrush(KswordTheme::WithAlpha(segment.accentColor, fillAlpha));
            painter.drawRect(segmentRect);

            painter.setPen(KswordTheme::TextSecondaryColor());
            painter.drawText(
                QRectF(segmentRect.left(), diagramRect.top() - 25.0, segmentRect.width(), 20.0),
                Qt::AlignCenter,
                segment.highBit == segment.lowBit
                    ? QString::number(segment.highBit)
                    : QStringLiteral("%1:%2").arg(segment.highBit).arg(segment.lowBit));

            const int hexWidth = (segment.bitCount + 3) / 4;
            const QString valueText = m_valid
                ? (segment.bitCount == 1
                    ? QString::number(segment.value)
                    : QStringLiteral("0x%1")
                        .arg(segment.value, hexWidth, 16, QLatin1Char('0'))
                        .toUpper())
                : QStringLiteral("—");
            painter.setPen(KswordTheme::TextPrimaryColor());
            painter.drawText(segmentRect.adjusted(3.0, 3.0, -3.0, -3.0), Qt::AlignCenter, valueText);
            cursorX += segmentWidth;
        }

        // 图例使用等宽六列，不受 Common/Custom 只有一位造成的窄区段限制。
        const qreal legendTop = diagramRect.bottom() + 12.0;
        const qreal legendWidth = diagramRect.width() / static_cast<qreal>(segments.size());
        QFont legendFont = painter.font();
        legendFont.setBold(false);
        painter.setFont(legendFont);
        for (std::size_t index = 0U; index < segments.size(); ++index)
        {
            const Segment& segment = segments[index];
            const QRectF legendRect(
                diagramRect.left() + legendWidth * static_cast<qreal>(index),
                legendTop,
                legendWidth,
                22.0);
            painter.fillRect(
                QRectF(legendRect.left() + 4.0, legendRect.top() + 6.0, 10.0, 10.0),
                segment.accentColor);
            painter.setPen(KswordTheme::TextPrimaryColor());
            painter.drawText(
                legendRect.adjusted(18.0, 0.0, -2.0, 0.0),
                Qt::AlignVCenter | Qt::AlignLeft,
                QStringLiteral("%1 [%2:%3]")
                    .arg(segment.labelText)
                    .arg(segment.highBit)
                    .arg(segment.lowBit));
        }

        // Common 是 bit 31，Custom 是 bit 13；二者分别位于 Device 和 Function 字段最高位。
        const QString commonText = kernelText("kernel.ioctl_decoder.flag.common", QStringLiteral("Common"));
        const QString customText = kernelText("kernel.ioctl_decoder.flag.custom", QStringLiteral("Custom"));
        const QString flagText = m_valid
            ? QStringLiteral("%1(bit 31)=%2    %3(bit 13)=%4")
                .arg(commonText)
                .arg((m_codeValue >> 31U) & 0x1U)
                .arg(customText)
                .arg((m_codeValue >> 13U) & 0x1U)
            : QStringLiteral("%1(bit 31)=—    %2(bit 13)=—").arg(commonText, customText);
        painter.setPen(KswordTheme::TextSecondaryColor());
        painter.drawText(
            QRectF(diagramRect.left(), legendTop + 26.0, diagramRect.width(), 22.0),
            Qt::AlignCenter,
            flagText);
    }

private:
    std::uint32_t m_codeValue = 0U; // m_codeValue：最近一次合法或清空后的 32 位控制码。
    bool m_valid = false;           // m_valid：决定是否展示字段值，false 时仅展示结构占位。
};

KernelIoctlDecoderTab::KernelIoctlDecoderTab(QWidget* parent)
    : QWidget(parent)
{
    initializeUi();
}

void KernelIoctlDecoderTab::initializeUi()
{
    // rootLayout 管理说明、左右两栏和状态提示，页面本身不执行任何内核调用。
    auto* rootLayout = new QVBoxLayout(this);
    rootLayout->setContentsMargins(12, 12, 12, 12);
    rootLayout->setSpacing(10);

    auto* descriptionLabel = new QLabel(
        kernelText(
            "kernel.ioctl_decoder.description",
            QStringLiteral("输入 32 位 IOCTL 控制码，实时解析 CTL_CODE 字段并显示位布局。")),
        this);
    descriptionLabel->setWordWrap(true);
    descriptionLabel->setStyleSheet(
        QStringLiteral("color:%1;font-size:13px;").arg(KswordTheme::TextSecondaryHex()));
    rootLayout->addWidget(descriptionLabel);

    // contentLayout 将字段表单和位布局并排，布局比例与 issue 参考图保持一致。
    auto* contentLayout = new QHBoxLayout();
    contentLayout->setSpacing(12);
    auto* decoderGroup = new QGroupBox(
        kernelText("kernel.ioctl_decoder.group.fields", QStringLiteral("控制码字段")),
        this);
    auto* fieldLayout = new QFormLayout(decoderGroup);
    fieldLayout->setContentsMargins(14, 16, 14, 14);
    fieldLayout->setHorizontalSpacing(10);
    fieldLayout->setVerticalSpacing(10);
    fieldLayout->setLabelAlignment(Qt::AlignRight | Qt::AlignVCenter);

    // createOutputEdit 统一生成不可编辑结果框，避免四个字段出现不一致的主题状态。
    const auto createOutputEdit = [decoderGroup]() -> QLineEdit*
    {
        auto* outputEdit = new QLineEdit(decoderGroup);
        outputEdit->setReadOnly(true);
        outputEdit->setText(QStringLiteral("—"));
        outputEdit->setStyleSheet(QStringLiteral(
            "QLineEdit{background:%1;color:%2;border:1px solid %3;border-radius:3px;padding:5px 8px;}")
            .arg(KswordTheme::SurfaceAltColorHex())
            .arg(KswordTheme::TextPrimaryColorHex())
            .arg(KswordTheme::BorderColorHex()));
        return outputEdit;
    };

    m_codeEdit = new QLineEdit(decoderGroup);
    m_codeEdit->setClearButtonEnabled(true);
    m_codeEdit->setMaxLength(10);
    m_codeEdit->setPlaceholderText(
        kernelText("kernel.ioctl_decoder.input.placeholder", QStringLiteral("例如：0x222004")));
    m_codeEdit->setToolTip(
        kernelText("kernel.ioctl_decoder.input.tooltip", QStringLiteral("输入 0 到 FFFFFFFF，可选 0x 前缀")));
    m_codeEdit->setValidator(new QRegularExpressionValidator(
        QRegularExpression(QStringLiteral("^(?:0[xX])?[0-9A-Fa-f]{0,8}$")),
        m_codeEdit));
    m_deviceEdit = createOutputEdit();
    m_functionEdit = createOutputEdit();
    m_accessEdit = createOutputEdit();
    m_methodEdit = createOutputEdit();

    fieldLayout->addRow(
        kernelText("kernel.ioctl_decoder.input.label", QStringLiteral("IOCTL（十六进制）：")),
        m_codeEdit);
    fieldLayout->addRow(
        kernelText("kernel.ioctl_decoder.form.device", QStringLiteral("Device：")),
        m_deviceEdit);
    fieldLayout->addRow(
        kernelText("kernel.ioctl_decoder.form.function", QStringLiteral("Function：")),
        m_functionEdit);
    fieldLayout->addRow(
        kernelText("kernel.ioctl_decoder.form.access", QStringLiteral("Access：")),
        m_accessEdit);
    fieldLayout->addRow(
        kernelText("kernel.ioctl_decoder.form.method", QStringLiteral("Method：")),
        m_methodEdit);

    auto* layoutGroup = new QGroupBox(
        kernelText("kernel.ioctl_decoder.group.layout", QStringLiteral("CTL_CODE 位布局")),
        this);
    auto* bitLayout = new QVBoxLayout(layoutGroup);
    bitLayout->setContentsMargins(8, 8, 8, 8);
    m_bitLayoutWidget = new KernelIoctlBitLayoutWidget(layoutGroup);
    bitLayout->addWidget(m_bitLayoutWidget, 1);

    contentLayout->addWidget(decoderGroup, 5);
    contentLayout->addWidget(layoutGroup, 7);
    rootLayout->addLayout(contentLayout, 1);

    m_statusLabel = new QLabel(
        kernelText("kernel.ioctl_decoder.status.empty", QStringLiteral("请输入 32 位 IOCTL 控制码。")),
        this);
    m_statusLabel->setStyleSheet(
        QStringLiteral("color:%1;font-weight:600;").arg(KswordTheme::TextSecondaryHex()));
    rootLayout->addWidget(m_statusLabel);

    // textChanged 提供实时解析，editingFinished 只负责规范化显示，不改变字段语义。
    connect(m_codeEdit, &QLineEdit::textChanged, this, [this](const QString& inputText)
    {
        updateDecodedFields(inputText);
    });
    connect(m_codeEdit, &QLineEdit::editingFinished, this, [this]()
    {
        normalizeInput();
    });
    updateDecodedFields(QString());
}

void KernelIoctlDecoderTab::updateDecodedFields(const QString& inputText)
{
    // normalizedText 去除前后空白与可选 0x 前缀，后续只按十六进制读取。
    QString normalizedText = inputText.trimmed();
    if (normalizedText.startsWith(QStringLiteral("0x"), Qt::CaseInsensitive))
    {
        normalizedText.remove(0, 2);
    }

    if (normalizedText.isEmpty())
    {
        m_deviceEdit->setText(QStringLiteral("—"));
        m_functionEdit->setText(QStringLiteral("—"));
        m_accessEdit->setText(QStringLiteral("—"));
        m_methodEdit->setText(QStringLiteral("—"));
        m_statusLabel->setText(
            kernelText("kernel.ioctl_decoder.status.empty", QStringLiteral("请输入 32 位 IOCTL 控制码。")));
        m_statusLabel->setStyleSheet(
            QStringLiteral("color:%1;font-weight:600;").arg(KswordTheme::TextSecondaryHex()));
        m_bitLayoutWidget->setCode(0U, false);
        return;
    }

    // parsedValue 使用 64 位临时量检测越界，最终合法值必须完全落在 32 位范围。
    bool parseOk = false;
    const qulonglong parsedValue = normalizedText.toULongLong(&parseOk, 16);
    if (!parseOk || normalizedText.size() > 8 || parsedValue > 0xFFFFFFFFULL)
    {
        m_deviceEdit->setText(QStringLiteral("—"));
        m_functionEdit->setText(QStringLiteral("—"));
        m_accessEdit->setText(QStringLiteral("—"));
        m_methodEdit->setText(QStringLiteral("—"));
        m_statusLabel->setText(kernelText(
            "kernel.ioctl_decoder.status.invalid",
            QStringLiteral("输入无效：请输入 1 至 8 位十六进制控制码。")));
        m_statusLabel->setStyleSheet(
            QStringLiteral("color:%1;font-weight:600;").arg(KswordTheme::ErrorHex()));
        m_bitLayoutWidget->setCode(0U, false);
        return;
    }

    // 四个局部变量严格对应微软 CTL_CODE 宏，避免 UI 与协议位定义发生偏移。
    const std::uint32_t codeValue = static_cast<std::uint32_t>(parsedValue);
    const std::uint32_t deviceValue = (codeValue >> 16U) & 0xFFFFU;
    const std::uint32_t accessValue = (codeValue >> 14U) & 0x3U;
    const std::uint32_t functionValue = (codeValue >> 2U) & 0xFFFU;
    const std::uint32_t methodValue = codeValue & 0x3U;

    m_deviceEdit->setText(formatNumericField(deviceValue, 4));
    m_functionEdit->setText(formatNumericField(functionValue, 3));
    m_accessEdit->setText(
        QStringLiteral("0x%1 · %2").arg(accessValue, 1, 16).arg(accessName(accessValue)).toUpper());
    m_methodEdit->setText(
        QStringLiteral("0x%1 · %2").arg(methodValue, 1, 16).arg(methodName(methodValue)).toUpper());

    const std::uint32_t commonBit = (codeValue >> 31U) & 0x1U;
    const std::uint32_t customBit = (codeValue >> 13U) & 0x1U;
    m_statusLabel->setText(
        kernelText(
            "kernel.ioctl_decoder.status.valid",
            QStringLiteral("解析完成：Common=%1，Custom=%2。"))
            .arg(commonBit)
            .arg(customBit));
    m_statusLabel->setStyleSheet(
        QStringLiteral("color:%1;font-weight:600;").arg(KswordTheme::SuccessHex()));
    m_bitLayoutWidget->setCode(codeValue, true);
}

void KernelIoctlDecoderTab::normalizeInput()
{
    // normalizedText 与实时解析共用相同前缀规则，仅在完整合法时改写输入框。
    QString normalizedText = m_codeEdit->text().trimmed();
    if (normalizedText.startsWith(QStringLiteral("0x"), Qt::CaseInsensitive))
    {
        normalizedText.remove(0, 2);
    }

    bool parseOk = false;
    const qulonglong parsedValue = normalizedText.toULongLong(&parseOk, 16);
    if (!parseOk || normalizedText.isEmpty() || normalizedText.size() > 8 || parsedValue > 0xFFFFFFFFULL)
    {
        return;
    }

    // signalBlocker 防止规范化文本触发两次中间态解析，随后显式刷新一次最终结果。
    const QString formattedText = QStringLiteral("0x%1")
        .arg(parsedValue, 8, 16, QLatin1Char('0'))
        .toUpper();
    const QSignalBlocker signalBlocker(m_codeEdit);
    m_codeEdit->setText(formattedText);
    updateDecodedFields(formattedText);
}

QString KernelIoctlDecoderTab::formatNumericField(
    const std::uint32_t value,
    const int hexWidth)
{
    return QStringLiteral("0x%1 (%2)")
        .arg(value, hexWidth, 16, QLatin1Char('0'))
        .arg(value)
        .toUpper();
}

QString KernelIoctlDecoderTab::accessName(const std::uint32_t accessValue)
{
    switch (accessValue & 0x3U)
    {
    case 0U:
        return QStringLiteral("FILE_ANY_ACCESS");
    case 1U:
        return QStringLiteral("FILE_READ_ACCESS");
    case 2U:
        return QStringLiteral("FILE_WRITE_ACCESS");
    case 3U:
        return QStringLiteral("FILE_READ_ACCESS | FILE_WRITE_ACCESS");
    default:
        return QStringLiteral("FILE_ANY_ACCESS");
    }
}

QString KernelIoctlDecoderTab::methodName(const std::uint32_t methodValue)
{
    switch (methodValue & 0x3U)
    {
    case 0U:
        return QStringLiteral("METHOD_BUFFERED");
    case 1U:
        return QStringLiteral("METHOD_IN_DIRECT");
    case 2U:
        return QStringLiteral("METHOD_OUT_DIRECT");
    case 3U:
        return QStringLiteral("METHOD_NEITHER");
    default:
        return QStringLiteral("METHOD_BUFFERED");
    }
}
