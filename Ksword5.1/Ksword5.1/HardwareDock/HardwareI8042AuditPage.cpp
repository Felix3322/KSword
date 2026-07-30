#include "HardwareI8042AuditPage.h"

#include "../ArkDriverClient/ArkDriverClient.h"
#include "../Internationalization/LanguageManager.h"
#include "../UI/VisibleTableWidget.h"
#include "../theme.h"

#include <QAbstractItemView>
#include <QComboBox>
#include <QCoreApplication>
#include <QHeaderView>
#include <QHBoxLayout>
#include <QIcon>
#include <QLabel>
#include <QLineEdit>
#include <QMetaObject>
#include <QPointer>
#include <QPushButton>
#include <QShowEvent>
#include <QStringList>
#include <QTableWidget>
#include <QTableWidgetItem>
#include <QVBoxLayout>

#include <algorithm>
#include <array>
#include <thread>
#include <utility>

namespace
{
    QString i8042Text(const char* const key, const QString& sourceText)
    {
        return ks::i18n::contextText(QString::fromLatin1(key), sourceText);
    }

    enum I8042Column : int
    {
        ColumnSource = 0,
        ColumnTarget,
        ColumnItem,
        ColumnAddress,
        ColumnRelatedAddress,
        ColumnModule,
        ColumnStatus,
        ColumnFlags,
        ColumnDetail,
        ColumnCount
    };

    const std::array<const wchar_t*, 5> kI8042DriverNames = {
        L"\\Driver\\i8042prt",
        L"\\Driver\\kbdclass",
        L"\\Driver\\mouclass",
        L"\\Driver\\kbdhid",
        L"\\Driver\\mouhid"
    };

    QTableWidgetItem* readOnlyI8042Item(const QString& text)
    {
        auto* item = new QTableWidgetItem(text);
        item->setFlags(item->flags() & ~Qt::ItemIsEditable);
        return item;
    }

    bool isI8042RelatedModule(const std::wstring& modulePath)
    {
        const QString path = QString::fromStdWString(modulePath);
        return path.contains(QStringLiteral("i8042prt"), Qt::CaseInsensitive) ||
            path.contains(QStringLiteral("kbdclass"), Qt::CaseInsensitive) ||
            path.contains(QStringLiteral("mouclass"), Qt::CaseInsensitive) ||
            path.contains(QStringLiteral("kbdhid"), Qt::CaseInsensitive) ||
            path.contains(QStringLiteral("mouhid"), Qt::CaseInsensitive);
    }
}

HardwareI8042AuditPage::HardwareI8042AuditPage(QWidget* parent)
    : QWidget(parent)
{
    initializeUi();
}

void HardwareI8042AuditPage::showEvent(QShowEvent* event)
{
    QWidget::showEvent(event);
    if (!m_firstRefreshStarted)
    {
        m_firstRefreshStarted = true;
        QMetaObject::invokeMethod(this, [this]() { refreshAsync(); }, Qt::QueuedConnection);
    }
}

void HardwareI8042AuditPage::initializeUi()
{
    auto* rootLayout = new QVBoxLayout(this);
    rootLayout->setContentsMargins(6, 6, 6, 6);
    rootLayout->setSpacing(6);

    auto* explanation = new QLabel(
        i8042Text(
            "hardware.i8042.explanation",
            QStringLiteral("只读 i8042prt 审计：组合 DriverObject 派遣表、输入设备栈和已登记回调；"
                           "同时展示 kbdclass/mouclass/kbdhid/mouhid 邻接关系。"
                           "本页不读取按键、扫描码、鼠标移动或 HID 报告，也不使用私有裸偏移。")),
        this);
    explanation->setWordWrap(true);
    explanation->setStyleSheet(
        QStringLiteral("QLabel{padding:6px;border:1px solid %1;border-radius:4px;color:%2;}")
            .arg(KswordTheme::BorderColorHex())
            .arg(KswordTheme::TextSecondaryHex()));
    rootLayout->addWidget(explanation);

    auto* toolbar = new QHBoxLayout();
    m_refreshButton = new QPushButton(QIcon(QStringLiteral(":/Icon/process_refresh.svg")), QString(), this);
    m_refreshButton->setToolTip(i8042Text(
        "hardware.i8042.refresh.tooltip",
        QStringLiteral("重新组合 i8042prt DriverObject、InputStack 与 CallbackEnum 只读证据")));
    m_refreshButton->setStyleSheet(KswordTheme::ThemedButtonStyle());
    m_columnGroupCombo = new QComboBox(this);
    m_columnGroupCombo->addItems({
        i8042Text("hardware.i8042.columns.a", QStringLiteral("列组 A：链路")),
        i8042Text("hardware.i8042.columns.b", QStringLiteral("列组 B：完整性")),
        i8042Text("hardware.i8042.columns.c", QStringLiteral("列组 C：全部"))
    });
    m_columnGroupCombo->setToolTip(i8042Text(
        "hardware.i8042.columns.tooltip",
        QStringLiteral("切换链路定位、完整性诊断或全部列")));
    m_filterEdit = new QLineEdit(this);
    m_filterEdit->setClearButtonEnabled(true);
    m_filterEdit->setPlaceholderText(i8042Text(
        "hardware.i8042.filter.placeholder",
        QStringLiteral("过滤驱动 / IRP / 设备 / 回调 / 模块 / 状态")));
    m_statusLabel = new QLabel(
        i8042Text("hardware.i8042.status.waiting", QStringLiteral("状态：等待刷新")),
        this);
    m_statusLabel->setTextInteractionFlags(Qt::TextSelectableByMouse);
    toolbar->addWidget(m_refreshButton);
    toolbar->addWidget(m_columnGroupCombo);
    toolbar->addWidget(m_filterEdit, 1);
    toolbar->addWidget(m_statusLabel);
    rootLayout->addLayout(toolbar);

    m_table = new ks::ui::VisibleTableWidget(this);
    m_table->setColumnCount(ColumnCount);
    m_table->setHorizontalHeaderLabels({
        i8042Text("hardware.i8042.header.source", QStringLiteral("证据源")),
        i8042Text("hardware.i8042.header.target", QStringLiteral("目标驱动")),
        i8042Text("hardware.i8042.header.item", QStringLiteral("项目")),
        i8042Text("hardware.i8042.header.address", QStringLiteral("地址")),
        i8042Text("hardware.i8042.header.related_address", QStringLiteral("关联地址")),
        i8042Text("hardware.i8042.header.module", QStringLiteral("模块")),
        i8042Text("hardware.i8042.header.status", QStringLiteral("状态")),
        i8042Text("hardware.i8042.header.flags", QStringLiteral("标志")),
        i8042Text("hardware.i8042.header.detail", QStringLiteral("备注"))
    });
    m_table->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_table->setSelectionMode(QAbstractItemView::SingleSelection);
    m_table->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_table->setAlternatingRowColors(true);
    m_table->verticalHeader()->setVisible(false);
    m_table->horizontalHeader()->setSectionResizeMode(QHeaderView::ResizeToContents);
    m_table->horizontalHeader()->setStretchLastSection(true);
    rootLayout->addWidget(m_table, 1);

    connect(m_refreshButton, &QPushButton::clicked, this, [this]() { refreshAsync(); });
    connect(m_columnGroupCombo, &QComboBox::currentIndexChanged, this, [this]() { applyColumnGroup(); });
    connect(m_filterEdit, &QLineEdit::textChanged, this, [this]() { applyFilter(); });
    applyColumnGroup();
}

void HardwareI8042AuditPage::refreshAsync()
{
    if (m_refreshRunning)
    {
        return;
    }
    m_refreshRunning = true;
    m_refreshButton->setEnabled(false);
    m_statusLabel->setText(i8042Text(
        "hardware.i8042.status.refreshing",
        QStringLiteral("状态：正在组合三类只读证据...")));
    QPointer<HardwareI8042AuditPage> safeThis(this);

    std::thread([safeThis]()
    {
        Snapshot snapshot;
        ksword::ark::DriverClient client;
        snapshot.drivers.reserve(kI8042DriverNames.size());
        for (const wchar_t* driverName : kI8042DriverNames)
        {
            snapshot.drivers.push_back(client.queryDriverObject(driverName));
        }
        snapshot.inputStack = client.queryInputStackAudit(L"\\Driver\\i8042prt");
        snapshot.callbacks = client.enumerateCallbacks(KSWORD_ARK_ENUM_CALLBACK_FLAG_INCLUDE_ALL);
        QCoreApplication* application = QCoreApplication::instance();
        if (application == nullptr)
        {
            return;
        }
        const bool posted = QMetaObject::invokeMethod(
            application,
            [safeThis, snapshot = std::move(snapshot)]() mutable
            {
                if (safeThis != nullptr)
                {
                    safeThis->applySnapshot(std::move(snapshot));
                }
            },
            Qt::QueuedConnection);
        // 中文说明：投递失败时也不允许 worker 触碰页面状态；页面恢复只能发生在 GUI 回调内。
        Q_UNUSED(posted);
    }).detach();
}

void HardwareI8042AuditPage::applySnapshot(Snapshot snapshot)
{
    m_refreshRunning = false;
    m_refreshButton->setEnabled(true);
    m_table->setRowCount(0);
    int successfulDriverQueries = 0;
    for (const ksword::ark::DriverObjectQueryResult& driver : snapshot.drivers)
    {
        appendDriverRows(driver);
        if (driver.io.ok)
        {
            ++successfulDriverQueries;
        }
    }
    appendInputRows(snapshot.inputStack);
    appendCallbackRows(snapshot.callbacks);
    applyColumnGroup();
    applyFilter();
    m_statusLabel->setText(
        i8042Text(
            "hardware.i8042.status.summary",
            QStringLiteral("状态：%1 行；DriverObject %2/%3；InputStack=%4；CallbackEnum=%5"))
            .arg(m_table->rowCount())
            .arg(successfulDriverQueries)
            .arg(snapshot.drivers.size())
            .arg(snapshot.inputStack.io.ok
                     ? i8042Text("hardware.i8042.value.ok", QStringLiteral("正常"))
                     : i8042Text("hardware.i8042.value.failed", QStringLiteral("失败")))
            .arg(snapshot.callbacks.io.ok
                     ? i8042Text("hardware.i8042.value.ok", QStringLiteral("正常"))
                     : i8042Text("hardware.i8042.value.failed", QStringLiteral("失败"))));
}

void HardwareI8042AuditPage::appendDriverRows(const ksword::ark::DriverObjectQueryResult& result)
{
    const QString targetName = result.driverName.empty()
        ? i8042Text("hardware.i8042.value.driver_query_failed", QStringLiteral("<DriverObject 查询失败>"))
        : QString::fromStdWString(result.driverName);
    appendRow({
        QStringLiteral("DriverObject"),
        targetName,
        i8042Text("hardware.i8042.value.driver_summary", QStringLiteral("驱动摘要")),
        addressText(result.driverObjectAddress),
        addressText(result.driverStart),
        QString::fromStdWString(result.imagePath),
        result.io.ok
            ? i8042Text("hardware.i8042.value.ok", QStringLiteral("正常"))
            : i8042Text("hardware.i8042.value.query_failed", QStringLiteral("查询失败")),
        QStringLiteral("DriverFlags=0x%1").arg(result.driverFlags, 8, 16, QLatin1Char('0')),
        i8042Text(
            "hardware.i8042.driver.detail",
            QStringLiteral("Unload=%1；Service=%2；NTSTATUS=0x%3"))
            .arg(addressText(result.driverUnload))
            .arg(QString::fromStdWString(result.serviceKeyName))
            .arg(static_cast<unsigned long>(result.lastStatus), 8, 16, QLatin1Char('0'))
    });

    for (const ksword::ark::DriverMajorFunctionEntry& major : result.majorFunctions)
    {
        appendRow({
            QStringLiteral("DriverObject.MajorFunction"),
            targetName,
            majorFunctionText(major.majorFunction),
            addressText(major.dispatchAddress),
            addressText(major.moduleBase),
            QString::fromStdWString(major.moduleName),
            (major.flags & 0x00000002UL) != 0UL
                ? i8042Text("hardware.i8042.value.owned", QStringLiteral("由目标映像拥有"))
                : i8042Text("hardware.i8042.value.delegated", QStringLiteral("已委派 / 所有者不匹配")),
            QStringLiteral("0x%1").arg(major.flags, 8, 16, QLatin1Char('0')),
            i8042Text(
                "hardware.i8042.dispatch.detail",
                QStringLiteral("派遣地址和模块归属来自现有 DriverObject 查询协议；不读取私有偏移。"))
        });
    }
}

void HardwareI8042AuditPage::appendInputRows(const ksword::ark::DeviceAuditResult& result)
{
    for (const KSWORD_ARK_DEVICE_AUDIT_ENTRY& entry : result.entries)
    {
        appendRow({
            QStringLiteral("InputStack"),
            fixedWide(entry.driverName, KSWORD_ARK_DEVICE_AUDIT_DRIVER_NAME_CHARS),
            entry.rowKind == KSWORD_ARK_DEVICE_AUDIT_ROW_KIND_DRIVER_SUMMARY
                ? i8042Text("hardware.i8042.value.driver_summary", QStringLiteral("驱动摘要"))
                : i8042Text(
                      "hardware.i8042.input.device_depth",
                      QStringLiteral("设备层级 %1 / 已附加 %2"))
                      .arg(entry.relationDepth)
                      .arg(entry.attachedDepth),
            addressText(entry.deviceObjectAddress != 0ULL
                ? entry.deviceObjectAddress
                : entry.driverObjectAddress),
            addressText(entry.attachedDeviceAddress != 0ULL
                ? entry.attachedDeviceAddress
                : entry.nextDeviceObjectAddress),
            fixedWide(entry.imagePath, KSWORD_ARK_DEVICE_AUDIT_IMAGE_PATH_CHARS),
            QStringLiteral("Status=%1 Risk=0x%2")
                .arg(entry.status)
                .arg(entry.riskFlags, 8, 16, QLatin1Char('0')),
            QStringLiteral("0x%1").arg(entry.fieldFlags, 8, 16, QLatin1Char('0')),
            fixedWide(entry.detail, KSWORD_ARK_DEVICE_AUDIT_DETAIL_CHARS)
        });
    }
}

void HardwareI8042AuditPage::appendCallbackRows(const ksword::ark::CallbackEnumResult& result)
{
    for (const ksword::ark::CallbackEnumEntry& entry : result.entries)
    {
        if (!isI8042RelatedModule(entry.modulePath))
        {
            continue;
        }
        appendRow({
            QStringLiteral("CallbackEnum"),
            QString::fromStdWString(entry.modulePath),
            QString::fromStdWString(entry.name),
            addressText(entry.callbackAddress),
            addressText(entry.registrationAddress),
            QString::fromStdWString(entry.modulePath),
            QStringLiteral("Class=%1 Status=%2 Trust=0x%3")
                .arg(entry.callbackClass)
                .arg(entry.status)
                .arg(entry.trustFlags, 8, 16, QLatin1Char('0')),
            QStringLiteral("0x%1").arg(entry.fieldFlags, 8, 16, QLatin1Char('0')),
            QString::fromStdWString(entry.detail)
        });
    }
}

void HardwareI8042AuditPage::appendRow(const QStringList& cells)
{
    const int row = m_table->rowCount();
    m_table->insertRow(row);
    for (int column = 0; column < ColumnCount; ++column)
    {
        m_table->setItem(
            row,
            column,
            readOnlyI8042Item(column < cells.size() ? cells[column] : QString()));
    }
}

void HardwareI8042AuditPage::applyColumnGroup()
{
    const int group = m_columnGroupCombo != nullptr ? m_columnGroupCombo->currentIndex() : 0;
    for (int column = 0; column < ColumnCount; ++column)
    {
        bool visible = group == 2;
        if (group == 0)
        {
            visible = column == ColumnSource ||
                column == ColumnTarget ||
                column == ColumnItem ||
                column == ColumnAddress ||
                column == ColumnRelatedAddress ||
                column == ColumnStatus;
        }
        else if (group == 1)
        {
            visible = column == ColumnSource ||
                column == ColumnItem ||
                column == ColumnModule ||
                column == ColumnStatus ||
                column == ColumnFlags ||
                column == ColumnDetail;
        }
        m_table->setColumnHidden(column, !visible);
    }
}

void HardwareI8042AuditPage::applyFilter()
{
    const QString filter = m_filterEdit != nullptr ? m_filterEdit->text().trimmed() : QString();
    for (int row = 0; row < m_table->rowCount(); ++row)
    {
        bool matched = filter.isEmpty();
        for (int column = 0; !matched && column < m_table->columnCount(); ++column)
        {
            const QTableWidgetItem* item = m_table->item(row, column);
            matched = item != nullptr && item->text().contains(filter, Qt::CaseInsensitive);
        }
        m_table->setRowHidden(row, !matched);
    }
}

QString HardwareI8042AuditPage::addressText(const std::uint64_t address)
{
    return address == 0ULL
        ? QStringLiteral("-")
        : QStringLiteral("0x%1").arg(address, 16, 16, QLatin1Char('0'));
}

QString HardwareI8042AuditPage::majorFunctionText(const std::uint32_t majorFunction)
{
    switch (majorFunction)
    {
    case 0:
        return QStringLiteral("IRP_MJ_CREATE");
    case 2:
        return QStringLiteral("IRP_MJ_CLOSE");
    case 3:
        return QStringLiteral("IRP_MJ_READ");
    case 4:
        return QStringLiteral("IRP_MJ_WRITE");
    case 14:
        return QStringLiteral("IRP_MJ_DEVICE_CONTROL");
    case 15:
        return QStringLiteral("IRP_MJ_INTERNAL_DEVICE_CONTROL");
    case 22:
        return QStringLiteral("IRP_MJ_POWER");
    case 23:
        return QStringLiteral("IRP_MJ_SYSTEM_CONTROL");
    case 27:
        return QStringLiteral("IRP_MJ_PNP");
    default:
        return QStringLiteral("IRP_MJ_%1").arg(majorFunction);
    }
}

QString HardwareI8042AuditPage::fixedWide(const wchar_t* text, const int capacity)
{
    if (text == nullptr || capacity <= 0)
    {
        return QString();
    }
    int length = 0;
    while (length < capacity && text[length] != L'\0')
    {
        ++length;
    }
    return QString::fromWCharArray(text, length);
}
