#include "KernelPlatformAuditTab.h"

#include "KernelDock.h"
#include "../ArkDriverClient/ArkDriverClient.h"
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
#include <QTabWidget>
#include <QTableWidget>
#include <QTableWidgetItem>
#include <QVBoxLayout>

#include <array>
#include <thread>
#include <utility>

using ksword::kernel_dock_internal::kernelText;

namespace
{
    enum PlatformColumn : int
    {
        ColumnName = 0,
        ColumnIndex,
        ColumnLiveAddress,
        ColumnBaselineAddress,
        ColumnHook,
        ColumnModule,
        ColumnVendor,
        ColumnTableAddress,
        ColumnSignature,
        ColumnConfidence,
        ColumnStatus,
        ColumnDetail,
        ColumnCount
    };

    QTableWidgetItem* readOnlyPlatformItem(const QString& text)
    {
        auto* item = new QTableWidgetItem(text);
        item->setFlags(item->flags() & ~Qt::ItemIsEditable);
        return item;
    }
}

KernelPlatformAuditTab::KernelPlatformAuditTab(const Mode mode, QWidget* parent)
    : QWidget(parent),
      m_mode(mode)
{
    initializeUi();
}

void KernelPlatformAuditTab::showEvent(QShowEvent* event)
{
    QWidget::showEvent(event);
    if (!m_firstRefreshStarted)
    {
        m_firstRefreshStarted = true;
        QMetaObject::invokeMethod(this, [this]() { refreshAsync(); }, Qt::QueuedConnection);
    }
}

void KernelPlatformAuditTab::initializeUi()
{
    auto* rootLayout = new QVBoxLayout(this);
    rootLayout->setContentsMargins(6, 6, 6, 6);
    rootLayout->setSpacing(6);

    auto* explanationLabel = new QLabel(
        m_mode == Mode::Hal
            ? kernelText(
                  "kernel.platform.hal.explanation",
                  QStringLiteral("只读 HAL 审计：公开表按 WDK v6 结构解析；私有表只接受精确导出，或可信导出锚点内有界且唯一的 byte/mask + RIP-relative 结构签名。没有 PDB 或系统布局不确定时会明确失败关闭。"))
            : kernelText(
                  "kernel.platform.wdf.explanation",
                  QStringLiteral("只读 WDF 审计：函数来自当前驱动的 KMDF 绑定表，回调来自本驱动实际 WDF 配置；不会扫描 Wdf01000 私有内存。")),
        this);
    explanationLabel->setWordWrap(true);
    explanationLabel->setStyleSheet(
        QStringLiteral("QLabel{padding:6px;border:1px solid %1;border-radius:4px;color:%2;}")
            .arg(KswordTheme::BorderColorHex())
            .arg(KswordTheme::TextSecondaryHex()));
    rootLayout->addWidget(explanationLabel);

    auto* toolbar = new QHBoxLayout();
    m_refreshButton = new QPushButton(QIcon(QStringLiteral(":/Icon/process_refresh.svg")), QString(), this);
    m_refreshButton->setToolTip(kernelText(
        "kernel.platform.toolbar.refresh.tooltip",
        QStringLiteral("重新读取经过结构与模块边界验证的只读审计快照")));
    m_refreshButton->setStyleSheet(KswordTheme::ThemedButtonStyle());
    m_columnGroupCombo = new QComboBox(this);
    m_columnGroupCombo->addItem(kernelText("kernel.platform.columns.a", QStringLiteral("列组 A：定位")));
    m_columnGroupCombo->addItem(kernelText("kernel.platform.columns.b", QStringLiteral("列组 B：验证")));
    m_columnGroupCombo->addItem(kernelText("kernel.platform.columns.c", QStringLiteral("列组 C：全部")));
    m_columnGroupCombo->setToolTip(kernelText(
        "kernel.platform.columns.tooltip",
        QStringLiteral("在地址定位、签名验证和全部字段三种紧凑视图间切换")));
    m_filterEdit = new QLineEdit(this);
    m_filterEdit->setClearButtonEnabled(true);
    m_filterEdit->setPlaceholderText(kernelText(
        "kernel.platform.filter.placeholder",
        QStringLiteral("过滤名称 / 模块 / 厂商 / 状态 / 备注")));
    m_statusLabel = new QLabel(
        kernelText("kernel.platform.status.waiting", QStringLiteral("状态：等待刷新")),
        this);
    m_statusLabel->setTextInteractionFlags(Qt::TextSelectableByMouse);
    toolbar->addWidget(m_refreshButton);
    toolbar->addWidget(m_columnGroupCombo);
    toolbar->addWidget(m_filterEdit, 1);
    toolbar->addWidget(m_statusLabel);
    rootLayout->addLayout(toolbar);

    m_innerTabs = new QTabWidget(this);
    m_innerTabs->setDocumentMode(true);
    if (m_mode == Mode::Hal)
    {
        addPage(
            KSWORD_ARK_PLATFORM_AUDIT_SCOPE_HAL_DISPATCH,
            kernelText("kernel.platform.hal.dispatch", QStringLiteral("HalDispatchTable")));
        addPage(
            KSWORD_ARK_PLATFORM_AUDIT_SCOPE_HAL_PRIVATE,
            kernelText("kernel.platform.hal.private", QStringLiteral("HalPrivateDispatchTable")));
        addPage(
            KSWORD_ARK_PLATFORM_AUDIT_SCOPE_HAL_ACPI,
            kernelText("kernel.platform.hal.acpi", QStringLiteral("HalAcpiDispatchTable")));
        addPage(
            KSWORD_ARK_PLATFORM_AUDIT_SCOPE_HAL_SUBCOMPONENTS,
            kernelText("kernel.platform.hal.subcomponents", QStringLiteral("HalSubComponents")));
    }
    else
    {
        addPage(
            KSWORD_ARK_PLATFORM_AUDIT_SCOPE_WDF_FUNCTIONS,
            kernelText("kernel.platform.wdf.functions", QStringLiteral("WDF 函数")));
        addPage(
            KSWORD_ARK_PLATFORM_AUDIT_SCOPE_WDF_CALLBACKS,
            kernelText("kernel.platform.wdf.callbacks", QStringLiteral("WDF 回调")));
    }
    rootLayout->addWidget(m_innerTabs, 1);

    connect(m_refreshButton, &QPushButton::clicked, this, [this]() { refreshAsync(); });
    connect(m_columnGroupCombo, &QComboBox::currentIndexChanged, this, [this]() { applyColumnGroup(); });
    connect(m_filterEdit, &QLineEdit::textChanged, this, [this]() { applyFilter(); });
}

void KernelPlatformAuditTab::addPage(const unsigned long scope, const QString& title)
{
    auto* table = new ks::ui::VisibleTableWidget(m_innerTabs);
    table->setColumnCount(ColumnCount);
    table->setHorizontalHeaderLabels({
        kernelText("kernel.platform.header.name", QStringLiteral("函数 / 回调")),
        kernelText("kernel.platform.header.index", QStringLiteral("索引")),
        kernelText("kernel.platform.header.live", QStringLiteral("当前地址")),
        kernelText("kernel.platform.header.baseline", QStringLiteral("运行时结构快照")),
        kernelText("kernel.platform.header.hook", QStringLiteral("Hook")),
        kernelText("kernel.platform.header.module", QStringLiteral("模块")),
        kernelText("kernel.platform.header.vendor", QStringLiteral("厂商")),
        kernelText("kernel.platform.header.table", QStringLiteral("表地址")),
        kernelText("kernel.platform.header.signature", QStringLiteral("签名策略")),
        kernelText("kernel.platform.header.confidence", QStringLiteral("置信度")),
        kernelText("kernel.platform.header.status", QStringLiteral("状态")),
        kernelText("kernel.platform.header.detail", QStringLiteral("备注"))
    });
    table->setSelectionBehavior(QAbstractItemView::SelectRows);
    table->setSelectionMode(QAbstractItemView::SingleSelection);
    table->setEditTriggers(QAbstractItemView::NoEditTriggers);
    table->setAlternatingRowColors(true);
    table->verticalHeader()->setVisible(false);
    table->horizontalHeader()->setSectionResizeMode(QHeaderView::ResizeToContents);
    table->horizontalHeader()->setStretchLastSection(true);
    m_innerTabs->addTab(table, title);
    m_pages.push_back(Page{ scope, table });
    applyColumnGroup();
}

void KernelPlatformAuditTab::refreshAsync()
{
    if (m_refreshRunning)
    {
        return;
    }
    m_refreshRunning = true;
    m_refreshButton->setEnabled(false);
    m_statusLabel->setText(kernelText(
        "kernel.platform.status.refreshing",
        QStringLiteral("状态：正在读取只读审计快照...")));

    const unsigned long scope =
        m_mode == Mode::Hal
            ? (KSWORD_ARK_PLATFORM_AUDIT_SCOPE_HAL_DISPATCH |
               KSWORD_ARK_PLATFORM_AUDIT_SCOPE_HAL_PRIVATE |
               KSWORD_ARK_PLATFORM_AUDIT_SCOPE_HAL_ACPI |
               KSWORD_ARK_PLATFORM_AUDIT_SCOPE_HAL_SUBCOMPONENTS)
            : (KSWORD_ARK_PLATFORM_AUDIT_SCOPE_WDF_FUNCTIONS |
               KSWORD_ARK_PLATFORM_AUDIT_SCOPE_WDF_CALLBACKS);
    QPointer<KernelPlatformAuditTab> safeThis(this);
    std::thread([safeThis, scope]()
    {
        ksword::ark::DriverClient client;
        auto result = client.queryPlatformAudit(scope);
        QCoreApplication* application = QCoreApplication::instance();
        if (application == nullptr)
        {
            return;
        }
        const bool posted = QMetaObject::invokeMethod(
            application,
            [safeThis, result = std::move(result)]() mutable
            {
                if (safeThis != nullptr)
                {
                    safeThis->applyResult(std::move(result));
                }
            },
            Qt::QueuedConnection);
        // 中文说明：投递失败时也不允许 worker 触碰页面状态；页面恢复只能发生在 GUI 回调内。
        Q_UNUSED(posted);
    }).detach();
}

void KernelPlatformAuditTab::applyResult(ksword::ark::PlatformAuditResult result)
{
    m_refreshRunning = false;
    m_refreshButton->setEnabled(true);
    for (Page& page : m_pages)
    {
        populatePage(page, result);
    }
    applyColumnGroup();
    applyFilter();

    if (!result.io.ok)
    {
        m_statusLabel->setText(kernelText(
            "kernel.platform.status.failed",
            QStringLiteral("状态：查询失败 - %1"))
            .arg(QString::fromStdString(result.io.message)));
        return;
    }
    m_statusLabel->setText(kernelText(
        "kernel.platform.status.summary",
        QStringLiteral("状态：%1/%2 行，Build %3，Flags 0x%4"))
        .arg(result.entries.size())
        .arg(result.totalCount)
        .arg(result.buildNumber)
        .arg(result.responseFlags, 0, 16));
}

void KernelPlatformAuditTab::populatePage(
    Page& page,
    const ksword::ark::PlatformAuditResult& result)
{
    if (page.table == nullptr)
    {
        return;
    }
    page.table->setRowCount(0);
    for (const KSWORD_ARK_PLATFORM_AUDIT_ENTRY& entry : result.entries)
    {
        if (entry.scope != page.scope)
        {
            continue;
        }
        const int row = page.table->rowCount();
        page.table->insertRow(row);
        QString signatureDisplay = signatureText(entry.signatureId);
        if (entry.prologueSignatureId != 0UL)
        {
            signatureDisplay += QStringLiteral(" / prologue-%1").arg(entry.prologueSignatureId);
        }
        const std::array<QString, ColumnCount> cells = {
            fixedWide(entry.name, KSWORD_ARK_PLATFORM_NAME_CHARS),
            QString::number(entry.entryIndex),
            addressText(entry.liveAddress),
            addressText(entry.baselineAddress),
            hookText(entry.hookStatus),
            fixedWide(entry.modulePath, KSWORD_ARK_PLATFORM_MODULE_PATH_CHARS),
            fixedWide(entry.vendor, KSWORD_ARK_PLATFORM_VENDOR_CHARS),
            addressText(entry.tableAddress),
            signatureDisplay,
            QStringLiteral("%1%").arg(entry.confidence),
            statusText(entry.status, entry.lastStatus),
            fixedWide(entry.detail, KSWORD_ARK_PLATFORM_DETAIL_CHARS)
        };
        for (int column = 0; column < ColumnCount; ++column)
        {
            page.table->setItem(row, column, readOnlyPlatformItem(cells[static_cast<std::size_t>(column)]));
        }
    }
}

void KernelPlatformAuditTab::applyColumnGroup()
{
    const int groupIndex = m_columnGroupCombo != nullptr ? m_columnGroupCombo->currentIndex() : 0;
    for (const Page& page : m_pages)
    {
        if (page.table == nullptr)
        {
            continue;
        }
        for (int column = 0; column < ColumnCount; ++column)
        {
            bool visible = groupIndex == 2;
            if (groupIndex == 0)
            {
                visible = column == ColumnName ||
                    column == ColumnLiveAddress ||
                    column == ColumnBaselineAddress ||
                    column == ColumnHook ||
                    column == ColumnModule ||
                    column == ColumnStatus;
            }
            else if (groupIndex == 1)
            {
                visible = column == ColumnName ||
                    column == ColumnIndex ||
                    column == ColumnTableAddress ||
                    column == ColumnSignature ||
                    column == ColumnConfidence ||
                    column == ColumnDetail;
            }
            page.table->setColumnHidden(column, !visible);
        }
    }
}

void KernelPlatformAuditTab::applyFilter()
{
    const QString filterText = m_filterEdit != nullptr ? m_filterEdit->text().trimmed() : QString();
    for (const Page& page : m_pages)
    {
        if (page.table == nullptr)
        {
            continue;
        }
        for (int row = 0; row < page.table->rowCount(); ++row)
        {
            bool matched = filterText.isEmpty();
            for (int column = 0; !matched && column < page.table->columnCount(); ++column)
            {
                const QTableWidgetItem* item = page.table->item(row, column);
                matched = item != nullptr && item->text().contains(filterText, Qt::CaseInsensitive);
            }
            page.table->setRowHidden(row, !matched);
        }
    }
}

QString KernelPlatformAuditTab::fixedWide(const wchar_t* text, const int capacity)
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

QString KernelPlatformAuditTab::addressText(const unsigned long long address)
{
    return address == 0ULL
        ? QStringLiteral("-")
        : QStringLiteral("0x%1").arg(address, 16, 16, QLatin1Char('0')).toUpper();
}

QString KernelPlatformAuditTab::statusText(const unsigned long status, const long lastStatus)
{
    QString text;
    switch (status)
    {
    case KSWORD_ARK_PLATFORM_AUDIT_STATUS_OK:
        text = kernelText("kernel.platform.value.ok", QStringLiteral("正常"));
        break;
    case KSWORD_ARK_PLATFORM_AUDIT_STATUS_PARTIAL:
        text = kernelText("kernel.platform.value.partial", QStringLiteral("部分"));
        break;
    case KSWORD_ARK_PLATFORM_AUDIT_STATUS_UNSUPPORTED:
        text = kernelText("kernel.platform.value.unsupported", QStringLiteral("不支持 / 失败关闭"));
        break;
    case KSWORD_ARK_PLATFORM_AUDIT_STATUS_SIGNATURE_MISMATCH:
        text = kernelText("kernel.platform.value.signature_mismatch", QStringLiteral("签名不匹配"));
        break;
    case KSWORD_ARK_PLATFORM_AUDIT_STATUS_QUERY_FAILED:
        text = kernelText("kernel.platform.value.query_failed", QStringLiteral("查询失败"));
        break;
    default:
        text = kernelText("kernel.platform.value.unavailable", QStringLiteral("不可用"));
        break;
    }
    return QStringLiteral("%1 (0x%2)")
        .arg(text)
        .arg(static_cast<unsigned long>(lastStatus), 8, 16, QLatin1Char('0'))
        .toUpper();
}

QString KernelPlatformAuditTab::hookText(const unsigned long hookStatus)
{
    switch (hookStatus)
    {
    case KSWORD_ARK_PLATFORM_HOOK_CLEAN:
        return kernelText("kernel.platform.hook.clean", QStringLiteral("Clean"));
    case KSWORD_ARK_PLATFORM_HOOK_SUSPICIOUS:
        return kernelText("kernel.platform.hook.suspicious", QStringLiteral("Suspicious"));
    case KSWORD_ARK_PLATFORM_HOOK_UNSUPPORTED:
        return kernelText("kernel.platform.hook.unsupported", QStringLiteral("Unsupported"));
    default:
        return kernelText("kernel.platform.hook.unknown", QStringLiteral("Unknown"));
    }
}

QString KernelPlatformAuditTab::signatureText(const unsigned long signatureId)
{
    switch (signatureId)
    {
    case KSWORD_ARK_PLATFORM_SIGNATURE_PUBLIC_HAL_V6:
        return QStringLiteral("Public HAL v6");
    case KSWORD_ARK_PLATFORM_SIGNATURE_COUNT_PREFIXED_TABLE:
        return QStringLiteral("Exact export + count");
    case KSWORD_ARK_PLATFORM_SIGNATURE_WDF_BINDING_TABLE:
        return QStringLiteral("KMDF binding");
    case KSWORD_ARK_PLATFORM_SIGNATURE_X64_PROLOGUE:
        return QStringLiteral("x64 prologue");
    case KSWORD_ARK_PLATFORM_SIGNATURE_EXACT_EXPORT_ONLY:
        return QStringLiteral("Exact export / fail-closed");
    case KSWORD_ARK_PLATFORM_SIGNATURE_RIP_RELATIVE_MASKED:
        return QStringLiteral("Bounded byte/mask + RIP-relative");
    default:
        return QStringLiteral("-");
    }
}
