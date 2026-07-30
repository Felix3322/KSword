#include "KernelPlatformAuditTab.h"

#include "KernelCleanImageBaseline.h"
#include "KernelDock.h"
#include "../ArkDriverClient/ArkDriverClient.h"
#include "../UI/TableInteractionSupport.h"
#include "../UI/VisibleTableWidget.h"
#include "../theme.h"

#include <QAbstractItemView>
#include <QComboBox>
#include <QDir>
#include <QEvent>
#include <QHeaderView>
#include <QHBoxLayout>
#include <QHash>
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

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <limits>
#include <utility>
#include <vector>

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>

#pragma comment(lib, "Version.lib")

using ksword::kernel_dock_internal::kernelText;

namespace
{
    enum PlatformColumn : int
    {
        ColumnName = 0,
        ColumnIndex,
        ColumnLiveAddress,
        ColumnOriginalAddress,
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

    bool validateRuntimeCleanPointer(
        const ks::kernel::CleanImageBaselineResult& baseline,
        const std::uint64_t runtimePointer,
        std::uint64_t& runtimeAddressOut)
    {
        runtimeAddressOut = 0U;
        if (!baseline.available ||
            !baseline.identityMatched ||
            !baseline.diskTrustVerified ||
            !baseline.codeIntegrityTrusted ||
            baseline.moduleBase == 0U ||
            baseline.moduleSize == 0U ||
            runtimePointer < baseline.moduleBase)
        {
            return false;
        }
        const std::uint64_t rva =
            runtimePointer - baseline.moduleBase;
        if (rva >= baseline.moduleSize)
        {
            return false;
        }
        runtimeAddressOut = runtimePointer;
        return true;
    }

    void enrichWdfFunctionBaselines(
        ksword::ark::PlatformAuditResult& result)
    {
        std::uint64_t tableAddress = 0U;
        std::size_t functionCount = 0U;
        for (const KSWORD_ARK_PLATFORM_AUDIT_ENTRY& entry : result.entries)
        {
            if (entry.scope !=
                    KSWORD_ARK_PLATFORM_AUDIT_SCOPE_WDF_FUNCTIONS ||
                entry.rowKind != KSWORD_ARK_PLATFORM_AUDIT_ROW_FUNCTION ||
                entry.tableAddress == 0U ||
                entry.entryIndex >= KSWORD_ARK_PLATFORM_HARD_MAX_ROWS)
            {
                continue;
            }
            if (tableAddress == 0U)
            {
                tableAddress = entry.tableAddress;
            }
            else if (tableAddress != entry.tableAddress)
            {
                // 同一响应出现两个绑定表时拒绝建立混合基线。
                return;
            }
            functionCount = std::max(
                functionCount,
                static_cast<std::size_t>(entry.entryIndex) + 1U);
        }
        if (tableAddress == 0U ||
            functionCount == 0U ||
            functionCount >
                std::numeric_limits<std::uint32_t>::max() /
                    sizeof(std::uint64_t))
        {
            return;
        }

        const std::uint32_t tableBytes = static_cast<std::uint32_t>(
            functionCount * sizeof(std::uint64_t));
        const ks::kernel::CleanImageBaselineResult baseline =
            ks::kernel::KernelCleanImageBaseline::compareAddress(
                tableAddress,
                tableBytes,
                {},
                true);
        if (!baseline.available ||
            !baseline.diskTrustVerified ||
            baseline.cleanBytes.size() != tableBytes)
        {
            return;
        }

        for (KSWORD_ARK_PLATFORM_AUDIT_ENTRY& entry : result.entries)
        {
            if (entry.scope !=
                    KSWORD_ARK_PLATFORM_AUDIT_SCOPE_WDF_FUNCTIONS ||
                entry.rowKind != KSWORD_ARK_PLATFORM_AUDIT_ROW_FUNCTION ||
                entry.tableAddress != tableAddress ||
                entry.entryIndex >= functionCount)
            {
                continue;
            }
            const std::size_t byteOffset =
                static_cast<std::size_t>(entry.entryIndex) *
                sizeof(std::uint64_t);
            if (byteOffset > baseline.cleanBytes.size() ||
                sizeof(std::uint64_t) >
                    baseline.cleanBytes.size() - byteOffset)
            {
                continue;
            }

            std::uint64_t runtimePointer = 0U;
            std::memcpy(
                &runtimePointer,
                baseline.cleanBytes.data() + byteOffset,
                sizeof(runtimePointer));
            std::uint64_t originalAddress = 0U;
            if (!validateRuntimeCleanPointer(
                    baseline,
                    runtimePointer,
                    originalAddress))
            {
                continue;
            }

            entry.originalAddress = originalAddress;
            entry.originalAddressSource =
                KSWORD_ARK_PLATFORM_ORIGINAL_SOURCE_DISK_IMAGE;
            entry.fieldFlags |=
                KSWORD_ARK_PLATFORM_FIELD_ORIGINAL_ADDRESS |
                KSWORD_ARK_PLATFORM_FIELD_BASELINE_VALIDATED;
            const bool liveSlotObserved =
                (entry.fieldFlags &
                 KSWORD_ARK_PLATFORM_FIELD_LIVE_ADDRESS) != 0UL ||
                entry.detailCode ==
                    KSWORD_ARK_PLATFORM_DETAIL_NULL_SLOT;
            if (liveSlotObserved &&
                entry.liveAddress != entry.originalAddress &&
                entry.hookStatus != KSWORD_ARK_PLATFORM_HOOK_SUSPICIOUS)
            {
                entry.fieldFlags |=
                    KSWORD_ARK_PLATFORM_FIELD_DETAIL_ARGS;
                entry.detailArgs[0] = entry.liveAddress;
                entry.detailArgs[1] = entry.originalAddress;
                entry.detailArgs[2] = baseline.relativeVirtualAddress;
                entry.detailArgs[3] = entry.entryIndex;
                entry.hookStatus =
                    KSWORD_ARK_PLATFORM_HOOK_SUSPICIOUS;
                entry.confidence = KSWORD_ARK_PLATFORM_CONFIDENCE_HIGH;
                entry.status =
                    KSWORD_ARK_PLATFORM_AUDIT_STATUS_SIGNATURE_MISMATCH;
                entry.lastStatus =
                    static_cast<long>(0xC000003EUL);
                entry.detailCode =
                    KSWORD_ARK_PLATFORM_DETAIL_BASELINE_MISMATCH;
            }
            // 槽位值相等只能证明绑定表指针未被替换，不能证明函数入口未被
            // inline hook；已有 Suspicious 也携带更具体的 owner/执行节/跳转
            // 证据。两种情况都保留 R0 结论，只补充独立磁盘基线字段。
        }
    }
}

KernelPlatformAuditTab::KernelPlatformAuditTab(const Mode mode, QWidget* parent)
    : QWidget(parent),
      m_mode(mode)
{
    initializeUi();
}

KernelPlatformAuditTab::~KernelPlatformAuditTab()
{
    {
        const std::lock_guard lock(m_refreshMutex);
        m_closing = true;
        if (m_refreshThread.joinable())
        {
            // 中文说明：取消该 worker 正在等待的同步 DeviceIoControl；失败只表示
            // 当下没有可取消的同步 I/O，随后仍必须 join。
            (void)::CancelSynchronousIo(m_refreshThread.native_handle());
        }
    }
    if (m_refreshThread.joinable())
    {
        m_refreshThread.join();
    }
}

void KernelPlatformAuditTab::changeEvent(QEvent* event)
{
    QWidget::changeEvent(event);
    if (event != nullptr && event->type() == QEvent::LanguageChange)
    {
        retranslateUi();
    }
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

    m_explanationLabel = new QLabel(
        m_mode == Mode::Hal
            ? kernelText(
                  "kernel.platform.hal.explanation",
                  QStringLiteral("只读 HAL 审计：公开表逐字段按 WDK 结构解析；私有表按受支持 Build/Version/ByteSize 描述解析，ACPI 与子组件仅接受可信锚点小窗口内唯一且完整验证的 RIP-relative 候选。没有独立基线时只报告 owner/执行节一致性，不把运行时地址判为 Clean。"))
            : kernelText(
                  "kernel.platform.wdf.explanation",
                  QStringLiteral("只读 WDF 审计：完整枚举当前驱动的 KMDF 绑定表及实际注册回调。原始地址仅在 Wdf01000.sys 磁盘映像通过 embedded/catalog 完整链信任验证、与加载映像 PE 身份匹配并成功重定位对应槽位时有效；槽位不匹配标记 Suspicious，槽位匹配仍保留函数入口的独立判定，绝不据此覆盖为 Clean。")),
        this);
    m_explanationLabel->setWordWrap(true);
    m_explanationLabel->setStyleSheet(
        QStringLiteral("QLabel{padding:6px;border:1px solid %1;border-radius:4px;color:%2;}")
            .arg(KswordTheme::BorderColorHex())
            .arg(KswordTheme::TextSecondaryHex()));
    rootLayout->addWidget(m_explanationLabel);

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

void KernelPlatformAuditTab::retranslateUi()
{
    QList<QTableView*> platformTables;
    platformTables.reserve(m_pages.size());
    for (const Page& page : m_pages)
    {
        platformTables.push_back(page.table);
    }
    if (ks::ui::IsTableUiCommitBlockedByContextMenu(platformTables))
    {
        const QPointer<KernelPlatformAuditTab> safeThis(this);
        ks::ui::DeferTableUiCommitIfContextMenuOpen(
            this,
            QStringLiteral("kernel-platform-audit-retranslate"),
            platformTables,
            [safeThis]()
            {
                if (!safeThis.isNull())
                {
                    safeThis->retranslateUi();
                }
            });
        return;
    }

    if (m_explanationLabel != nullptr)
    {
        m_explanationLabel->setText(
            m_mode == Mode::Hal
                ? kernelText(
                      "kernel.platform.hal.explanation",
                      QStringLiteral("只读 HAL 审计：公开表逐字段按 WDK 结构解析；私有表按受支持 Build/Version/ByteSize 描述解析，ACPI 与子组件仅接受可信锚点小窗口内唯一且完整验证的 RIP-relative 候选。没有独立基线时只报告 owner/执行节一致性，不把运行时地址判为 Clean。"))
                : kernelText(
                      "kernel.platform.wdf.explanation",
                      QStringLiteral("只读 WDF 审计：完整枚举当前驱动的 KMDF 绑定表及实际注册回调。原始地址仅在 Wdf01000.sys 磁盘映像通过 embedded/catalog 完整链信任验证、与加载映像 PE 身份匹配并成功重定位对应槽位时有效；槽位不匹配标记 Suspicious，槽位匹配仍保留函数入口的独立判定，绝不据此覆盖为 Clean。")));
    }
    if (m_refreshButton != nullptr)
    {
        m_refreshButton->setToolTip(kernelText(
            "kernel.platform.toolbar.refresh.tooltip",
            QStringLiteral("重新读取经过结构与模块边界验证的只读审计快照")));
    }
    if (m_columnGroupCombo != nullptr &&
        m_columnGroupCombo->count() >= 3)
    {
        m_columnGroupCombo->setItemText(
            0,
            kernelText(
                "kernel.platform.columns.a",
                QStringLiteral("列组 A：定位")));
        m_columnGroupCombo->setItemText(
            1,
            kernelText(
                "kernel.platform.columns.b",
                QStringLiteral("列组 B：验证")));
        m_columnGroupCombo->setItemText(
            2,
            kernelText(
                "kernel.platform.columns.c",
                QStringLiteral("列组 C：全部")));
        m_columnGroupCombo->setToolTip(kernelText(
            "kernel.platform.columns.tooltip",
            QStringLiteral("在地址定位、签名验证和全部字段三种紧凑视图间切换")));
    }
    if (m_filterEdit != nullptr)
    {
        m_filterEdit->setPlaceholderText(kernelText(
            "kernel.platform.filter.placeholder",
            QStringLiteral("过滤名称 / 模块 / 厂商 / 状态 / 备注")));
    }

    const QStringList headers = {
        kernelText("kernel.platform.header.name", QStringLiteral("函数 / 回调")),
        kernelText("kernel.platform.header.index", QStringLiteral("索引")),
        kernelText("kernel.platform.header.live", QStringLiteral("当前地址")),
        kernelText("kernel.platform.header.original", QStringLiteral("原始地址")),
        kernelText("kernel.platform.header.hook", QStringLiteral("Hook")),
        kernelText("kernel.platform.header.module", QStringLiteral("模块")),
        kernelText("kernel.platform.header.vendor", QStringLiteral("厂商")),
        kernelText("kernel.platform.header.table", QStringLiteral("表地址")),
        kernelText("kernel.platform.header.signature", QStringLiteral("签名策略")),
        kernelText("kernel.platform.header.confidence", QStringLiteral("置信度")),
        kernelText("kernel.platform.header.status", QStringLiteral("状态")),
        kernelText("kernel.platform.header.detail", QStringLiteral("备注"))
    };
    for (std::size_t index = 0U; index < m_pages.size(); ++index)
    {
        Page& page = m_pages[index];
        if (page.table != nullptr)
        {
            page.table->setHorizontalHeaderLabels(headers);
        }
        QString title;
        switch (page.scope)
        {
        case KSWORD_ARK_PLATFORM_AUDIT_SCOPE_HAL_DISPATCH:
            title = kernelText(
                "kernel.platform.hal.dispatch",
                QStringLiteral("HalDispatchTable"));
            break;
        case KSWORD_ARK_PLATFORM_AUDIT_SCOPE_HAL_PRIVATE:
            title = kernelText(
                "kernel.platform.hal.private",
                QStringLiteral("HalPrivateDispatchTable"));
            break;
        case KSWORD_ARK_PLATFORM_AUDIT_SCOPE_HAL_ACPI:
            title = kernelText(
                "kernel.platform.hal.acpi",
                QStringLiteral("HalAcpiDispatchTable"));
            break;
        case KSWORD_ARK_PLATFORM_AUDIT_SCOPE_HAL_SUBCOMPONENTS:
            title = kernelText(
                "kernel.platform.hal.subcomponents",
                QStringLiteral("HalSubComponents"));
            break;
        case KSWORD_ARK_PLATFORM_AUDIT_SCOPE_WDF_FUNCTIONS:
            title = kernelText(
                "kernel.platform.wdf.functions",
                QStringLiteral("WDF 函数"));
            break;
        case KSWORD_ARK_PLATFORM_AUDIT_SCOPE_WDF_CALLBACKS:
            title = kernelText(
                "kernel.platform.wdf.callbacks",
                QStringLiteral("WDF 回调"));
            break;
        default:
            break;
        }
        if (m_innerTabs != nullptr &&
            index < static_cast<std::size_t>(m_innerTabs->count()) &&
            !title.isEmpty())
        {
            m_innerTabs->setTabText(static_cast<int>(index), title);
        }
    }

    if (m_refreshRunning)
    {
        m_statusLabel->setText(kernelText(
            "kernel.platform.status.refreshing",
            QStringLiteral("状态：正在读取只读审计快照...")));
    }
    else if (m_hasResult)
    {
        applyResult(m_lastResult);
    }
    else
    {
        m_statusLabel->setText(kernelText(
            "kernel.platform.status.waiting",
            QStringLiteral("状态：等待刷新")));
    }
}

void KernelPlatformAuditTab::addPage(const unsigned long scope, const QString& title)
{
    auto* table = new ks::ui::VisibleTableWidget(m_innerTabs);
    table->setColumnCount(ColumnCount);
    table->setHorizontalHeaderLabels({
        kernelText("kernel.platform.header.name", QStringLiteral("函数 / 回调")),
        kernelText("kernel.platform.header.index", QStringLiteral("索引")),
        kernelText("kernel.platform.header.live", QStringLiteral("当前地址")),
        kernelText("kernel.platform.header.original", QStringLiteral("原始地址")),
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
    if (m_refreshThread.joinable())
    {
        // 中文说明：m_refreshRunning 只会由 GUI 回调清零，因此走到这里时
        // 上一 worker 已经完成；join 只回收句柄，不等待正在进行的查询。
        m_refreshThread.join();
    }
    {
        const std::lock_guard lock(m_refreshMutex);
        if (m_closing)
        {
            return;
        }
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
    {
        const std::lock_guard lock(m_refreshMutex);
        if (m_closing)
        {
            m_refreshRunning = false;
            m_refreshButton->setEnabled(true);
            return;
        }
        m_refreshThread = std::thread([this, scope]()
        {
            ksword::ark::DriverClient client;
            auto result = client.queryPlatformAudit(scope);
            if (result.io.ok)
            {
                enrichWdfFunctionBaselines(result);
            }
            {
                const std::lock_guard workerLock(m_refreshMutex);
                if (m_closing)
                {
                    return;
                }
                const bool posted = QMetaObject::invokeMethod(
                    this,
                    [this, result = std::move(result)]() mutable
                    {
                        {
                            const std::lock_guard guiLock(m_refreshMutex);
                            if (m_closing)
                            {
                                return;
                            }
                        }
                        applyResult(std::move(result));
                    },
                    Qt::QueuedConnection);
                // 中文说明：receiver 是页面自身；QObject 析构会丢弃未执行事件。
                // 投递失败时 worker 也不直接触碰 GUI。
                Q_UNUSED(posted);
            }
        });
    }
}

void KernelPlatformAuditTab::applyResult(ksword::ark::PlatformAuditResult result)
{
    QList<QTableView*> platformTables;
    platformTables.reserve(m_pages.size());
    for (const Page& page : m_pages)
    {
        platformTables.push_back(page.table);
    }
    if (ks::ui::IsTableUiCommitBlockedByContextMenu(platformTables))
    {
        // 所有平台审计页来自同一 R0 返回，必须保持同一代次原子提交。
        const QPointer<KernelPlatformAuditTab> safeThis(this);
        ks::ui::DeferTableUiCommitIfContextMenuOpen(
            this,
            QStringLiteral("kernel-platform-audit-apply"),
            platformTables,
            [safeThis, result = std::move(result)]() mutable
            {
                if (!safeThis.isNull())
                {
                    safeThis->applyResult(std::move(result));
                }
            });
        return;
    }

    m_lastResult = result;
    m_hasResult = true;
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
    QHash<QString, QString> companyCache;
    for (const KSWORD_ARK_PLATFORM_AUDIT_ENTRY& entry : result.entries)
    {
        // 中文说明：全局失败（例如模块快照不可用）会以本次请求的组合
        // scope 返回；组合诊断必须在每个受影响页面都可见。
        if ((entry.scope & page.scope) == 0UL)
        {
            continue;
        }
        const int row = page.table->rowCount();
        page.table->insertRow(row);
        QString signatureDisplay = signatureText(entry.signatureId);
        if (entry.prologueSignatureId != 0UL)
        {
            signatureDisplay += kernelText(
                "kernel.platform.signature.prologue_suffix",
                QStringLiteral(" / 函数头格式-%1"))
                .arg(entry.prologueSignatureId);
        }
        const QString modulePath =
            fixedWide(entry.modulePath, KSWORD_ARK_PLATFORM_MODULE_PATH_CHARS);
        if (!companyCache.contains(modulePath))
        {
            companyCache.insert(modulePath, companyNameForModule(modulePath));
        }
        const std::array<QString, ColumnCount> cells = {
            fixedWide(entry.name, KSWORD_ARK_PLATFORM_NAME_CHARS),
            QString::number(entry.entryIndex),
            addressText(entry.liveAddress),
            addressText(entry.originalAddress),
            hookText(entry.hookStatus),
            modulePath,
            companyCache.value(modulePath),
            addressText(entry.tableAddress),
            signatureDisplay,
            QStringLiteral("%1%").arg(entry.confidence),
            statusText(entry.status, entry.lastStatus),
            detailText(entry)
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
                    column == ColumnOriginalAddress ||
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
        text = kernelText("kernel.platform.value.ok", QStringLiteral("已读取"));
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
        return kernelText("kernel.platform.signature.public_hal_v6", QStringLiteral("公开 HAL v6"));
    case KSWORD_ARK_PLATFORM_SIGNATURE_WDF_BINDING_TABLE:
        return kernelText("kernel.platform.signature.wdf_binding", QStringLiteral("KMDF 绑定表"));
    case KSWORD_ARK_PLATFORM_SIGNATURE_X64_PROLOGUE:
        return kernelText("kernel.platform.signature.x64_format", QStringLiteral("x64 函数头格式"));
    case KSWORD_ARK_PLATFORM_SIGNATURE_EXACT_EXPORT_ONLY:
        return kernelText("kernel.platform.signature.exact_export", QStringLiteral("精确导出 / 失败关闭"));
    case KSWORD_ARK_PLATFORM_SIGNATURE_RIP_RELATIVE_MASKED:
        return kernelText("kernel.platform.signature.rip_masked", QStringLiteral("有界 byte/mask + RIP-relative"));
    case KSWORD_ARK_PLATFORM_SIGNATURE_HAL_PRIVATE_V54:
        return kernelText("kernel.platform.signature.private_v54", QStringLiteral("HAL 私有表 v54 / 0x4D8"));
    case KSWORD_ARK_PLATFORM_SIGNATURE_HAL_PRIVATE_V58:
        return kernelText("kernel.platform.signature.private_v58", QStringLiteral("HAL 私有表 v58 / 0x4F0"));
    case KSWORD_ARK_PLATFORM_SIGNATURE_HAL_PRIVATE_V61:
        return kernelText("kernel.platform.signature.private_v61", QStringLiteral("HAL 私有表 v61 / 0x518"));
    case KSWORD_ARK_PLATFORM_SIGNATURE_HAL_ACPI_V5:
        return kernelText("kernel.platform.signature.acpi_v5", QStringLiteral("HAL ACPI v5 / 18 项"));
    case KSWORD_ARK_PLATFORM_SIGNATURE_HAL_SUBCOMPONENTS_22:
        return kernelText("kernel.platform.signature.subcomponents_22", QStringLiteral("HAL 子组件 / 22 对"));
    default:
        return QStringLiteral("-");
    }
}

QString KernelPlatformAuditTab::detailText(
    const KSWORD_ARK_PLATFORM_AUDIT_ENTRY& entry)
{
    const auto hex = [](const unsigned long long value)
    {
        return QStringLiteral("0x%1").arg(value, 0, 16).toUpper();
    };

    switch (entry.detailCode)
    {
    case KSWORD_ARK_PLATFORM_DETAIL_OWNER_CONSISTENT:
        return kernelText(
            "kernel.platform.detail.owner_consistent",
            QStringLiteral("owner 与执行节一致；没有独立基线，结论保持 Unknown。"));
    case KSWORD_ARK_PLATFORM_DETAIL_OWNER_MISMATCH:
        return kernelText(
            "kernel.platform.detail.owner_mismatch",
            QStringLiteral("地址 %1 不属于该槽允许的 provider（策略 %2）。"))
            .arg(hex(entry.detailArgs[0]))
            .arg(entry.detailArgs[2]);
    case KSWORD_ARK_PLATFORM_DETAIL_NON_EXECUTABLE:
        return kernelText(
            "kernel.platform.detail.non_executable",
            QStringLiteral("地址 %1 不在所属模块的可执行节。"))
            .arg(hex(entry.detailArgs[0]));
    case KSWORD_ARK_PLATFORM_DETAIL_NULL_SLOT:
        return kernelText(
            "kernel.platform.detail.null_slot",
            QStringLiteral("槽位为空（offset/index %1）。"))
            .arg(hex(entry.detailArgs[0]));
    case KSWORD_ARK_PLATFORM_DETAIL_READ_FAILED:
        return kernelText(
            "kernel.platform.detail.read_failed",
            QStringLiteral("已验证范围内读取失败（offset/address %1，size %2）。"))
            .arg(hex(entry.detailArgs[0]))
            .arg(entry.detailArgs[1]);
    case KSWORD_ARK_PLATFORM_DETAIL_BUILD_UNSUPPORTED:
        return kernelText(
            "kernel.platform.detail.build_unsupported",
            QStringLiteral("Build %1 没有经过验证的结构/定位描述，当前 scope 失败关闭。"))
            .arg(entry.detailArgs[0]);
    case KSWORD_ARK_PLATFORM_DETAIL_VERSION_MISMATCH:
        return kernelText(
            "kernel.platform.detail.version_mismatch",
            QStringLiteral("结构版本不匹配：期望 %1，实际 %2；当前 scope 失败关闭。"))
            .arg(entry.detailArgs[0])
            .arg(entry.detailArgs[1]);
    case KSWORD_ARK_PLATFORM_DETAIL_RANGE_INVALID:
        return kernelText(
            "kernel.platform.detail.range_invalid",
            QStringLiteral("表的完整范围/所属节验证失败（期望字节 %1）。"))
            .arg(entry.detailArgs[0]);
    case KSWORD_ARK_PLATFORM_DETAIL_LOCATOR_NOT_UNIQUE:
        return kernelText(
            "kernel.platform.detail.locator_not_unique",
            QStringLiteral("可信锚点小窗口内出现多个完整候选，拒绝选择。"));
    case KSWORD_ARK_PLATFORM_DETAIL_LOCATOR_NOT_FOUND:
        return kernelText(
            "kernel.platform.detail.locator_not_found",
            QStringLiteral("可信锚点小窗口内没有唯一且完整验证的候选，当前 scope 失败关闭。"));
    case KSWORD_ARK_PLATFORM_DETAIL_TABLE_INVALID:
        return kernelText(
            "kernel.platform.detail.table_invalid",
            QStringLiteral("表元数据或完整结构验证失败。"));
    case KSWORD_ARK_PLATFORM_DETAIL_MODULE_SNAPSHOT_FAILED:
        return kernelText(
            "kernel.platform.detail.module_snapshot_failed",
            QStringLiteral("无法取得加载模块快照；没有 owner 证据时拒绝审计。"));
    case KSWORD_ARK_PLATFORM_DETAIL_SCALAR_VALUE:
        return kernelText(
            "kernel.platform.detail.scalar_value",
            QStringLiteral("标量值 %1（结构字节/offset %2）。"))
            .arg(hex(entry.detailArgs[0]))
            .arg(hex(entry.detailArgs[1]));
    case KSWORD_ARK_PLATFORM_DETAIL_DUMMY_SLOT:
        return kernelText(
            "kernel.platform.detail.dummy_slot",
            QStringLiteral("该描述明确标记为 dummy，不按函数指针解释；原值 %1。"))
            .arg(hex(entry.detailArgs[0]));
    case KSWORD_ARK_PLATFORM_DETAIL_DETOUR_EXTERNAL:
        return kernelText(
            "kernel.platform.detail.detour_external",
            QStringLiteral("检测到跳转：%1 -> %2，目标不属于允许的 provider。"))
            .arg(hex(entry.detailArgs[0]))
            .arg(hex(entry.detailArgs[1]));
    case KSWORD_ARK_PLATFORM_DETAIL_DETOUR_SAME_OWNER:
        return kernelText(
            "kernel.platform.detail.detour_same_owner",
            QStringLiteral("检测到同一允许 provider 内的跳转：%1 -> %2；没有独立基线，保持 Unknown。"))
            .arg(hex(entry.detailArgs[0]))
            .arg(hex(entry.detailArgs[1]));
    case KSWORD_ARK_PLATFORM_DETAIL_FORMAT_RECOGNIZED:
        return kernelText(
            "kernel.platform.detail.format_recognized",
            QStringLiteral("owner/执行节一致，函数头格式 %1 可识别；格式仅为提示，没有独立基线，保持 Unknown。"))
            .arg(entry.detailArgs[0]);
    case KSWORD_ARK_PLATFORM_DETAIL_FORMAT_UNKNOWN:
        return kernelText(
            "kernel.platform.detail.format_unknown",
            QStringLiteral("owner/执行节一致，但函数头不匹配通用格式；没有独立基线，保持 Unknown。"));
    case KSWORD_ARK_PLATFORM_DETAIL_WDF_TABLE_INVALID:
        return kernelText(
            "kernel.platform.detail.wdf_table_invalid",
            QStringLiteral("WDF 完整绑定表不在 Wdf01000.sys 的同一非执行节，或表项数无效。"));
    case KSWORD_ARK_PLATFORM_DETAIL_WDF_INDEX_INVALID:
        return kernelText(
            "kernel.platform.detail.wdf_index_invalid",
            QStringLiteral("WDF 表项索引/指针无效。"));
    case KSWORD_ARK_PLATFORM_DETAIL_ACPI_V5_VALIDATED:
        return kernelText(
            "kernel.platform.detail.acpi_v5_validated",
            QStringLiteral("HAL ACPI v5 的 Signature、Version 和 18 个函数已完整验证。"));
    case KSWORD_ARK_PLATFORM_DETAIL_SUBCOMPONENT_VALIDATED:
        return kernelText(
            "kernel.platform.detail.subcomponent_validated",
            QStringLiteral("22 对函数/UTF-16 名称（含 Qos）已完整验证。"));
    case KSWORD_ARK_PLATFORM_DETAIL_BASELINE_MATCH:
        return kernelText(
            "kernel.platform.detail.baseline_match",
            QStringLiteral("已验证磁盘映像基线匹配：当前地址 %1，原始地址 %2。"))
            .arg(hex(entry.detailArgs[0]))
            .arg(hex(entry.detailArgs[1]));
    case KSWORD_ARK_PLATFORM_DETAIL_BASELINE_MISMATCH:
        return kernelText(
            "kernel.platform.detail.baseline_mismatch",
            QStringLiteral("已验证磁盘映像基线不匹配：当前地址 %1，原始地址 %2。"))
            .arg(hex(entry.detailArgs[0]))
            .arg(hex(entry.detailArgs[1]));
    default:
        return QStringLiteral("-");
    }
}

QString KernelPlatformAuditTab::companyNameForModule(const QString& modulePath)
{
    if (modulePath.trimmed().isEmpty())
    {
        return QStringLiteral("-");
    }

    QString path = QDir::fromNativeSeparators(modulePath.trimmed());
    if (path.startsWith(QStringLiteral("/SystemRoot/"), Qt::CaseInsensitive))
    {
        wchar_t windowsDirectory[MAX_PATH] = {};
        const UINT length =
            ::GetWindowsDirectoryW(windowsDirectory, ARRAYSIZE(windowsDirectory));
        if (length == 0U || length >= ARRAYSIZE(windowsDirectory))
        {
            return QStringLiteral("-");
        }
        path = QDir::fromNativeSeparators(
            QString::fromWCharArray(windowsDirectory)) +
            path.mid(QStringLiteral("/SystemRoot").size());
    }
    else if (path.startsWith(QStringLiteral("/??/")) ||
             path.startsWith(QStringLiteral("//?/")))
    {
        path.remove(0, 4);
    }
    if (!QDir::isAbsolutePath(path))
    {
        return QStringLiteral("-");
    }
    path = QDir::toNativeSeparators(QDir::cleanPath(path));

    DWORD ignored = 0UL;
    const DWORD bytes = ::GetFileVersionInfoSizeW(
        reinterpret_cast<LPCWSTR>(path.utf16()),
        &ignored);
    if (bytes == 0UL ||
        bytes > static_cast<DWORD>(std::numeric_limits<int>::max()))
    {
        return QStringLiteral("-");
    }
    std::vector<unsigned char> versionData(bytes);
    if (!::GetFileVersionInfoW(
            reinterpret_cast<LPCWSTR>(path.utf16()),
            0UL,
            bytes,
            versionData.data()))
    {
        return QStringLiteral("-");
    }

    struct Translation
    {
        WORD language;
        WORD codePage;
    };
    Translation* translations = nullptr;
    UINT translationBytes = 0U;
    std::vector<Translation> candidates;
    if (::VerQueryValueW(
            versionData.data(),
            L"\\VarFileInfo\\Translation",
            reinterpret_cast<void**>(&translations),
            &translationBytes) &&
        translations != nullptr)
    {
        const UINT count = translationBytes / sizeof(Translation);
        candidates.assign(translations, translations + count);
    }
    candidates.push_back(Translation{ 0x0409U, 0x04B0U });

    for (const Translation candidate : candidates)
    {
        const QString block = QStringLiteral(
            "\\StringFileInfo\\%1%2\\CompanyName")
            .arg(candidate.language, 4, 16, QLatin1Char('0'))
            .arg(candidate.codePage, 4, 16, QLatin1Char('0'));
        wchar_t* company = nullptr;
        UINT companyChars = 0U;
        if (::VerQueryValueW(
                versionData.data(),
                reinterpret_cast<LPCWSTR>(block.utf16()),
                reinterpret_cast<void**>(&company),
                &companyChars) &&
            company != nullptr &&
            companyChars > 1U)
        {
            const QString value =
                QString::fromWCharArray(
                    company,
                    static_cast<int>(companyChars - 1U))
                    .trimmed();
            if (!value.isEmpty())
            {
                return value;
            }
        }
    }
    return QStringLiteral("-");
}
