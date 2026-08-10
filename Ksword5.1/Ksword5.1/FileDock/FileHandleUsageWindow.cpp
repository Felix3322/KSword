#include "FileHandleUsageWindow.h"
#include "../ArkDriverClient/ArkDriverClient.h"
#include "../Framework/DestructiveActionConfirmation.h"
#include "../Internationalization/LanguageManager.h"

// ============================================================
// FileHandleUsageWindow.cpp
// 作用：
// - 实现占用句柄结果窗口 UI；
// - 实现异步刷新、右键菜单与进程详情跳转；
// - 保持主线程仅负责渲染，扫描任务放在线程池。
// ============================================================

#include "../theme.h"
#include "../UI/TableInteractionSupport.h"
#include "../ksword/file/file_handle_tools.h"

#include <QAbstractItemView>
#include <QApplication>
#include <QClipboard>
#include <QDir>
#include <QHeaderView>
#include <QHBoxLayout>
#include <QLabel>
#include <QMenu>
#include <QMessageBox>
#include <QMetaObject>
#include <QPointer>
#include <QPushButton>
#include <QRunnable>
#include <QStringList>
#include <QThreadPool>
#include <QTreeWidget>
#include <QTreeWidgetItem>
#include <QResizeEvent>
#include <QVBoxLayout>

#include <memory>
#include <string>
#include <utility>

namespace
{
    // buildBlueButtonStyle 作用：生成统一蓝色按钮样式（图标按钮紧凑尺寸）。
    QString buildBlueButtonStyle()
    {
        return KswordTheme::ThemedButtonStyle();
    }

    // buildOpaqueHandleUsageDialogStyle 作用：
    // - 覆盖父级 Dock 透明样式，确保“文件占用”窗口在浅色主题不是黑底；
    // - 统一列表区和表头为主题色板背景。
    QString buildOpaqueHandleUsageDialogStyle(const QString& dialogObjectName)
    {
        return QStringLiteral(
            "QDialog#%1{"
            "  background-color:palette(window) !important;"
            "  color:palette(text) !important;"
            "}"
            "QDialog#%1 QTreeWidget,"
            "QDialog#%1 QAbstractScrollArea,"
            "QDialog#%1 QAbstractScrollArea::viewport{"
            "  background-color:palette(base) !important;"
            "  color:palette(text) !important;"
            "}"
            "QDialog#%1 QHeaderView::section{"
            "  background:transparent !important;"
            "  background-color:transparent !important;"
            "  color:palette(text) !important;"
            "}")
            .arg(dialogObjectName);
    }

    // formatHex 作用：把整数转为 0x 前缀十六进制文本。
    QString formatHex(const std::uint64_t value, const int width = 0)
    {
        if (width > 0)
        {
            return QStringLiteral("0x%1")
                .arg(static_cast<qulonglong>(value), width, 16, QChar('0'))
                .toUpper();
        }
        return QStringLiteral("0x%1")
            .arg(static_cast<qulonglong>(value), 0, 16)
            .toUpper();
    }

    bool isCriticalProcessName(const QString& processName)
    {
        static const QStringList criticalNameList{
            QStringLiteral("smss.exe"),
            QStringLiteral("csrss.exe"),
            QStringLiteral("wininit.exe"),
            QStringLiteral("services.exe"),
            QStringLiteral("lsass.exe"),
            QStringLiteral("winlogon.exe")
        };
        return criticalNameList.contains(processName.trimmed(), Qt::CaseInsensitive);
    }

}

FileHandleUsageWindow::FileHandleUsageWindow(const std::vector<QString>& targetPaths, QWidget* parent)
    : QDialog(parent)
    , m_targetPaths(targetPaths)
    , m_scanCancelRequested(std::make_shared<std::atomic_bool>(false))
{
    initializeUi();
    initializeConnections();
    requestRefresh(true);
}

FileHandleUsageWindow::~FileHandleUsageWindow()
{
    m_scanCancelRequested->store(true);
}

void FileHandleUsageWindow::setOpenProcessDetailCallback(OpenProcessDetailCallback callback)
{
    m_openProcessDetailCallback = std::move(callback);
}

void FileHandleUsageWindow::resizeEvent(QResizeEvent* event)
{
    QDialog::resizeEvent(event);
    applyAdaptiveColumnWidths();
}

void FileHandleUsageWindow::initializeUi()
{
    setObjectName(QStringLiteral("FileHandleUsageWindowRoot"));
    setAttribute(Qt::WA_StyledBackground, true);
    setAutoFillBackground(true);
    setStyleSheet(buildOpaqueHandleUsageDialogStyle(objectName()));

    setWindowTitle(QStringLiteral("占用句柄扫描结果"));
    setMinimumSize(1100, 680);

    m_rootLayout = new QVBoxLayout(this);
    m_rootLayout->setContentsMargins(8, 8, 8, 8);
    m_rootLayout->setSpacing(6);

    m_toolbarLayout = new QHBoxLayout();
    m_toolbarLayout->setContentsMargins(0, 0, 0, 0);
    m_toolbarLayout->setSpacing(6);

    // 刷新按钮：图标化并通过 tooltip 解释。
    m_refreshButton = new QPushButton(this);
    m_refreshButton->setIcon(QIcon(":/Icon/handle_refresh.svg"));
    m_refreshButton->setIconSize(QSize(16, 16));
    m_refreshButton->setFixedSize(28, 28);
    m_refreshButton->setToolTip(QStringLiteral("刷新扫描结果"));
    m_refreshButton->setStyleSheet(buildBlueButtonStyle());

    // 转到进程详情按钮：图标化并通过 tooltip 解释。
    m_openProcessButton = new QPushButton(this);
    m_openProcessButton->setIcon(QIcon(":/Icon/process_details.svg"));
    m_openProcessButton->setIconSize(QSize(16, 16));
    m_openProcessButton->setFixedSize(28, 28);
    m_openProcessButton->setToolTip(QStringLiteral("转到当前行的进程详细信息"));
    m_openProcessButton->setStyleSheet(buildBlueButtonStyle());

    // 解锁动作：占用扫描结果就是唯一的解锁工作台，直接对当前行执行可验证的动作。
    m_closeHandleButton = new QPushButton(this);
    m_closeHandleButton->setIcon(QIcon(":/Icon/handle_close.svg"));
    m_closeHandleButton->setIconSize(QSize(16, 16));
    m_closeHandleButton->setFixedSize(28, 28);
    m_closeHandleButton->setToolTip(ks::i18n::sourceText(QStringLiteral("关闭当前句柄(R3)")));
    m_closeHandleButton->setStyleSheet(buildBlueButtonStyle());

    m_terminateProcessButton = new QPushButton(this);
    m_terminateProcessButton->setIcon(QIcon(":/Icon/process_terminate.svg"));
    m_terminateProcessButton->setIconSize(QSize(16, 16));
    m_terminateProcessButton->setFixedSize(28, 28);
    m_terminateProcessButton->setToolTip(ks::i18n::sourceText(QStringLiteral("结束进程")));
    m_terminateProcessButton->setStyleSheet(buildBlueButtonStyle());

    m_terminateProcessR0Button = new QPushButton(this);
    m_terminateProcessR0Button->setIcon(QIcon(":/Icon/process_terminate.svg"));
    m_terminateProcessR0Button->setIconSize(QSize(16, 16));
    m_terminateProcessR0Button->setFixedSize(28, 28);
    m_terminateProcessR0Button->setToolTip(ks::i18n::sourceText(QStringLiteral("R0结束进程")));
    m_terminateProcessR0Button->setStyleSheet(buildBlueButtonStyle());

    QStringList pathTextList;
    for (const QString& pathText : m_targetPaths)
    {
        pathTextList.push_back(QDir::toNativeSeparators(pathText));
    }
    m_targetLabel = new QLabel(QStringLiteral("目标：%1").arg(pathTextList.join(QStringLiteral(" | "))), this);
    m_targetLabel->setTextInteractionFlags(Qt::TextSelectableByMouse);
    m_targetLabel->setStyleSheet(
        QStringLiteral("color:%1;font-weight:600;").arg(KswordTheme::TextPrimaryHex()));

    m_toolbarLayout->addWidget(m_refreshButton);
    m_toolbarLayout->addWidget(m_openProcessButton);
    m_toolbarLayout->addWidget(m_closeHandleButton);
    m_toolbarLayout->addWidget(m_terminateProcessButton);
    m_toolbarLayout->addWidget(m_terminateProcessR0Button);
    m_toolbarLayout->addWidget(m_targetLabel, 1);

    m_statusLabel = new QLabel(QStringLiteral("● 等待扫描"), this);
    m_statusLabel->setStyleSheet(
        QStringLiteral("color:%1;font-weight:600;").arg(KswordTheme::TextSecondaryHex()));

    m_resultTable = new QTreeWidget(this);
    m_resultTable->setColumnCount(static_cast<int>(TableColumn::Count));
    m_resultTable->setHeaderLabels(QStringList{
        QStringLiteral("PID"),
        QStringLiteral("进程名"),
        QStringLiteral("句柄"),
        QStringLiteral("类型"),
        QStringLiteral("对象名"),
        QStringLiteral("访问掩码"),
        QStringLiteral("命中目标"),
        QStringLiteral("命中规则"),
        QStringLiteral("来源"),
        QStringLiteral("进程路径")
        });
    m_resultTable->setRootIsDecorated(false);
    m_resultTable->setItemsExpandable(false);
    m_resultTable->setAlternatingRowColors(true);
    m_resultTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_resultTable->setSelectionMode(QAbstractItemView::SingleSelection);
    m_resultTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_resultTable->setSortingEnabled(true);
    m_resultTable->setContextMenuPolicy(Qt::CustomContextMenu);

    if (m_resultTable->header() != nullptr)
    {
        m_resultTable->header()->setSectionResizeMode(QHeaderView::Interactive);
        m_resultTable->header()->setStretchLastSection(false);
    }

    m_rootLayout->addLayout(m_toolbarLayout);
    m_rootLayout->addWidget(m_statusLabel);
    m_rootLayout->addWidget(m_resultTable, 1);
    applyAdaptiveColumnWidths();
}

void FileHandleUsageWindow::initializeConnections()
{
    connect(m_refreshButton, &QPushButton::clicked, this, [this]()
        {
            requestRefresh(true);
        });

    connect(m_openProcessButton, &QPushButton::clicked, this, [this]()
        {
            openCurrentProcessDetail();
        });

    connect(m_closeHandleButton, &QPushButton::clicked, this, [this]()
        {
            closeCurrentRemoteHandle();
        });

    connect(m_terminateProcessButton, &QPushButton::clicked, this, [this]()
        {
            terminateCurrentProcess(false);
        });

    connect(m_terminateProcessR0Button, &QPushButton::clicked, this, [this]()
        {
            terminateCurrentProcess(true);
        });

    connect(m_resultTable, &QTreeWidget::customContextMenuRequested, this, [this](const QPoint& localPosition)
        {
            showTableContextMenu(localPosition);
        });
}

void FileHandleUsageWindow::requestRefresh(const bool forceRefresh)
{
    if (m_refreshInProgress)
    {
        if (forceRefresh)
        {
            m_refreshPending = true;
        }
        return;
    }

    const std::uint64_t currentTicket = ++m_refreshTicket;
    m_refreshInProgress = true;
    m_statusLabel->setText(QStringLiteral("● 正在扫描占用句柄..."));
    m_statusLabel->setStyleSheet(QStringLiteral("color:%1;font-weight:700;").arg(KswordTheme::PrimaryBlueHex));

    if (m_refreshProgressPid <= 0)
    {
        m_refreshProgressPid = kPro.addReusable(this, "文件句柄扫描", "准备扫描目标占用句柄");
    }
    kPro.set(m_refreshProgressPid, "后台扫描中", 0, 20.0f);

    kLogEvent refreshEvent;
    info << refreshEvent
        << "[FileHandleUsageWindow] requestRefresh: ticket="
        << currentTicket
        << ", targetCount="
        << m_targetPaths.size()
        << eol;

    const std::vector<QString> targetPathsSnapshot = m_targetPaths;
    const int progressPid = m_refreshProgressPid;
    m_scanCancelRequested->store(false);
    const std::shared_ptr<std::atomic_bool> cancelRequested = m_scanCancelRequested;
    QPointer<FileHandleUsageWindow> guardThis(this);
    QPointer<QObject> uiDispatcher(QCoreApplication::instance());
    auto* refreshTask = QRunnable::create(
        [guardThis, uiDispatcher, currentTicket, targetPathsSnapshot, progressPid, cancelRequested]()
        {
            const filedock::handleusage::HandleUsageScanResult refreshResult =
                filedock::handleusage::scanHandleUsageByPaths(
                    targetPathsSnapshot,
                    progressPid,
                    true,
                    [cancelRequested]()
                    {
                        return cancelRequested->load();
                    });
            QObject* dispatcher = uiDispatcher.data();
            if (cancelRequested->load() || dispatcher == nullptr)
            {
                return;
            }

            QMetaObject::invokeMethod(
                dispatcher,
                [guardThis, cancelRequested, currentTicket, refreshResult]()
                {
                    if (cancelRequested->load() || guardThis == nullptr)
                    {
                        return;
                    }
                    guardThis->applyRefreshResult(currentTicket, refreshResult);
                },
                Qt::QueuedConnection);
        });
    refreshTask->setAutoDelete(true);
    QThreadPool::globalInstance()->start(refreshTask);
}

void FileHandleUsageWindow::applyRefreshResult(
    const std::uint64_t refreshTicket,
    const filedock::handleusage::HandleUsageScanResult& refreshResult)
{
    if (refreshTicket < m_refreshTicket)
    {
        return;
    }

    if (ks::ui::IsItemViewUiCommitBlockedByContextMenu({ m_resultTable }))
    {
        const auto refreshSnapshot =
            std::make_shared<filedock::handleusage::HandleUsageScanResult>(refreshResult);
        const QPointer<FileHandleUsageWindow> safeThis(this);
        if (ks::ui::DeferItemViewUiCommitIfContextMenuOpen(
            this,
            QStringLiteral("file-handle-usage-snapshot"),
            { m_resultTable },
            [safeThis, refreshTicket, refreshSnapshot]()
            {
                if (!safeThis.isNull())
                {
                    safeThis->applyRefreshResult(refreshTicket, *refreshSnapshot);
                }
            }))
        {
            return;
        }
    }

    m_entries = refreshResult.entries;
    rebuildTable(m_entries);

    m_refreshInProgress = false;
    kPro.set(m_refreshProgressPid, "扫描完成", 0, 100.0f);

    QString statusText = QStringLiteral("● 扫描完成 %1 ms | 总句柄:%2 | 文件句柄命中:%3 | 总命中:%4")
        .arg(refreshResult.elapsedMs)
        .arg(refreshResult.totalHandleCount)
        .arg(refreshResult.fileLikeHandleCount)
        .arg(refreshResult.matchedHandleCount);
    if (!refreshResult.diagnosticText.trimmed().isEmpty())
    {
        statusText += QStringLiteral(" | %1").arg(refreshResult.diagnosticText);
    }
    m_statusLabel->setText(statusText);

    const bool hasDiagnostic = !refreshResult.diagnosticText.trimmed().isEmpty();
    m_statusLabel->setStyleSheet(
        QStringLiteral("color:%1;font-weight:600;")
        .arg((hasDiagnostic ? KswordTheme::WarningColor() : KswordTheme::SuccessColor())
            .name(QColor::HexRgb)));

    kLogEvent doneEvent;
    info << doneEvent
        << "[FileHandleUsageWindow] applyRefreshResult: ticket="
        << refreshTicket
        << ", total="
        << refreshResult.totalHandleCount
        << ", fileLike="
        << refreshResult.fileLikeHandleCount
        << ", matched="
        << refreshResult.matchedHandleCount
        << ", elapsedMs="
        << refreshResult.elapsedMs
        << eol;

    if (m_refreshPending)
    {
        m_refreshPending = false;
        QMetaObject::invokeMethod(this, [this]()
            {
                requestRefresh(true);
            }, Qt::QueuedConnection);
    }
}

void FileHandleUsageWindow::rebuildTable(const std::vector<filedock::handleusage::HandleUsageEntry>& entries)
{
    m_resultTable->setSortingEnabled(false);
    m_resultTable->clear();

    for (std::size_t rowIndex = 0; rowIndex < entries.size(); ++rowIndex)
    {
        const filedock::handleusage::HandleUsageEntry& entry = entries[rowIndex];
        auto* item = new QTreeWidgetItem();
        item->setText(static_cast<int>(TableColumn::ProcessId), QString::number(entry.processId));
        item->setText(static_cast<int>(TableColumn::ProcessName), entry.processName);
        item->setText(
            static_cast<int>(TableColumn::HandleValue),
            entry.handleValue == 0 ? QStringLiteral("-") : formatHex(entry.handleValue, 0));
        item->setText(
            static_cast<int>(TableColumn::TypeName),
            entry.typeIndex == 0
            ? entry.typeName
            : QStringLiteral("%1 (%2)").arg(entry.typeName).arg(entry.typeIndex));
        item->setText(static_cast<int>(TableColumn::ObjectName), entry.objectName);
        item->setText(
            static_cast<int>(TableColumn::AccessMask),
            entry.grantedAccess == 0 ? QStringLiteral("-") : formatHex(entry.grantedAccess, 8));
        item->setText(static_cast<int>(TableColumn::MatchPath), entry.matchedTargetPath);
        item->setText(
            static_cast<int>(TableColumn::MatchRule),
            entry.matchRuleText.trimmed().isEmpty()
            ? ks::i18n::sourceText(entry.matchedByDirectoryRule
                ? QStringLiteral("目录前缀")
                : QStringLiteral("精确"))
            : entry.matchRuleText);
        item->setText(
            static_cast<int>(TableColumn::Source),
            entry.enumerationSource.trimmed().isEmpty() ? QStringLiteral("R3 DuplicateHandle") : entry.enumerationSource);
        item->setText(static_cast<int>(TableColumn::ProcessPath), entry.processImagePath);
        item->setData(static_cast<int>(TableColumn::ProcessId), Qt::UserRole, static_cast<qulonglong>(rowIndex));
        m_resultTable->addTopLevelItem(item);
    }

    if (m_resultTable->topLevelItemCount() > 0)
    {
        m_resultTable->setCurrentItem(m_resultTable->topLevelItem(0));
    }

    applyAdaptiveColumnWidths();
    m_resultTable->setSortingEnabled(true);
}

void FileHandleUsageWindow::applyAdaptiveColumnWidths()
{
    if (m_resultTable == nullptr || m_resultTable->header() == nullptr)
    {
        return;
    }

    QHeaderView* header = m_resultTable->header();
    header->setSectionResizeMode(QHeaderView::Interactive);

    const int viewportWidth = m_resultTable->viewport()->width();
    if (viewportWidth <= 0)
    {
        return;
    }

    const int pidWidth = 82;
    const int processNameWidth = 150;
    const int handleWidth = 110;
    const int typeWidth = 140;
    const int accessWidth = 120;
    const int ruleWidth = 150;
    const int sourceWidth = 150;

    m_resultTable->setColumnWidth(static_cast<int>(TableColumn::ProcessId), pidWidth);
    m_resultTable->setColumnWidth(static_cast<int>(TableColumn::ProcessName), processNameWidth);
    m_resultTable->setColumnWidth(static_cast<int>(TableColumn::HandleValue), handleWidth);
    m_resultTable->setColumnWidth(static_cast<int>(TableColumn::TypeName), typeWidth);
    m_resultTable->setColumnWidth(static_cast<int>(TableColumn::AccessMask), accessWidth);
    m_resultTable->setColumnWidth(static_cast<int>(TableColumn::MatchRule), ruleWidth);
    m_resultTable->setColumnWidth(static_cast<int>(TableColumn::Source), sourceWidth);

    const int fixedWidth =
        pidWidth + processNameWidth + handleWidth + typeWidth + accessWidth + ruleWidth + sourceWidth;
    const int flexibleWidth = std::max(420, viewportWidth - fixedWidth - 24);

    const int objectNameWidth = std::max(240, static_cast<int>(flexibleWidth * 0.40));
    const int matchPathWidth = std::max(220, static_cast<int>(flexibleWidth * 0.26));
    const int processPathWidth = std::max(220, flexibleWidth - objectNameWidth - matchPathWidth);

    m_resultTable->setColumnWidth(static_cast<int>(TableColumn::ObjectName), objectNameWidth);
    m_resultTable->setColumnWidth(static_cast<int>(TableColumn::MatchPath), matchPathWidth);
    m_resultTable->setColumnWidth(static_cast<int>(TableColumn::ProcessPath), processPathWidth);
}

const filedock::handleusage::HandleUsageEntry* FileHandleUsageWindow::selectedEntry() const
{
    if (m_resultTable == nullptr || m_resultTable->currentItem() == nullptr)
    {
        return nullptr;
    }

    const QVariant rowIndexValue =
        m_resultTable->currentItem()->data(static_cast<int>(TableColumn::ProcessId), Qt::UserRole);
    if (!rowIndexValue.isValid())
    {
        return nullptr;
    }
    const std::size_t rowIndex = static_cast<std::size_t>(rowIndexValue.toULongLong());
    if (rowIndex >= m_entries.size())
    {
        return nullptr;
    }
    return &m_entries[rowIndex];
}

void FileHandleUsageWindow::copyCurrentRow()
{
    if (m_resultTable == nullptr || m_resultTable->currentItem() == nullptr)
    {
        return;
    }

    QStringList fields;
    for (int columnIndex = 0; columnIndex < static_cast<int>(TableColumn::Count); ++columnIndex)
    {
        fields.push_back(m_resultTable->currentItem()->text(columnIndex));
    }
    QApplication::clipboard()->setText(fields.join('\t'));
}

void FileHandleUsageWindow::openCurrentProcessDetail()
{
    const filedock::handleusage::HandleUsageEntry* entry = selectedEntry();
    if (entry == nullptr)
    {
        QMessageBox::information(this, QStringLiteral("进程详情"), QStringLiteral("请先选择一条句柄记录。"));
        return;
    }

    if (!m_openProcessDetailCallback)
    {
        QMessageBox::warning(this, QStringLiteral("进程详情"), QStringLiteral("未配置进程详情跳转回调。"));
        return;
    }

    kLogEvent openDetailEvent;
    info << openDetailEvent
        << "[FileHandleUsageWindow] openCurrentProcessDetail: pid="
        << entry->processId
        << ", process="
        << entry->processName.toStdString()
        << eol;

    m_openProcessDetailCallback(entry->processId);
}

void FileHandleUsageWindow::closeCurrentRemoteHandle()
{
    // 第一步：读取当前选中句柄记录，并拒绝没有真实句柄值的合成来源。
    const filedock::handleusage::HandleUsageEntry* entry = selectedEntry();
    if (entry == nullptr)
    {
        QMessageBox::information(this, QStringLiteral("关闭句柄"), QStringLiteral("请先选择一条句柄记录。"));
        return;
    }
    const filedock::handleusage::HandleUsageEntry selectedHandleEntry = *entry;
    if (selectedHandleEntry.handleValue == 0U
        || selectedHandleEntry.processId == 0U
        || selectedHandleEntry.processId <= 4U)
    {
        QMessageBox::warning(
            this,
            QStringLiteral("关闭句柄"),
            QStringLiteral("当前记录没有可关闭的远程句柄，或目标 PID 受保护。"));
        return;
    }

    // 第二步：让用户确认，避免误关正在写入数据的文件句柄。
    const QMessageBox::StandardButton userChoice = QMessageBox::question(
        this,
        QStringLiteral("关闭句柄确认"),
        QStringLiteral("将尝试关闭 %1(%2) 中的句柄 %3。\n该操作可能导致目标进程读写失败，是否继续？")
        .arg(selectedHandleEntry.processName.trimmed().isEmpty()
            ? QStringLiteral("Unknown")
            : selectedHandleEntry.processName)
        .arg(selectedHandleEntry.processId)
        .arg(formatHex(selectedHandleEntry.handleValue, 0)),
        QMessageBox::Yes | QMessageBox::No,
        QMessageBox::No);
    if (userChoice != QMessageBox::Yes)
    {
        return;
    }

    // 第三步：复用 ks::file 后端关闭远程句柄；成功后立即刷新扫描结果。
    std::string detailText;
    const bool closeOk = ks::file::CloseRemoteHandle(
        selectedHandleEntry.processId,
        selectedHandleEntry.handleValue,
        selectedHandleEntry.processCreationTime,
        selectedHandleEntry.matchedTargetPath.toStdWString(),
        selectedHandleEntry.matchedByDirectoryRule,
        detailText);
    kLogEvent closeEvent;
    if (closeOk)
    {
        info << closeEvent
            << "[FileHandleUsageWindow] closeCurrentRemoteHandle success: pid="
            << selectedHandleEntry.processId
            << ", handle=0x"
            << QString::number(static_cast<qulonglong>(selectedHandleEntry.handleValue), 16).toUpper().toStdString()
            << eol;
        QMessageBox::information(this, QStringLiteral("关闭句柄"), QStringLiteral("句柄关闭成功，将重新扫描占用状态。"));
        requestRefresh(true);
        return;
    }

    warn << closeEvent
        << "[FileHandleUsageWindow] closeCurrentRemoteHandle failed: pid="
        << selectedHandleEntry.processId
        << ", handle=0x"
        << QString::number(static_cast<qulonglong>(selectedHandleEntry.handleValue), 16).toUpper().toStdString()
        << ", detail="
        << detailText
        << eol;
    QMessageBox::warning(
        this,
        QStringLiteral("关闭句柄"),
        QStringLiteral("关闭句柄失败：%1").arg(QString::fromStdString(detailText)));
}

void FileHandleUsageWindow::terminateCurrentProcess(const bool useKernelDriver)
{
    const filedock::handleusage::HandleUsageEntry* entry = selectedEntry();
    if (entry == nullptr)
    {
        QMessageBox::information(this, QStringLiteral("结束进程"), QStringLiteral("请先选择一条句柄记录。"));
        return;
    }

    const filedock::handleusage::HandleUsageEntry selectedProcessEntry = *entry;
    if (selectedProcessEntry.processId <= 4U ||
        selectedProcessEntry.processId == static_cast<std::uint32_t>(::GetCurrentProcessId()) ||
        selectedProcessEntry.processCreationTime == 0U ||
        isCriticalProcessName(selectedProcessEntry.processName))
    {
        QMessageBox::warning(
            this,
            QStringLiteral("结束进程"),
            QStringLiteral("当前记录没有可关闭的远程句柄，或目标 PID 受保护。"));
        return;
    }

    const QString actionTitle = useKernelDriver
        ? ks::i18n::sourceText(QStringLiteral("R0结束进程"))
        : ks::i18n::sourceText(QStringLiteral("结束进程"));
    const QString targetText = ks::i18n::sourceText(QStringLiteral("PID %1（%2）"))
        .arg(selectedProcessEntry.processId)
        .arg(selectedProcessEntry.processName.trimmed().isEmpty()
            ? QStringLiteral("Unknown")
            : selectedProcessEntry.processName);
    const QString riskText = useKernelDriver
        ? ks::i18n::sourceText(QStringLiteral(
            "R0 结束操作不可逆，可能造成数据丢失、系统不稳定或蓝屏。请确认目标无误后再继续。"))
        : QString();
    if (!ks::ui::confirmDestructiveAction(
            this,
            useKernelDriver
                ? QStringLiteral("file-handle-usage-terminate-r0")
                : QStringLiteral("file-handle-usage-terminate-r3"),
            actionTitle,
            targetText,
            riskText))
    {
        return;
    }

    std::string detailText;
    HANDLE verifiedProcessHandle = nullptr;
    if (!ks::file::OpenProcessForVerifiedAction(
            selectedProcessEntry.processId,
            selectedProcessEntry.processCreationTime,
            useKernelDriver ? SYNCHRONIZE : (PROCESS_TERMINATE | SYNCHRONIZE),
            verifiedProcessHandle,
            detailText))
    {
        QMessageBox::warning(this, actionTitle, QString::fromStdString(detailText));
        return;
    }

    bool terminateOk = false;
    if (useKernelDriver)
    {
        ksword::ark::DriverClient driverClient;
        const ksword::ark::IoResult driverResult = driverClient.terminateProcess(
            selectedProcessEntry.processId,
            static_cast<long>(0xC0000005U));
        detailText = driverResult.message;
        terminateOk = driverResult.ok;
    }
    else
    {
        const BOOL terminateResult = ::TerminateProcess(
            verifiedProcessHandle,
            static_cast<UINT>(0xC0000005U));
        terminateOk = terminateResult != FALSE;
        if (!terminateOk)
        {
            detailText = "TerminateProcess failed, error=" + std::to_string(::GetLastError());
        }
    }
    ::CloseHandle(verifiedProcessHandle);

    kLogEvent terminateEvent;
    if (terminateOk)
    {
        info << terminateEvent
            << "[FileHandleUsageWindow] terminateCurrentProcess success: method="
            << (useKernelDriver ? "R0" : "R3")
            << ", pid="
            << selectedProcessEntry.processId
            << eol;
        requestRefresh(true);
        return;
    }

    warn << terminateEvent
        << "[FileHandleUsageWindow] terminateCurrentProcess failed: method="
        << (useKernelDriver ? "R0" : "R3")
        << ", pid="
        << selectedProcessEntry.processId
        << ", detail="
        << detailText
        << eol;
    QMessageBox::warning(this, actionTitle, QString::fromStdString(detailText));
}

void FileHandleUsageWindow::showTableContextMenu(const QPoint& localPosition)
{
    if (m_resultTable == nullptr)
    {
        return;
    }

    QTreeWidgetItem* clickedItem = m_resultTable->itemAt(localPosition);
    if (clickedItem == nullptr)
    {
        return;
    }
    m_resultTable->setCurrentItem(clickedItem);

    QMenu menu(this);
    menu.setStyleSheet(KswordTheme::ContextMenuStyle());
    QAction* openProcessAction = menu.addAction(QIcon(":/Icon/process_details.svg"), QStringLiteral("转到进程详细信息"));
    QAction* closeHandleAction = menu.addAction(QIcon(":/Icon/handle_close.svg"), QStringLiteral("关闭当前句柄(R3)"));
    QAction* terminateProcessAction = menu.addAction(
        QIcon(":/Icon/process_terminate.svg"),
        ks::i18n::sourceText(QStringLiteral("结束进程")));
    QAction* terminateProcessR0Action = menu.addAction(
        QIcon(":/Icon/process_terminate.svg"),
        ks::i18n::sourceText(QStringLiteral("R0结束进程")));
    QAction* copyRowAction = menu.addAction(QIcon(":/Icon/handle_copy_row.svg"), QStringLiteral("复制整行"));

    QAction* selectedAction = menu.exec(m_resultTable->viewport()->mapToGlobal(localPosition));
    if (selectedAction == nullptr)
    {
        return;
    }
    if (selectedAction == openProcessAction)
    {
        openCurrentProcessDetail();
        return;
    }
    if (selectedAction == closeHandleAction)
    {
        closeCurrentRemoteHandle();
        return;
    }
    if (selectedAction == terminateProcessAction)
    {
        terminateCurrentProcess(false);
        return;
    }
    if (selectedAction == terminateProcessR0Action)
    {
        terminateCurrentProcess(true);
        return;
    }
    if (selectedAction == copyRowAction)
    {
        copyCurrentRow();
    }
}
