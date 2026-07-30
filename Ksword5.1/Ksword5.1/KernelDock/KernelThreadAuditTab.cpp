#include "KernelThreadAuditTab.h"

#include "../ArkDriverClient/ArkDriverClient.h"
#include "../Internationalization/LanguageManager.h"
#include "../UI/CodeEditorWidget.h"
#include "../theme.h"

#include <QAbstractItemView>
#include <QAction>
#include <QCoreApplication>
#include <QEvent>
#include <QHeaderView>
#include <QHBoxLayout>
#include <QIcon>
#include <QLabel>
#include <QLineEdit>
#include <QMenu>
#include <QMessageBox>
#include <QMetaObject>
#include <QPointer>
#include <QPushButton>
#include <QSplitter>
#include <QTableWidget>
#include <QTableWidgetItem>
#include <QThreadPool>
#include <QTimer>
#include <QVBoxLayout>

#include <algorithm>
#include <limits>
#include <memory>
#include <utility>

namespace
{
    // threadAuditText：
    // - 输入 key：语言包稳定键；fallbackText：中文回退文本；
    // - 处理：统一走 LanguageManager 上下文翻译；
    // - 返回：当前语言下的页面文本。
    QString threadAuditText(const char* key, const QString& fallbackText)
    {
        return ks::i18n::contextText(QString::fromLatin1(key), fallbackText);
    }

    constexpr std::uint32_t kWaitReasonQueue = 15U; // KWAIT_REASON::WrQueue。

    // menuStyle：
    // - 返回不透明 QMenu 主题；
    // - 解决浅色模式下透明菜单导致的黑底黑字问题。
    QString menuStyle()
    {
        return QStringLiteral(
            "QMenu{background:%1;color:%2;border:1px solid %3;padding:4px;}"
            "QMenu::item{padding:5px 24px 5px 8px;}"
            "QMenu::item:selected{background:%4;color:%5;}"
            "QMenu::item:disabled{color:%6;}")
            .arg(KswordTheme::SurfaceHex())
            .arg(KswordTheme::TextPrimaryHex())
            .arg(KswordTheme::BorderHex())
            .arg(KswordTheme::PrimaryBlueHex)
            .arg(QStringLiteral("#FFFFFF"))
            .arg(KswordTheme::TextSecondaryHex());
    }

    // messageBoxStyle：
    // - 为本页危险操作确认框显式设置不透明背景；
    // - 保证浅色和深色主题均可读取风险文本。
    QString messageBoxStyle()
    {
        return QStringLiteral(
            "QMessageBox{background:%1;color:%2;}"
            "QMessageBox QLabel{background:transparent;color:%2;min-width:440px;}"
            "QMessageBox QPushButton{min-width:90px;padding:6px 12px;}")
            .arg(KswordTheme::SurfaceHex())
            .arg(KswordTheme::TextPrimaryHex());
    }

    // showConfirmation：
    // - 输入 parent/title/body：确认框宿主与文本；
    // - 处理：显式主题、Yes/No、默认 No；
    // - 返回：用户明确选择 Yes 时为 true。
    bool showConfirmation(QWidget* parent, const QString& titleText, const QString& bodyText)
    {
        QMessageBox confirmationBox(QMessageBox::Warning, titleText, bodyText, QMessageBox::NoButton, parent);
        confirmationBox.setStyleSheet(messageBoxStyle());
        confirmationBox.setTextFormat(Qt::PlainText);
        QPushButton* yesButton = confirmationBox.addButton(QMessageBox::Yes);
        QPushButton* noButton = confirmationBox.addButton(QMessageBox::No);
        confirmationBox.setDefaultButton(noButton);
        confirmationBox.setEscapeButton(noButton);
        confirmationBox.exec();
        return confirmationBox.clickedButton() == yesButton;
    }

    // showResultMessage：
    // - 输入 success：决定信息或警告图标；
    // - 处理：显示带不透明主题的结果弹窗；
    // - 返回：无。
    void showResultMessage(
        QWidget* parent,
        const bool success,
        const QString& titleText,
        const QString& bodyText)
    {
        QMessageBox resultBox(
            success ? QMessageBox::Information : QMessageBox::Warning,
            titleText,
            bodyText,
            QMessageBox::Ok,
            parent);
        resultBox.setStyleSheet(messageBoxStyle());
        resultBox.setTextFormat(Qt::PlainText);
        resultBox.exec();
    }

}

KernelThreadAuditTab::KernelThreadAuditTab(const Mode mode, QWidget* parent)
    : QWidget(parent),
      m_mode(mode)
{
    initializeUi();
    applyTranslatedText();

    // 首次刷新延后到事件循环，避免 Dock 构造阶段同步查询系统信息。
    QTimer::singleShot(0, this, [this]() {
        requestRefresh();
    });
}

void KernelThreadAuditTab::initializeUi()
{
    // 根布局：风险说明常驻顶部，工具栏、表格和详情垂直排列。
    auto* rootLayout = new QVBoxLayout(this);
    rootLayout->setContentsMargins(6, 6, 6, 6);
    rootLayout->setSpacing(6);

    auto* safetyLabel = new QLabel(this);
    safetyLabel->setObjectName(QStringLiteral("kernelThreadAuditSafetyLabel"));
    safetyLabel->setWordWrap(true);
    safetyLabel->setStyleSheet(QStringLiteral(
        "QLabel#kernelThreadAuditSafetyLabel{background:%1;color:%2;"
        "border:1px solid %3;border-radius:4px;padding:7px;}")
        .arg(KswordTheme::SurfaceAltHex())
        .arg(KswordTheme::TextPrimaryHex())
        .arg(KswordTheme::WarningHex()));
    rootLayout->addWidget(safetyLabel);

    // 工具栏按钮使用图标和 tooltip；A/B 按钮按列组规范紧贴放置。
    auto* toolLayout = new QHBoxLayout();
    toolLayout->setContentsMargins(0, 0, 0, 0);
    toolLayout->setSpacing(4);

    m_refreshButton = new QPushButton(QIcon(QStringLiteral(":/Icon/process_refresh.svg")), QString(), this);
    m_suspendButton = new QPushButton(QIcon(QStringLiteral(":/Icon/process_pause.svg")), QString(), this);
    m_resumeButton = new QPushButton(QIcon(QStringLiteral(":/Icon/process_resume.svg")), QString(), this);
    m_terminateButton = new QPushButton(QIcon(QStringLiteral(":/Icon/process_terminate.svg")), QString(), this);
    for (QPushButton* actionButton : { m_refreshButton, m_suspendButton, m_resumeButton, m_terminateButton })
    {
        actionButton->setFixedSize(30, 30);
        actionButton->setIconSize(QSize(16, 16));
    }

    m_overviewButton = new QPushButton(QStringLiteral("A"), this);
    m_evidenceButton = new QPushButton(QStringLiteral("B"), this);
    m_overviewButton->setFixedSize(28, 28);
    m_evidenceButton->setFixedSize(28, 28);

    m_filterEdit = new QLineEdit(this);
    m_filterEdit->setClearButtonEnabled(true);
    m_statusLabel = new QLabel(this);
    m_statusLabel->setStyleSheet(QStringLiteral("QLabel{color:%1;}").arg(KswordTheme::TextSecondaryHex()));

    toolLayout->addWidget(m_refreshButton);
    toolLayout->addSpacing(3);
    toolLayout->addWidget(m_suspendButton);
    toolLayout->addWidget(m_resumeButton);
    toolLayout->addWidget(m_terminateButton);
    toolLayout->addSpacing(7);
    toolLayout->addWidget(m_overviewButton);
    toolLayout->addWidget(m_evidenceButton);
    toolLayout->addWidget(m_filterEdit, 1);
    toolLayout->addWidget(m_statusLabel);
    rootLayout->addLayout(toolLayout);

    // 表格与 CodeEditorWidget 由纵向 splitter 组织，详情窗口保持项目统一编辑器。
    auto* splitter = new QSplitter(Qt::Vertical, this);
    m_table = new QTableWidget(splitter);
    m_table->setColumnCount(static_cast<int>(Column::Count));
    m_table->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_table->setSelectionMode(QAbstractItemView::SingleSelection);
    m_table->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_table->setAlternatingRowColors(true);
    m_table->setSortingEnabled(true);
    m_table->setContextMenuPolicy(Qt::CustomContextMenu);
    m_table->verticalHeader()->setVisible(false);
    m_table->horizontalHeader()->setStretchLastSection(true);
    m_table->horizontalHeader()->setContextMenuPolicy(Qt::CustomContextMenu);

    m_detailEditor = new CodeEditorWidget(splitter);
    m_detailEditor->setReadOnly(true);
    splitter->setStretchFactor(0, 4);
    splitter->setStretchFactor(1, 2);
    rootLayout->addWidget(splitter, 1);

    // 连接：刷新、筛选、选择、A/B 列组、表头菜单和行操作菜单。
    connect(m_refreshButton, &QPushButton::clicked, this, [this]() { requestRefresh(); });
    connect(m_filterEdit, &QLineEdit::textChanged, this, [this]() { rebuildTable(); });
    connect(m_table, &QTableWidget::itemSelectionChanged, this, [this]() { updateDetail(); });
    connect(m_overviewButton, &QPushButton::clicked, this, [this]() {
        applyColumnPreset(ViewPreset::Overview);
    });
    connect(m_evidenceButton, &QPushButton::clicked, this, [this]() {
        applyColumnPreset(ViewPreset::Evidence);
    });
    connect(m_table->horizontalHeader(), &QHeaderView::customContextMenuRequested, this,
        [this](const QPoint& localPosition) { showHeaderMenu(localPosition); });
    connect(m_table, &QTableWidget::customContextMenuRequested, this,
        [this](const QPoint& localPosition) { showRowMenu(localPosition); });
    connect(m_suspendButton, &QPushButton::clicked, this, [this]() {
        runControlAction(KSWORD_ARK_DRIVER_THREAD_ACTION_SUSPEND);
    });
    connect(m_resumeButton, &QPushButton::clicked, this, [this]() {
        runControlAction(KSWORD_ARK_DRIVER_THREAD_ACTION_RESUME);
    });
    connect(m_terminateButton, &QPushButton::clicked, this, [this]() {
        runControlAction(KSWORD_ARK_DRIVER_THREAD_ACTION_TERMINATE);
    });

    applyColumnPreset(ViewPreset::Overview);
}

void KernelThreadAuditTab::applyTranslatedText()
{
    // 安全说明根据模式区分“全部系统线程”与“工作队列候选”。
    QLabel* safetyLabel = findChild<QLabel*>(QStringLiteral("kernelThreadAuditSafetyLabel"));
    if (safetyLabel != nullptr)
    {
        const QString safetyText = m_mode == Mode::SystemThreads
            ? threadAuditText(
                "thread_audit.system.safety",
                QStringLiteral("安全边界：只允许管理启动入口明确归属于第三方驱动的 System 线程；"
                               "ntoskrnl、KswordARK、未知归属和当前执行线程由 UI 与 R0 双重拒绝。"))
            : threadAuditText(
                "thread_audit.work_queue.safety",
                QStringLiteral("安全边界：本页只用 WrQueue 与可信 ActiveExWorker 标志识别候选；"
                               "不会猜测未公开工作队列链表、队列类型或工作项参数。"));
        safetyLabel->setText(safetyText);
    }

    // 图标按钮只通过 tooltip 表达动作含义。
    m_refreshButton->setToolTip(threadAuditText("thread_audit.tooltip.refresh", QStringLiteral("刷新线程审计快照")));
    m_suspendButton->setToolTip(threadAuditText("thread_audit.tooltip.suspend", QStringLiteral("挂起选中的第三方驱动系统线程")));
    m_resumeButton->setToolTip(threadAuditText("thread_audit.tooltip.resume", QStringLiteral("恢复选中的第三方驱动系统线程")));
    m_terminateButton->setToolTip(threadAuditText("thread_audit.tooltip.terminate", QStringLiteral("终止选中的第三方驱动系统线程（高风险）")));
    m_overviewButton->setToolTip(threadAuditText("thread_audit.tooltip.view_a", QStringLiteral("A：调度与队列概览")));
    m_evidenceButton->setToolTip(threadAuditText("thread_audit.tooltip.view_b", QStringLiteral("B：入口地址与模块归属证据")));
    m_filterEdit->setPlaceholderText(threadAuditText("thread_audit.filter.placeholder", QStringLiteral("按 TID、状态、队列或模块筛选")));
    m_filterEdit->setToolTip(threadAuditText("thread_audit.filter.tooltip", QStringLiteral("输入关键字后实时过滤当前线程快照")));

    // 表头按固定 Column 顺序翻译；A/B 预设只控制可见性，不改变数据列。
    m_table->setHorizontalHeaderLabels(QStringList{
        threadAuditText("thread_audit.header.tid", QStringLiteral("线程ID")),
        threadAuditText("thread_audit.header.category", QStringLiteral("类别")),
        threadAuditText("thread_audit.header.queue_type", QStringLiteral("队列类型")),
        threadAuditText("thread_audit.header.state", QStringLiteral("线程状态")),
        threadAuditText("thread_audit.header.wait_reason", QStringLiteral("等待原因")),
        threadAuditText("thread_audit.header.routine", QStringLiteral("例程入口")),
        threadAuditText("thread_audit.header.parameter", QStringLiteral("参数")),
        threadAuditText("thread_audit.header.module", QStringLiteral("入口模块")),
        threadAuditText("thread_audit.header.module_base", QStringLiteral("模块基址")),
        threadAuditText("thread_audit.header.module_path", QStringLiteral("模块路径")),
        threadAuditText("thread_audit.header.r0_status", QStringLiteral("R0状态")),
        threadAuditText("thread_audit.header.protection", QStringLiteral("管理保护"))
    });

    if (m_rows.empty() && !m_refreshRunning)
    {
        m_statusLabel->setText(threadAuditText("thread_audit.status.waiting", QStringLiteral("状态：等待刷新")));
        m_detailEditor->setText(threadAuditText("thread_audit.detail.initial", QStringLiteral("请选择一条线程记录查看证据与安全边界。")));
    }
    updatePresetButtons();
}

void KernelThreadAuditTab::requestRefresh()
{
    if (m_refreshRunning)
    {
        return;
    }

    m_refreshRunning = true;
    const std::uint64_t refreshTicket = ++m_refreshTicket;
    m_refreshButton->setEnabled(false);
    m_statusLabel->setText(threadAuditText("thread_audit.status.refreshing", QStringLiteral("状态：正在采集线程与模块证据...")));

    // 后台只构造值类型 Snapshot；UI 控件仅在主线程回调中访问。
    QPointer<KernelThreadAuditTab> guardThis(this);
    const Mode requestedMode = m_mode;
    QThreadPool::globalInstance()->start([guardThis, refreshTicket, requestedMode]() {
        auto snapshot = std::make_shared<Snapshot>(collectSnapshot(requestedMode));
        QMetaObject::invokeMethod(
            QCoreApplication::instance(),
            [guardThis, refreshTicket, snapshot]() {
                if (guardThis == nullptr || refreshTicket != guardThis->m_refreshTicket)
                {
                    return;
                }
                guardThis->applySnapshot(*snapshot);
            },
            Qt::QueuedConnection);
    });
}

void KernelThreadAuditTab::applySnapshot(const Snapshot& snapshot)
{
    m_rows = snapshot.rows;
    m_refreshRunning = false;
    m_refreshButton->setEnabled(true);
    rebuildTable();

    // 状态栏同时暴露 R3 枚举路径、R0 可用性和降级诊断。
    m_statusLabel->setText(
        threadAuditText(
            "thread_audit.status.completed",
            QStringLiteral("状态：%1 条；R3=%2；R0=%3；%4"))
            .arg(static_cast<qulonglong>(m_rows.size()))
            .arg(snapshot.usedNtQuery ? QStringLiteral("NtQuery") : QStringLiteral("Toolhelp"))
            .arg(snapshot.r0Available ? QStringLiteral("OK") : QStringLiteral("Unavailable"))
            .arg(snapshot.diagnosticText));
}

void KernelThreadAuditTab::rebuildTable()
{
    const QString filterText = m_filterEdit->text().trimmed();
    m_table->setSortingEnabled(false);
    m_table->setRowCount(0);

    // appendTextItem：统一创建不可编辑单元格并保存源行索引。
    for (std::size_t sourceIndex = 0; sourceIndex < m_rows.size(); ++sourceIndex)
    {
        const ThreadRow& row = m_rows[sourceIndex];
        const QString categoryText = row.activeWorker
            ? threadAuditText("thread_audit.category.worker", QStringLiteral("Ex工作线程"))
            : threadAuditText("thread_audit.category.system", QStringLiteral("系统线程"));
        const QString queueTypeText = row.activeWorker
            ? threadAuditText("thread_audit.queue.ex_worker", QStringLiteral("Ex worker（具体队列不可安全区分）"))
            : (row.waitReason == kWaitReasonQueue
                ? threadAuditText("thread_audit.queue.waiting", QStringLiteral("队列等待（具体类型不可安全区分）"))
                : threadAuditText("thread_audit.queue.unconfirmed", QStringLiteral("未确认")));
        const QString parameterText = threadAuditText("thread_audit.parameter.unavailable", QStringLiteral("<公开接口无法安全获取>"));
        const QString moduleText = row.moduleResolved
            ? row.module.name
            : threadAuditText("thread_audit.module.unknown", QStringLiteral("<未知归属>"));
        const QString protectionText = row.protectedTarget
            ? threadAuditText("thread_audit.protection.blocked", QStringLiteral("已保护：%1")).arg(row.protectionReason)
            : threadAuditText("thread_audit.protection.allowed", QStringLiteral("第三方驱动线程（需确认）"));

        const QStringList cellTexts{
            QString::number(row.threadId),
            categoryText,
            queueTypeText,
            stateText(row.state),
            waitReasonText(row.waitReason),
            addressText(row.startAddress),
            parameterText,
            moduleText,
            addressText(row.module.baseAddress),
            row.module.path,
            r0StatusText(row.r0Status),
            protectionText
        };
        if (!filterText.isEmpty() &&
            !cellTexts.join(QLatin1Char(' ')).contains(filterText, Qt::CaseInsensitive))
        {
            continue;
        }

        const int targetRow = m_table->rowCount();
        m_table->insertRow(targetRow);
        for (int columnIndex = 0; columnIndex < static_cast<int>(Column::Count); ++columnIndex)
        {
            auto* item = new QTableWidgetItem(cellTexts.value(columnIndex));
            item->setData(Qt::UserRole, static_cast<qulonglong>(sourceIndex));
            if (columnIndex == static_cast<int>(Column::ThreadId))
            {
                item->setData(Qt::DisplayRole, static_cast<qulonglong>(row.threadId));
            }
            m_table->setItem(targetRow, columnIndex, item);
        }
    }

    m_table->setSortingEnabled(true);
    m_table->resizeColumnsToContents();
    updateDetail();
}

void KernelThreadAuditTab::updateDetail()
{
    const ThreadRow* row = selectedRow();
    if (row == nullptr)
    {
        m_detailEditor->setText(threadAuditText("thread_audit.detail.initial", QStringLiteral("请选择一条线程记录查看证据与安全边界。")));
        m_suspendButton->setEnabled(false);
        m_resumeButton->setEnabled(false);
        m_terminateButton->setEnabled(false);
        return;
    }

    // 管理按钮只在 R3 已解析第三方模块且 R0 允许再次校验时启用。
    const bool actionAllowed = !row->protectedTarget && row->startAddress != 0U;
    m_suspendButton->setEnabled(actionAllowed);
    m_resumeButton->setEnabled(actionAllowed);
    m_terminateButton->setEnabled(actionAllowed);

    QStringList detailLines;
    detailLines
        << threadAuditText("thread_audit.detail.identity", QStringLiteral("[线程身份]"))
        << QStringLiteral("TID: %1").arg(row->threadId)
        << QStringLiteral("Priority/BasePriority: %1/%2").arg(row->priority).arg(row->basePriority)
        << QStringLiteral("State: %1 (%2)").arg(stateText(row->state)).arg(row->state)
        << QStringLiteral("WaitReason: %1 (%2)").arg(waitReasonText(row->waitReason)).arg(row->waitReason)
        << QString()
        << threadAuditText("thread_audit.detail.queue", QStringLiteral("[工作队列证据]"))
        << QStringLiteral("ActiveExWorkerKnown: %1").arg(row->workerKnown ? QStringLiteral("true") : QStringLiteral("false"))
        << QStringLiteral("ActiveExWorker: %1").arg(row->activeWorker ? QStringLiteral("true") : QStringLiteral("false"))
        << QStringLiteral("WrQueue: %1").arg(row->waitReason == kWaitReasonQueue ? QStringLiteral("true") : QStringLiteral("false"))
        << threadAuditText(
            "thread_audit.detail.queue_boundary",
            QStringLiteral("QueueType/WorkItemParameter: 未读取未公开链表或参数，避免错误偏移导致系统崩溃。"))
        << QString()
        << threadAuditText("thread_audit.detail.module", QStringLiteral("[入口与模块归属]"))
        << QStringLiteral("StartRoutine: %1").arg(addressText(row->startAddress))
        << QStringLiteral("Module: %1").arg(row->moduleResolved ? row->module.name : QStringLiteral("<unresolved>"))
        << QStringLiteral("ModuleBase/Size: %1 / 0x%2")
            .arg(addressText(row->module.baseAddress))
            .arg(row->module.imageSize, 0, 16)
        << QStringLiteral("ModulePath: %1").arg(row->module.path)
        << QString()
        << threadAuditText("thread_audit.detail.safety", QStringLiteral("[管理安全]"))
        << QStringLiteral("Protected: %1").arg(row->protectedTarget ? QStringLiteral("true") : QStringLiteral("false"))
        << QStringLiteral("Reason: %1").arg(row->protectionReason)
        << threadAuditText(
            "thread_audit.detail.safety_boundary",
            QStringLiteral("所有操作仍由 R0 重新核对 PID=4、真实启动地址、模块范围、内核/KswordARK/当前线程保护。"));
    m_detailEditor->setText(detailLines.join(QLatin1Char('\n')));
}

void KernelThreadAuditTab::applyColumnPreset(const ViewPreset preset)
{
    m_viewPreset = preset;

    // A：调度/队列概览；B：地址/模块/R0 证据。两组均保持精简。
    const std::vector<Column> visibleColumns = preset == ViewPreset::Evidence
        ? std::vector<Column>{
            Column::ThreadId,
            Column::StartRoutine,
            Column::Parameter,
            Column::Module,
            Column::ModuleBase,
            Column::ModulePath,
            Column::R0Status,
            Column::Protection }
        : std::vector<Column>{
            Column::ThreadId,
            Column::Category,
            Column::QueueType,
            Column::State,
            Column::WaitReason,
            Column::Module,
            Column::Protection };

    for (int columnIndex = 0; columnIndex < static_cast<int>(Column::Count); ++columnIndex)
    {
        const Column column = static_cast<Column>(columnIndex);
        const bool visible = std::find(visibleColumns.begin(), visibleColumns.end(), column) != visibleColumns.end();
        m_table->setColumnHidden(columnIndex, !visible);
    }
    updatePresetButtons();
}

void KernelThreadAuditTab::updatePresetButtons()
{
    const QString activeStyle = QStringLiteral(
        "QPushButton{background:%1;color:white;border:1px solid %1;border-radius:3px;font-weight:600;}")
        .arg(KswordTheme::PrimaryBlueHex);
    const QString inactiveStyle = QStringLiteral(
        "QPushButton{background:%1;color:%2;border:1px solid %3;border-radius:3px;}")
        .arg(KswordTheme::SurfaceHex())
        .arg(KswordTheme::TextPrimaryHex())
        .arg(KswordTheme::BorderHex());

    m_overviewButton->setStyleSheet(m_viewPreset == ViewPreset::Overview ? activeStyle : inactiveStyle);
    m_evidenceButton->setStyleSheet(m_viewPreset == ViewPreset::Evidence ? activeStyle : inactiveStyle);
}

void KernelThreadAuditTab::showHeaderMenu(const QPoint& localPosition)
{
    QMenu columnMenu(this);
    columnMenu.setStyleSheet(menuStyle());

    // 表头菜单允许逐列勾选；手工改变后 A/B 都取消着色，表示 Custom。
    for (int columnIndex = 0; columnIndex < static_cast<int>(Column::Count); ++columnIndex)
    {
        const QString headerText = m_table->horizontalHeaderItem(columnIndex) != nullptr
            ? m_table->horizontalHeaderItem(columnIndex)->text()
            : QString::number(columnIndex);
        QAction* columnAction = columnMenu.addAction(headerText);
        columnAction->setCheckable(true);
        columnAction->setChecked(!m_table->isColumnHidden(columnIndex));
        connect(columnAction, &QAction::toggled, this, [this, columnIndex](const bool visible) {
            m_table->setColumnHidden(columnIndex, !visible);
            m_viewPreset = ViewPreset::Custom;
            updatePresetButtons();
        });
    }
    columnMenu.exec(m_table->horizontalHeader()->mapToGlobal(localPosition));
}

void KernelThreadAuditTab::showRowMenu(const QPoint& localPosition)
{
    if (m_table->itemAt(localPosition) != nullptr)
    {
        m_table->selectRow(m_table->itemAt(localPosition)->row());
    }

    const ThreadRow* row = selectedRow();
    QMenu actionMenu(this);
    actionMenu.setStyleSheet(menuStyle());
    QAction* suspendAction = actionMenu.addAction(
        QIcon(QStringLiteral(":/Icon/process_pause.svg")),
        threadAuditText("thread_audit.menu.suspend", QStringLiteral("挂起第三方驱动线程")));
    QAction* resumeAction = actionMenu.addAction(
        QIcon(QStringLiteral(":/Icon/process_resume.svg")),
        threadAuditText("thread_audit.menu.resume", QStringLiteral("恢复第三方驱动线程")));
    QAction* terminateAction = actionMenu.addAction(
        QIcon(QStringLiteral(":/Icon/process_terminate.svg")),
        threadAuditText("thread_audit.menu.terminate", QStringLiteral("终止第三方驱动线程（高风险）")));

    const bool actionAllowed = row != nullptr && !row->protectedTarget && row->startAddress != 0U;
    suspendAction->setEnabled(actionAllowed);
    resumeAction->setEnabled(actionAllowed);
    terminateAction->setEnabled(actionAllowed);
    QAction* selectedAction = actionMenu.exec(m_table->viewport()->mapToGlobal(localPosition));
    if (selectedAction == suspendAction)
    {
        runControlAction(KSWORD_ARK_DRIVER_THREAD_ACTION_SUSPEND);
    }
    else if (selectedAction == resumeAction)
    {
        runControlAction(KSWORD_ARK_DRIVER_THREAD_ACTION_RESUME);
    }
    else if (selectedAction == terminateAction)
    {
        runControlAction(KSWORD_ARK_DRIVER_THREAD_ACTION_TERMINATE);
    }
}

void KernelThreadAuditTab::runControlAction(const unsigned long action)
{
    const ThreadRow* row = selectedRow();
    if (row == nullptr)
    {
        return;
    }
    if (row->protectedTarget || row->startAddress == 0U)
    {
        showResultMessage(
            this,
            false,
            threadAuditText("thread_audit.dialog.blocked.title", QStringLiteral("系统线程操作已阻止")),
            threadAuditText("thread_audit.dialog.blocked.body", QStringLiteral("该线程受到保护：%1")).arg(row->protectionReason));
        return;
    }

    const QString targetText = QStringLiteral("TID=%1\nStart=%2\nModule=%3")
        .arg(row->threadId)
        .arg(addressText(row->startAddress))
        .arg(row->module.name);
    const bool terminating = action == KSWORD_ARK_DRIVER_THREAD_ACTION_TERMINATE;
    const QString actionTitle = terminating
        ? threadAuditText("thread_audit.dialog.terminate.title", QStringLiteral("终止系统线程"))
        : (action == KSWORD_ARK_DRIVER_THREAD_ACTION_SUSPEND
            ? threadAuditText("thread_audit.dialog.suspend.title", QStringLiteral("挂起系统线程"))
            : threadAuditText("thread_audit.dialog.resume.title", QStringLiteral("恢复系统线程")));
    const QString firstWarning = terminating
        ? threadAuditText(
            "thread_audit.dialog.terminate.warning",
            QStringLiteral("高风险：终止驱动系统线程可能造成设备失效、数据丢失或系统崩溃。\n\n%1\n\n确认继续？")).arg(targetText)
        : threadAuditText(
            "thread_audit.dialog.control.warning",
            QStringLiteral("改变驱动系统线程调度状态可能造成设备失效或系统卡死。\n\n%1\n\n确认继续？")).arg(targetText);
    if (!showConfirmation(this, actionTitle, firstWarning))
    {
        return;
    }

    // 终止动作执行第二次独立确认；恢复/挂起保持一次确认。
    if (terminating &&
        !showConfirmation(
            this,
            threadAuditText("thread_audit.dialog.terminate.second.title", QStringLiteral("最终终止确认")),
            threadAuditText(
                "thread_audit.dialog.terminate.second.body",
                QStringLiteral("这是不可逆操作。R0 会再次校验线程身份，但无法保证目标驱动可以安全恢复。\n\n再次确认终止 TID %1？"))
                .arg(row->threadId)))
    {
        return;
    }

    const unsigned long terminateMethod = terminating
        ? KSWORD_ARK_DRIVER_THREAD_TERMINATE_METHOD_NORMAL_APC
        : KSWORD_ARK_DRIVER_THREAD_TERMINATE_METHOD_NONE;
    const bool uiConfirmed = action != KSWORD_ARK_DRIVER_THREAD_ACTION_RESUME;
    const ksword::ark::DriverClient driverClient;
    const ksword::ark::IoResult result = driverClient.controlDriverThread(
        row->threadId,
        row->startAddress,
        action,
        terminateMethod,
        uiConfirmed);

    kLogEvent controlEvent;
    if (result.ok)
    {
        info << controlEvent
            << "[KernelThreadAuditTab] 系统线程控制完成, tid="
            << row->threadId
            << ", action="
            << action
            << eol;
    }
    else
    {
        err << controlEvent
            << "[KernelThreadAuditTab] 系统线程控制失败, tid="
            << row->threadId
            << ", action="
            << action
            << ", detail="
            << result.message
            << eol;
    }

    const QString resultDetail = QString::fromStdString(result.message);
    showResultMessage(
        this,
        result.ok,
        actionTitle,
        result.ok
            ? threadAuditText("thread_audit.dialog.result.success", QStringLiteral("操作已由 R0 完成。\n%1")).arg(resultDetail)
            : threadAuditText("thread_audit.dialog.result.failure", QStringLiteral("R0 拒绝或执行失败。\n%1")).arg(resultDetail));
    requestRefresh();
}

const KernelThreadAuditTab::ThreadRow* KernelThreadAuditTab::selectedRow() const
{
    const int sourceIndex = selectedSourceIndex();
    if (sourceIndex < 0 || static_cast<std::size_t>(sourceIndex) >= m_rows.size())
    {
        return nullptr;
    }
    return &m_rows[static_cast<std::size_t>(sourceIndex)];
}

int KernelThreadAuditTab::selectedSourceIndex() const
{
    const QList<QTableWidgetItem*> selectedItems = m_table->selectedItems();
    if (selectedItems.isEmpty())
    {
        return -1;
    }
    const qulonglong sourceIndex = selectedItems.first()->data(Qt::UserRole).toULongLong();
    if (sourceIndex > static_cast<qulonglong>((std::numeric_limits<int>::max)()))
    {
        return -1;
    }
    return static_cast<int>(sourceIndex);
}

// collectSnapshot 的实现位于 KernelThreadAuditTab.Snapshot.cpp。

// queryKernelModules 的实现位于 KernelThreadAuditTab.Snapshot.cpp。

// findOwnerModule 的实现位于 KernelThreadAuditTab.Snapshot.cpp。

QString KernelThreadAuditTab::stateText(const std::uint32_t stateValue)
{
    switch (stateValue)
    {
    case 0U: return threadAuditText("thread_audit.state.initialized", QStringLiteral("已初始化"));
    case 1U: return threadAuditText("thread_audit.state.ready", QStringLiteral("就绪"));
    case 2U: return threadAuditText("thread_audit.state.running", QStringLiteral("运行中"));
    case 3U: return threadAuditText("thread_audit.state.standby", QStringLiteral("待运行"));
    case 4U: return threadAuditText("thread_audit.state.terminated", QStringLiteral("已终止"));
    case 5U: return threadAuditText("thread_audit.state.waiting", QStringLiteral("等待中"));
    case 6U: return threadAuditText("thread_audit.state.transition", QStringLiteral("转换中"));
    case 7U: return threadAuditText("thread_audit.state.deferred_ready", QStringLiteral("延迟就绪"));
    default: return QStringLiteral("Unknown(%1)").arg(stateValue);
    }
}

QString KernelThreadAuditTab::waitReasonText(const std::uint32_t waitReasonValue)
{
    switch (waitReasonValue)
    {
    case 0U: return QStringLiteral("Executive");
    case 4U: return QStringLiteral("DelayExecution");
    case 5U: return QStringLiteral("Suspended");
    case 6U: return QStringLiteral("UserRequest");
    case 7U: return QStringLiteral("WrExecutive");
    case 11U: return QStringLiteral("WrDelayExecution");
    case 12U: return QStringLiteral("WrSuspended");
    case 13U: return QStringLiteral("WrUserRequest");
    case kWaitReasonQueue: return QStringLiteral("WrQueue");
    case 16U: return QStringLiteral("WrLpcReceive");
    case 17U: return QStringLiteral("WrLpcReply");
    case 25U: return QStringLiteral("WrCalloutStack");
    case 26U: return QStringLiteral("WrKernel");
    case 27U: return QStringLiteral("WrResource");
    case 28U: return QStringLiteral("WrPushLock");
    case 29U: return QStringLiteral("WrMutex");
    default: return QStringLiteral("Reason(%1)").arg(waitReasonValue);
    }
}

QString KernelThreadAuditTab::r0StatusText(const std::uint32_t statusValue)
{
    switch (statusValue)
    {
    case KSWORD_ARK_THREAD_R0_STATUS_OK: return QStringLiteral("OK");
    case KSWORD_ARK_THREAD_R0_STATUS_PARTIAL: return QStringLiteral("Partial");
    case KSWORD_ARK_THREAD_R0_STATUS_DYNDATA_MISSING: return QStringLiteral("DynData missing");
    case KSWORD_ARK_THREAD_R0_STATUS_READ_FAILED: return QStringLiteral("Read failed");
    default: return QStringLiteral("Unavailable");
    }
}

QString KernelThreadAuditTab::addressText(const std::uint64_t addressValue)
{
    if (addressValue == 0U)
    {
        return QStringLiteral("Unavailable");
    }
    return QStringLiteral("0x%1")
        .arg(static_cast<qulonglong>(addressValue), 0, 16)
        .toUpper();
}

void KernelThreadAuditTab::changeEvent(QEvent* event)
{
    QWidget::changeEvent(event);
    if (event != nullptr && event->type() == QEvent::LanguageChange)
    {
        applyTranslatedText();
        rebuildTable();
    }
}
