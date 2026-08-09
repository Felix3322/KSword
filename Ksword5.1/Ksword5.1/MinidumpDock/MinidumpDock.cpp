// ============================================================
// MinidumpDock.cpp
// 作用：
// - 实现转储分析页的界面骨架与交互：
//   工具栏（路径 + 浏览 + 系统目录 + 解析 + 导出）、状态栏与结果页签；
// - 解析任务通过全局线程池执行，用 generation + 共享 owner 状态
//   防止过期结果回写与退出阶段竞态（与 ScannerDock 相同的模式）；
// - 表格渲染与报告生成的实现位于 MinidumpDock.Tables.cpp。
// ============================================================

#include "MinidumpDock.h"

#include "../Framework.h"
#include "Internationalization/LanguageManager.h"
#include "MinidumpParser.h"
#include "UI/CodeEditorWidget.h"

#include <QDir>
#include <QEvent>
#include <QFile>
#include <QFileDialog>
#include <QFileInfo>
#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QMessageBox>
#include <QMetaObject>
#include <QPushButton>
#include <QStyle>
#include <QTabWidget>
#include <QTableWidget>
#include <QThreadPool>
#include <QVBoxLayout>

#include <exception>
#include <mutex>
#include <utility>

// MinidumpAsyncState 作用：把 worker 的回投目标放在共享互斥状态中。
// 析构前先清空 owner；worker 只有在同一把锁保护下才能提交 queued 调用，
// 从而消除应用退出阶段的接收者竞态。
struct MinidumpAsyncState
{
    std::mutex mutex;               // mutex：保护 owner 的读写。
    MinidumpDock* owner = nullptr;  // owner：结果回投的目标控件；析构后为空。
};

namespace
{
    // defaultDumpDirectory 作用：给文件选择器一个有意义的起始目录。
    // 优先系统蓝屏小型转储目录，其次 Windows 目录（MEMORY.DMP 所在），
    // 都不存在时回退用户主目录；返回本地风格路径。
    QString defaultDumpDirectory()
    {
        // systemRoot：SystemRoot 环境变量；服务化环境可能为空。
        const QString systemRoot = qEnvironmentVariable("SystemRoot", QStringLiteral("C:\\Windows"));
        const QString minidumpDir = systemRoot + QStringLiteral("\\Minidump");
        if (QFileInfo::exists(minidumpDir))
        {
            return QDir::toNativeSeparators(minidumpDir);
        }
        if (QFileInfo::exists(systemRoot))
        {
            return QDir::toNativeSeparators(systemRoot);
        }
        return QDir::toNativeSeparators(QDir::homePath());
    }
}

MinidumpDock::MinidumpDock(QWidget* parent)
    : QWidget(parent)
{
    // m_asyncState：与 worker 共享的生命周期状态，必须先于任何解析建立。
    m_asyncState = std::make_shared<MinidumpAsyncState>();
    m_asyncState->owner = this;
    buildUi();
    retranslateUi();
    setStatus(
        "minidump.status.idle",
        "选择一个转储文件开始解析：支持应用崩溃 MDMP 与系统蓝屏 DMP。");
}

MinidumpDock::~MinidumpDock()
{
    // 加锁清空 owner：此后 worker 即使完成也不会再向本控件投递结果。
    std::lock_guard<std::mutex> lock(m_asyncState->mutex);
    m_asyncState->owner = nullptr;
}

void MinidumpDock::changeEvent(QEvent* event)
{
    QWidget::changeEvent(event);
    if (event != nullptr && event->type() == QEvent::LanguageChange)
    {
        retranslateUi();
    }
}

void MinidumpDock::buildUi()
{
    // rootLayout：承载路径工具条、状态提示与结果页签。
    auto* rootLayout = new QVBoxLayout(this);
    rootLayout->setContentsMargins(8, 8, 8, 8);
    rootLayout->setSpacing(8);

    // pathLayout：路径输入与全部动作按钮排在同一行。
    auto* pathLayout = new QHBoxLayout();
    pathLayout->setSpacing(6);
    m_pathLabel = new QLabel(this);
    m_pathEdit = new QLineEdit(this);
    m_pathEdit->setClearButtonEnabled(true);
    m_browseButton = new QPushButton(this);
    m_systemDirButton = new QPushButton(this);
    m_parseButton = new QPushButton(this);
    m_exportButton = new QPushButton(this);
    // 图标：含义简单的按钮用标准图标表达，文字配合悬停释义。
    m_browseButton->setIcon(style()->standardIcon(QStyle::SP_DialogOpenButton));
    m_systemDirButton->setIcon(style()->standardIcon(QStyle::SP_DirIcon));
    m_parseButton->setIcon(style()->standardIcon(QStyle::SP_BrowserReload));
    m_exportButton->setIcon(style()->standardIcon(QStyle::SP_DialogSaveButton));
    m_exportButton->setEnabled(false);
    pathLayout->addWidget(m_pathLabel);
    pathLayout->addWidget(m_pathEdit, 1);
    pathLayout->addWidget(m_browseButton);
    pathLayout->addWidget(m_systemDirButton);
    pathLayout->addWidget(m_parseButton);
    pathLayout->addWidget(m_exportButton);
    rootLayout->addLayout(pathLayout);

    // m_statusLabel：允许复制诊断状态，长路径自动换行。
    m_statusLabel = new QLabel(this);
    m_statusLabel->setWordWrap(true);
    m_statusLabel->setTextInteractionFlags(Qt::TextSelectableByMouse);
    rootLayout->addWidget(m_statusLabel);

    // m_resultTabs：解析结果页签；具体页在 renderResult 里按数据动态挂载。
    m_resultTabs = new QTabWidget(this);
    m_resultTabs->setDocumentMode(true);
    rootLayout->addWidget(m_resultTabs, 1);

    // 预创建全部表格与报告编辑器：语言切换/重复解析时复用，不反复销毁。
    m_analysisTable = createReadOnlyTable(m_resultTabs);
    m_blameTable = createReadOnlyTable(m_resultTabs);
    m_stackTable = createReadOnlyTable(m_resultTabs);
    m_registerTable = createReadOnlyTable(m_resultTabs);
    m_overviewTable = createReadOnlyTable(m_resultTabs);
    m_exceptionTable = createReadOnlyTable(m_resultTabs);
    m_streamTable = createReadOnlyTable(m_resultTabs);
    m_moduleTable = createReadOnlyTable(m_resultTabs);
    m_threadTable = createReadOnlyTable(m_resultTabs);
    m_memoryTable = createReadOnlyTable(m_resultTabs);
    m_handleTable = createReadOnlyTable(m_resultTabs);
    m_unloadedTable = createReadOnlyTable(m_resultTabs);
    // 诊断结论与调用栈都以长文本为主，允许换行以免关键结论被省略号截断。
    m_analysisTable->setWordWrap(true);
    m_blameTable->setWordWrap(true);
    // 调用栈表不拆 A/B/C：它的“来源”列标着「栈扫描（可能误报）」，
    // 一旦被列组预设隐藏，整页就再没有任何地方提示这些帧是猜的。
    // 六列在正常窗口宽度下放得下，没必要为它牺牲这条提示。
    m_stackPage = m_stackTable;
    // 宽表包装成 A/B/C 列组页；列数与 Tables.cpp 的填充逻辑保持一致。
    m_modulePage = createStructuredTablePage(m_moduleTable, 8);
    m_threadPage = createStructuredTablePage(m_threadTable, 13);
    m_memoryPage = createStructuredTablePage(m_memoryTable, 6);
    m_handlePage = createStructuredTablePage(m_handleTable, 7);
    m_reportEditor = new CodeEditorWidget(m_resultTabs);

    // 所有动作统一进入成员函数的校验流程。
    connect(m_browseButton, &QPushButton::clicked, this, [this]() { chooseFile(); });
    connect(m_systemDirButton, &QPushButton::clicked, this, [this]()
        {
            // 系统目录按钮：直接把选择器定位到蓝屏转储目录。
            m_pathEdit->setText(defaultDumpDirectory());
            chooseFile();
        });
    connect(m_parseButton, &QPushButton::clicked, this, [this]() { beginParse(); });
    connect(m_exportButton, &QPushButton::clicked, this, [this]() { exportReport(); });
    connect(m_pathEdit, &QLineEdit::returnPressed, this, [this]() { beginParse(); });
}

QString MinidumpDock::translated(const char* key, const char* fallback) const
{
    return ks::i18n::text(
        QString::fromLatin1(key),
        QString::fromUtf8(fallback));
}

void MinidumpDock::retranslateUi()
{
    m_pathLabel->setText(translated("minidump.path.label", "转储文件"));
    m_pathEdit->setPlaceholderText(translated(
        "minidump.path.placeholder",
        "选择要解析的转储文件（应用崩溃 .dmp / 蓝屏 Minidump / MEMORY.DMP）"));
    m_browseButton->setText(translated("minidump.action.browse", "浏览…"));
    m_browseButton->setToolTip(translated(
        "minidump.action.browse.tooltip",
        "选择一个转储文件进行只读解析"));
    m_systemDirButton->setText(translated("minidump.action.system_dir", "系统转储"));
    m_systemDirButton->setToolTip(translated(
        "minidump.action.system_dir.tooltip",
        "定位到系统蓝屏转储目录（C:\\Windows\\Minidump）"));
    m_parseButton->setText(translated("minidump.action.parse", "解析"));
    m_parseButton->setToolTip(translated(
        "minidump.action.parse.tooltip",
        "在后台解析转储结构，不会修改目标文件"));
    m_exportButton->setText(translated("minidump.action.export", "导出报告"));
    m_exportButton->setToolTip(translated(
        "minidump.action.export.tooltip",
        "把当前解析结果的全文报告保存为文本文件"));
    refreshStatus();

    // 已有结果时按新语言重建所有页签文本。
    if (m_lastResult)
    {
        renderResult(*m_lastResult);
    }
}

void MinidumpDock::chooseFile()
{
    // startDir：优先当前输入的路径（或其所在目录），否则用系统转储目录。
    QString startDir = m_pathEdit->text().trimmed();
    if (!startDir.isEmpty())
    {
        const QFileInfo startInfo(startDir);
        startDir = startInfo.isDir() ? startInfo.absoluteFilePath() : startInfo.absolutePath();
    }
    if (startDir.isEmpty() || !QFileInfo::exists(startDir))
    {
        startDir = defaultDumpDirectory();
    }
    const QString selectedPath = QFileDialog::getOpenFileName(
        this,
        translated("minidump.dialog.choose_file", "选择转储文件"),
        startDir,
        translated(
            "minidump.dialog.file_filter",
            "转储文件 (*.dmp *.mdmp *.hdmp *.kdmp);;所有文件 (*.*)"));
    if (selectedPath.isEmpty())
    {
        return;
    }
    m_pathEdit->setText(QDir::toNativeSeparators(selectedPath));
    beginParse();
}

void MinidumpDock::beginParse()
{
    if (m_parseBusy)
    {
        return;
    }

    // fileInfo：启动线程前先排除空路径、目录和不存在的目标。
    const QString path = QDir::toNativeSeparators(m_pathEdit->text().trimmed());
    const QFileInfo fileInfo(path);
    if (path.isEmpty() || !fileInfo.exists() || !fileInfo.isFile())
    {
        QMessageBox::warning(
            this,
            translated("minidump.dialog.invalid_file.title", "无法解析"),
            translated("minidump.dialog.invalid_file.body", "请选择一个存在的转储文件。"));
        return;
    }

    m_pathEdit->setText(path);
    setBusy(true);
    setStatus(
        "minidump.status.parsing",
        "正在解析：%1",
        QStringList{ path });

    {
        // 解析开始日志：整个动作链共用一个 kLogEvent 便于追踪。
        kLogEvent parseEvent;
        info << parseEvent << "MinidumpDock 开始解析转储文件: "
             << path.toStdString() << eol;
    }

    // generation：只有最新一代结果可以回写，避免旧解析覆盖新目标。
    const std::uint64_t generation = ++m_parseGeneration;
    const std::shared_ptr<MinidumpAsyncState> asyncState = m_asyncState;
    QThreadPool::globalInstance()->start(
        [asyncState, generation, path]()
        {
            // result：worker 中完成的解析产物；自包含，与文件映射无关联。
            // 解析的输入是不可信文件，畸形样本可能让某个列表申请超大内存。
            // 线程池 worker 里逃逸的异常会直接 std::terminate 掉整个进程，
            // 因此这里必须兜住，把它降级成一次“解析失败”。
            std::shared_ptr<ks::minidump::DumpParseResult> result;
            try
            {
                result = std::make_shared<ks::minidump::DumpParseResult>(
                    ks::minidump::ParseDumpFile(path));
            }
            catch (const std::exception& error)
            {
                result = std::make_shared<ks::minidump::DumpParseResult>();
                result->filePath = path;
                result->errorText =
                    QStringLiteral("解析过程中发生异常，文件可能已损坏或结构异常：%1")
                        .arg(QString::fromUtf8(error.what()));
            }
            catch (...)
            {
                result = std::make_shared<ks::minidump::DumpParseResult>();
                result->filePath = path;
                result->errorText =
                    QStringLiteral("解析过程中发生未知异常，文件可能已损坏或结构异常。");
            }
            std::lock_guard<std::mutex> lock(asyncState->mutex);
            MinidumpDock* receiver = asyncState->owner;
            if (receiver == nullptr)
            {
                return;
            }
            QMetaObject::invokeMethod(
                receiver,
                [asyncState, generation, result = std::move(result)]()
                {
                    // owner 复核：queued 回调真正执行时控件可能已析构。
                    MinidumpDock* owner = nullptr;
                    {
                        std::lock_guard<std::mutex> stateLock(asyncState->mutex);
                        owner = asyncState->owner;
                    }
                    if (owner != nullptr)
                    {
                        owner->finishParse(generation, result);
                    }
                },
                Qt::QueuedConnection);
        });
}

void MinidumpDock::finishParse(
    const std::uint64_t generation,
    std::shared_ptr<ks::minidump::DumpParseResult> result)
{
    if (generation != m_parseGeneration.load() || !result)
    {
        return;
    }

    setBusy(false);
    m_lastResult = std::move(result);
    renderResult(*m_lastResult);
    m_exportButton->setEnabled(m_lastResult->success);

    {
        // 解析结束日志：记录结果类别与成败，方便回溯。
        kLogEvent parseEvent;
        if (m_lastResult->success)
        {
            info << parseEvent << "MinidumpDock 解析完成: "
                 << m_lastResult->filePath.toStdString()
                 << " 模块 " << m_lastResult->modules.size()
                 << " 线程 " << m_lastResult->threads.size() << eol;
        }
        else
        {
            warn << parseEvent << "MinidumpDock 解析失败: "
                 << m_lastResult->filePath.toStdString()
                 << " 原因: " << m_lastResult->errorText.toStdString() << eol;
        }
    }

    if (m_lastResult->success)
    {
        // kindText：结果类别的状态词，走词条翻译后再代入状态文本。
        QString kindText;
        switch (m_lastResult->kind)
        {
        case ks::minidump::DumpKind::UserMinidump:
            kindText = translated("minidump.kind.user", "用户态 MDMP");
            break;
        case ks::minidump::DumpKind::KernelDump64:
            kindText = translated("minidump.kind.kernel64", "64 位内核转储");
            break;
        case ks::minidump::DumpKind::KernelDump32:
            kindText = translated("minidump.kind.kernel32", "32 位内核转储");
            break;
        default:
            kindText = translated("minidump.kind.unknown", "未知");
            break;
        }
        setStatus(
            "minidump.status.success",
            "解析完成：%1（%2）。",
            QStringList{ m_lastResult->filePath, kindText });
    }
    else if (m_lastResult->recognized)
    {
        // errorText 为解析层产出的中文规范文本，整串词条翻译后代入。
        setStatus(
            "minidump.status.malformed",
            "已识别转储格式，但内容损坏或截断：%1",
            QStringList{ ks::i18n::sourceText(m_lastResult->errorText) });
    }
    else
    {
        setStatus(
            "minidump.status.unrecognized",
            "不是受支持的转储文件：%1",
            QStringList{ ks::i18n::sourceText(m_lastResult->errorText) });
    }
}

void MinidumpDock::exportReport()
{
    if (!m_lastResult || !m_lastResult->success)
    {
        return;
    }
    // suggestedName：默认与转储同名的 .txt 报告文件。
    const QFileInfo dumpInfo(m_lastResult->filePath);
    const QString suggestedName = dumpInfo.completeBaseName() + QStringLiteral("_report.txt");
    const QString savePath = QFileDialog::getSaveFileName(
        this,
        translated("minidump.dialog.export_report", "导出解析报告"),
        QDir::toNativeSeparators(dumpInfo.absolutePath() + QStringLiteral("/") + suggestedName),
        translated("minidump.dialog.report_filter", "文本文件 (*.txt);;所有文件 (*.*)"));
    if (savePath.isEmpty())
    {
        return;
    }
    QFile reportFile(savePath);
    if (!reportFile.open(QIODevice::WriteOnly | QIODevice::Truncate))
    {
        QMessageBox::warning(
            this,
            translated("minidump.dialog.export_failed.title", "导出失败"),
            translated("minidump.dialog.export_failed.body", "无法写入目标文件：%1")
                .arg(reportFile.errorString()));
        return;
    }
    // 报告按当前界面语言渲染后写出 UTF-8 文本。
    const QString localizedReport =
        ks::ui::LocalizeGeneratedReport(buildReportText(*m_lastResult));
    reportFile.write(localizedReport.toUtf8());
    reportFile.close();
    setStatus(
        "minidump.status.exported",
        "报告已导出：%1",
        QStringList{ QDir::toNativeSeparators(savePath) });
}

void MinidumpDock::setStatus(
    const char* key,
    const char* fallback,
    const QStringList& arguments)
{
    // 记录键与参数：语言切换时 refreshStatus 按新语言重新渲染。
    m_statusKey = QString::fromLatin1(key);
    m_statusFallback = QString::fromUtf8(fallback);
    m_statusArguments = arguments;
    refreshStatus();
}

void MinidumpDock::refreshStatus()
{
    if (m_statusLabel == nullptr || m_statusKey.isEmpty())
    {
        return;
    }
    // text：先取词条再依次代入参数；参数本身保持原样（路径等动态内容）。
    QString text = ks::i18n::text(m_statusKey, m_statusFallback);
    for (const QString& argument : m_statusArguments)
    {
        text = text.arg(argument);
    }
    m_statusLabel->setText(text);
}

void MinidumpDock::setBusy(const bool busy)
{
    m_parseBusy = busy;
    // 解析期间冻结全部入口按钮，防止并发解析同一控件状态。
    m_parseButton->setEnabled(!busy);
    m_browseButton->setEnabled(!busy);
    m_systemDirButton->setEnabled(!busy);
    m_exportButton->setEnabled(!busy && m_lastResult && m_lastResult->success);
}
