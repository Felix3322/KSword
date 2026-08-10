#include "StartupDock.Internal.h"
#include "../UI/TableInteractionSupport.h"

using namespace startup_dock_detail;

StartupDock::StartupDock(QWidget* parent)
    : QWidget(parent)
{
    // 初始化顺序：
    // - 先创建 UI；
    // - 再连接交互；
    // - 启动项全量枚举改为“首次显示时懒加载”，避免拖慢主窗口启动。
    initializeUi();
    initializeConnections();

    kLogEvent initEvent;
    info << initEvent
        << startupText("startup.log.initialized", QStringLiteral("[StartupDock] 启动项页初始化完成。"))
               .toStdString()
        << eol;
}

StartupDock::~StartupDock()
{
    m_destroying.store(true);
    if (m_actionThread != nullptr && m_actionThread->joinable())
    {
        m_actionThread->join();
    }
    if (m_refreshThread != nullptr && m_refreshThread->joinable())
    {
        m_refreshThread->join();
    }
    if (m_refreshTimer != nullptr)
    {
        m_refreshTimer->stop();
    }

    kLogEvent destroyEvent;
    info << destroyEvent
        << startupText("startup.log.destroyed", QStringLiteral("[StartupDock] 启动项页已析构。"))
               .toStdString()
        << eol;
}

void StartupDock::changeEvent(QEvent* event)
{
    QWidget::changeEvent(event);
    if (event == nullptr || event->type() != QEvent::LanguageChange)
    {
        return;
    }

    applyTranslatedHeaders();
    rebuildAllTables();
    if (m_statusLabel == nullptr)
    {
        return;
    }
    if (m_refreshInProgress.load())
    {
        m_statusLabel->setText(
            m_refreshQueued.load()
                ? startupText(
                    "startup.status.refresh_queued",
                    QStringLiteral("状态：后台刷新进行中，已记录新的刷新请求"))
                : startupText(
                    "startup.status.refreshing",
                    QStringLiteral("状态：后台正在枚举启动项...")));
    }
    else if (!m_initialRefreshDone)
    {
        m_statusLabel->setText(
            startupText(
                "startup.status.initial",
                QStringLiteral("状态：首次打开该页时加载启动项")));
    }
    else
    {
        m_statusLabel->setText(
            startupText(
                "startup.status.summary",
                QStringLiteral("状态：共 %1 条，当前分类 %2"))
                .arg(m_entryList.size())
                .arg(categoryToText(currentCategory())));
    }
}

int StartupDock::toStartupColumn(const StartupColumn column)
{
    return static_cast<int>(column);
}

QString StartupDock::categoryToText(const StartupCategory category)
{
    switch (category)
    {
    case StartupCategory::All:
        return startupText("startup.category.overview", QStringLiteral("总览"));
    case StartupCategory::Logon:
        return startupText("startup.category.logon", QStringLiteral("登录"));
    case StartupCategory::Services:
        return startupText("startup.category.services", QStringLiteral("服务"));
    case StartupCategory::Drivers:
        return startupText("startup.category.drivers", QStringLiteral("驱动"));
    case StartupCategory::Tasks:
        return startupText("startup.category.tasks", QStringLiteral("计划任务"));
    case StartupCategory::Registry:
        return startupText("startup.category.registry", QStringLiteral("高级注册表"));
    case StartupCategory::Wmi:
        return startupText("startup.category.wmi", QStringLiteral("WMI"));
    case StartupCategory::Hidden:
        return startupText("startup.category.hidden", QStringLiteral("隐藏项"));
    default:
        return startupText("startup.category.unknown", QStringLiteral("未知"));
    }
}

void StartupDock::showEvent(QShowEvent* event)
{
    QWidget::showEvent(event);

    if (m_initialRefreshDone)
    {
        return;
    }

    m_initialRefreshDone = true;
    if (m_statusLabel != nullptr)
    {
        m_statusLabel->setText(
            startupText("startup.status.first_load", QStringLiteral("状态：首次打开，正在加载启动项...")));
    }

    // 延迟到事件循环末尾再发起首次后台枚举：
    // - 先把页签本身显示出来，避免用户感知为“点击无响应”；
    // - 同时把重活移出主窗口构造阶段，优化启动速度。
    QTimer::singleShot(0, this, [this]()
        {
            requestAsyncRefresh(true);
        });
}

StartupDock::StartupCategory StartupDock::currentCategory() const
{
    if (m_sideTabWidget == nullptr)
    {
        return StartupCategory::All;
    }

    switch (m_sideTabWidget->currentIndex())
    {
    case 0:
        return StartupCategory::All;
    case 1:
        return StartupCategory::Logon;
    case 2:
        return StartupCategory::Services;
    case 3:
        return StartupCategory::Drivers;
    case 4:
        return StartupCategory::Tasks;
    case 5:
        return StartupCategory::Registry;
    case 6:
        return StartupCategory::Wmi;
    case 7:
        return StartupCategory::Hidden;
    default:
        return StartupCategory::All;
    }
}

QTableWidget* StartupDock::currentCategoryTable() const
{
    switch (currentCategory())
    {
    case StartupCategory::All:
        return m_allTable;
    case StartupCategory::Logon:
        return m_logonTable;
    case StartupCategory::Services:
        return m_servicesTable;
    case StartupCategory::Drivers:
        return m_driversTable;
    case StartupCategory::Tasks:
        return m_tasksTable;
    case StartupCategory::Registry:
        return nullptr;
    case StartupCategory::Wmi:
        return m_wmiTable;
    case StartupCategory::Hidden:
        return m_hiddenTable;
    default:
        return m_allTable;
    }
}

QIcon StartupDock::resolveEntryIcon(const StartupEntry& entry)
{
    // 图标解析留在 UI 线程：
    // - 避免后台线程构造 QIcon / QFileIconProvider；
    // - 同一路径走缓存，降低表格重建开销。
    const QString cacheKeyText =
        entry.imagePathText.trimmed().isEmpty()
        ? QStringLiteral("type:%1").arg(entry.sourceTypeText)
        : QStringLiteral("path:%1").arg(QDir::toNativeSeparators(entry.imagePathText));

    const auto cacheIt = m_iconCache.constFind(cacheKeyText);
    if (cacheIt != m_iconCache.constEnd())
    {
        return cacheIt.value();
    }

    QIcon resolvedIcon;
    if (!entry.imagePathText.trimmed().isEmpty())
    {
        const QFileInfo fileInfo(entry.imagePathText);
        if (fileInfo.exists())
        {
            static QFileIconProvider fileIconProvider;
            resolvedIcon = fileIconProvider.icon(fileInfo);
        }
    }

    if (resolvedIcon.isNull())
    {
        if (entry.category == StartupCategory::Services)
        {
            resolvedIcon = createBlueIcon(":/Icon/process_start.svg");
        }
        else if (entry.category == StartupCategory::Drivers)
        {
            resolvedIcon = createBlueIcon(":/Icon/process_details.svg");
        }
        else if (entry.category == StartupCategory::Tasks)
        {
            resolvedIcon = createBlueIcon(":/Icon/process_refresh.svg");
        }
        else if (entry.category == StartupCategory::Registry)
        {
            resolvedIcon = createBlueIcon(":/Icon/file_find.svg");
        }
        else if (entry.category == StartupCategory::Hidden)
        {
            resolvedIcon = createBlueIcon(":/Icon/startup_hidden.svg");
        }
        else
        {
            resolvedIcon = createBlueIcon(":/Icon/process_main.svg");
        }
    }

    m_iconCache.insert(cacheKeyText, resolvedIcon);
    return resolvedIcon;
}

void StartupDock::requestAsyncRefresh(const bool forceRefresh)
{
    if (m_refreshInProgress)
    {
        if (forceRefresh)
        {
            m_refreshQueued = true;
        }
        if (m_statusLabel != nullptr)
        {
            m_statusLabel->setText(
                startupText(
                    "startup.status.refresh_queued",
                    QStringLiteral("状态：后台刷新进行中，已记录新的刷新请求")));
        }
        return;
    }

    if (m_refreshThread != nullptr && m_refreshThread->joinable())
    {
        m_refreshThread->join();
    }

    m_refreshInProgress = true;
    m_refreshQueued = false;
    m_progressPid = kPro.add(
        this,
        startupText("startup.progress.title", QStringLiteral("启动项")).toStdString(),
        startupText("startup.progress.enumerate", QStringLiteral("枚举自启动项")).toStdString());
    kPro.set(
        m_progressPid,
        startupText("startup.progress.prepare_logon", QStringLiteral("准备枚举登录项")).toStdString(),
        0,
        5.0f);
    if (m_statusLabel != nullptr)
    {
        m_statusLabel->setText(
            startupText("startup.status.refreshing", QStringLiteral("状态：后台正在枚举启动项...")));
    }

    const int progressPid = m_progressPid;
    // LanguageManager 的当前语言由 UI 线程切换。先在此处取得进度文案，
    // 避免后台枚举线程与语言切换并发访问翻译状态。
    const std::string enumerateBackendProgressText = startupText(
        "startup.progress.enumerate_backend",
        QStringLiteral("调用 ks::startup 后端枚举启动项")).toStdString();
    const std::string backendCompletedProgressText = startupText(
        "startup.progress.backend_completed",
        QStringLiteral("ks::startup 后端枚举完成")).toStdString();
    m_refreshThread = std::make_unique<std::thread>(
        [this,
         progressPid,
         enumerateBackendProgressText,
         backendCompletedProgressText]()
        {
            if (m_destroying.load())
            {
                return;
            }

            std::vector<StartupEntry> entryList;
            entryList.reserve(256);

            kPro.set(
                progressPid,
                enumerateBackendProgressText,
                0,
                15.0f);
            appendBackendStartupEntries(
                &entryList,
                ks::startup::EnumerateAllStartupEntries());
            kPro.set(
                progressPid,
                backendCompletedProgressText,
                0,
                96.0f);

            if (m_destroying.load())
            {
                return;
            }

            QMetaObject::invokeMethod(
                this,
                [this, entryList = std::move(entryList)]() mutable
                {
                    if (m_destroying.load())
                    {
                        return;
                    }
                    applyRefreshResult(std::move(entryList));
                },
                Qt::QueuedConnection);
        });
}

void StartupDock::applyRefreshResult(std::vector<StartupEntry> entryList)
{
    const QList<QTableView*> startupTables = {
        m_allTable,
        m_logonTable,
        m_servicesTable,
        m_driversTable,
        m_tasksTable,
        m_wmiTable,
        m_hiddenTable
    };
    if (ks::ui::IsTableUiCommitBlockedByContextMenu(startupTables))
    {
        // 七张分类表来自同一快照，菜单关闭后必须原子替换，
        // 避免各标签页缓存与可见行处于不同代次。
        const QPointer<StartupDock> safeThis(this);
        ks::ui::DeferTableUiCommitIfContextMenuOpen(
            this,
            QStringLiteral("startup-tables-refresh-apply"),
            startupTables,
            [safeThis, entryList = std::move(entryList)]() mutable
            {
                if (!safeThis.isNull())
                {
                    safeThis->applyRefreshResult(std::move(entryList));
                }
            });
        return;
    }

    std::sort(
        entryList.begin(),
        entryList.end(),
        [](const StartupEntry& left, const StartupEntry& right)
        {
            if (left.category != right.category)
            {
                return static_cast<int>(left.category) < static_cast<int>(right.category);
            }
            if (left.itemNameText.compare(right.itemNameText, Qt::CaseInsensitive) != 0)
            {
                return left.itemNameText.compare(right.itemNameText, Qt::CaseInsensitive) < 0;
            }
            return left.locationText.compare(right.locationText, Qt::CaseInsensitive) < 0;
        });

    m_entryList = std::move(entryList);
    rebuildAllTables();

    if (m_statusLabel != nullptr)
    {
        m_statusLabel->setText(
            startupText("startup.status.summary", QStringLiteral("状态：共 %1 条，当前分类 %2"))
            .arg(m_entryList.size())
            .arg(categoryToText(currentCategory())));
    }

    if (m_progressPid != 0)
    {
        kPro.set(
            m_progressPid,
            startupText("startup.progress.completed", QStringLiteral("启动项刷新完成")).toStdString(),
            0,
            100.0f);
    }

    m_refreshInProgress = false;

    kLogEvent refreshEvent;
    info << refreshEvent
        << startupText("startup.log.refresh.completed", QStringLiteral("[StartupDock] 后台刷新完成, count="))
               .toStdString()
        << m_entryList.size()
        << eol;

    if (m_refreshQueued)
    {
        requestAsyncRefresh(false);
    }
}
