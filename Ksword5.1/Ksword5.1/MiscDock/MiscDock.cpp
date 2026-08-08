#include "MiscDock.h"

#include "BootEditor/BootEditorTab.h"
#include "ApplicationControlPage.h"
#include "ContextMenuCleaner/ContextMenuCleanerTab.h"
#include "Experimental/BugcheckGuardPage.h"
#include "DiskEditor/DiskEditorTab.h"
#include "SoundSource/SoundSourcePage.h"
#include "SystemTime/SystemTimePage.h"

#include "../Internationalization/LanguageManager.h"
#include <QIcon>
#include <QTabWidget>
#include <QTimer>
#include <QVBoxLayout>
#include <QWidget>

namespace
{
    // buildHostLayout：
    // - 作用：为页签占位控件建立统一的承载布局，边距与间距全部归零，
    //   让真实子页占满原来直接作为页签页时的同一块区域；
    // - 入参 hostWidget：页签占位控件，必须非空；
    // - 返回：已挂到占位控件上的垂直布局。
    QVBoxLayout* buildHostLayout(QWidget* hostWidget)
    {
        QVBoxLayout* hostLayout = new QVBoxLayout(hostWidget);
        hostLayout->setContentsMargins(0, 0, 0, 0);
        hostLayout->setSpacing(0);
        return hostLayout;
    }
}

MiscDock::MiscDock(QWidget* parent)
    : QWidget(parent)
{
    initializeUi();

    kLogEvent initEvent;
    info << initEvent << "[MiscDock] 杂项页面初始化完成。" << eol;
}

void MiscDock::initializeUi()
{
    // 根布局负责承载整个“杂项”容器。
    m_rootLayout = new QVBoxLayout(this);
    m_rootLayout->setContentsMargins(0, 0, 0, 0);
    m_rootLayout->setSpacing(0);

    // 主 Tab 承载所有杂项工具，保持 Dock 外层只暴露一个统一入口。
    m_mainTabWidget = new QTabWidget(this);
    m_mainTabWidget->setObjectName(QStringLiteral("ksMiscDockMainTab"));
    m_rootLayout->addWidget(m_mainTabWidget, 1);

    // 懒加载策略：
    // - 七个页签先用空占位控件占住，页签顺序、标题与图标与旧实现逐一对齐；
    // - 真实子页在页签第一次被选中时才构造，避免“杂项”页一被创建就把磁盘、
    //   Shell 关联、应用控制等重页面全部建出来（每一个都会自带首轮枚举）。
    m_bootEditorHostWidget = new QWidget(m_mainTabWidget);
    m_soundSourceHostWidget = new QWidget(m_mainTabWidget);
    m_systemTimeHostWidget = new QWidget(m_mainTabWidget);
    m_bugcheckGuardHostWidget = new QWidget(m_mainTabWidget);
    m_contextMenuCleanerHostWidget = new QWidget(m_mainTabWidget);
    m_diskEditorHostWidget = new QWidget(m_mainTabWidget);
    m_applicationControlHostWidget = new QWidget(m_mainTabWidget);

    m_bootEditorTabIndex = m_mainTabWidget->addTab(
        m_bootEditorHostWidget,
        QStringLiteral("引导"));

    // 声音来源页：
    // - R3 连续采样 Core Audio 输出会话峰值并归因到 PID；
    // - R0 复用进程 Cross-View 与 Runtime Detail 交叉核验候选 PID。
    m_soundSourceTabIndex = m_mainTabWidget->addTab(
        m_soundSourceHostWidget,
        QIcon(QStringLiteral(":/Icon/sound_source.svg")),
        QStringLiteral("声音来源"));

    // 系统全局变速页：
    // - 通过 ArkDriverClient 控制 R0 性能计数器连续倍率映射；
    // - 永久展示失稳风险，并在每次启用前执行双重确认。
    m_systemTimeTabIndex = m_mainTabWidget->addTab(
        m_systemTimeHostWidget,
        QIcon(QStringLiteral(":/Icon/system_time.svg")),
        QStringLiteral("系统变速"));

    // 蓝屏缓冲页严格归入“实验性”：它只提供一次性 KeBugCheckEx 延迟，
    // 不承诺恢复系统，也不默认跳过最终 BugCheck。
    m_bugcheckGuardTabIndex = m_mainTabWidget->addTab(
        m_bugcheckGuardHostWidget,
        QIcon(QStringLiteral(":/Icon/codeeditor_replace.svg")),
        QStringLiteral("实验性"));
    // i18n 绑定挂在占位控件上：LanguageManager 按 QTabWidget::widget(index) 回读属性，
    // 占位控件才是常驻页签页，真实子页只是它的孩子。
    ks::i18n::LanguageManager::instance().bindTab(
        m_mainTabWidget,
        m_bugcheckGuardHostWidget,
        QStringLiteral("misc.experimental.tab"),
        QStringLiteral("实验性"));

    // Shell 关联管理页：
    // - 覆盖右键菜单、URL 绑定、打开方式和 Explorer 第三方主页项；
    // - 仅在用户确认后删除表格绑定的精确注册表子树或值。
    m_contextMenuCleanerTabIndex = m_mainTabWidget->addTab(
        m_contextMenuCleanerHostWidget,
        QIcon(QStringLiteral(":/Icon/log_track.svg")),
        QStringLiteral("Shell 关联管理"));

    // 磁盘编辑页：
    // - 参考 DiskGenius 类工具布局，提供横向柱形分区图；
    // - 默认只读，用户显式解锁后才允许写回物理磁盘。
    m_diskEditorTabIndex = m_mainTabWidget->addTab(
        m_diskEditorHostWidget,
        QIcon(QStringLiteral(":/Icon/disk_storage.svg")),
        QStringLiteral("磁盘编辑"));

    // 应用控制页：
    // - 第一版仅做 AppLocker / WDAC / Defender / 事件日志只读诊断；
    // - 不修改、不删除、不禁用任何策略。
    m_applicationControlTabIndex = m_mainTabWidget->addTab(
        m_applicationControlHostWidget,
        QIcon(QStringLiteral(":/Icon/process_details.svg")),
        QStringLiteral("应用控制"));

    // 页签切换：按需初始化对应子页。
    connect(
        m_mainTabWidget,
        &QTabWidget::currentChanged,
        this,
        [this](const int tabIndex)
        {
            ensureTabInitialized(tabIndex);
        });

    // 首屏页必须同步初始化：
    // - ADS 可能直接把“杂项”恢复为当前 Dock，此时不会再触发一次 currentChanged；
    // - 只初始化当前页，其余页面仍然保持懒加载。
    ensureTabInitialized(m_mainTabWidget->currentIndex());

    // 再补一次 0ms 兜底，覆盖主题/ADS 延迟恢复导致 currentIndex 稍后才变化的情况。
    QTimer::singleShot(0, this, [this]()
        {
            ensureTabInitialized(m_mainTabWidget != nullptr ? m_mainTabWidget->currentIndex() : -1);
        });
}

void MiscDock::ensureTabInitialized(const int tabIndex)
{
    if (tabIndex < 0)
    {
        return;
    }

    if (tabIndex == m_bootEditorTabIndex)
    {
        initializeBootEditorTab();
        return;
    }
    if (tabIndex == m_soundSourceTabIndex)
    {
        initializeSoundSourcePage();
        return;
    }
    if (tabIndex == m_systemTimeTabIndex)
    {
        initializeSystemTimePage();
        return;
    }
    if (tabIndex == m_bugcheckGuardTabIndex)
    {
        initializeBugcheckGuardPage();
        return;
    }
    if (tabIndex == m_contextMenuCleanerTabIndex)
    {
        initializeContextMenuCleanerTab();
        return;
    }
    if (tabIndex == m_diskEditorTabIndex)
    {
        initializeDiskEditorTab();
        return;
    }
    if (tabIndex == m_applicationControlTabIndex)
    {
        initializeApplicationControlPage();
        return;
    }
}

void MiscDock::initializeBootEditorTab()
{
    if (m_bootEditorHostWidget == nullptr || m_bootEditorTab != nullptr)
    {
        return;
    }

    QVBoxLayout* const hostLayout = buildHostLayout(m_bootEditorHostWidget);
    m_bootEditorTab = new BootEditorTab(m_bootEditorHostWidget);
    hostLayout->addWidget(m_bootEditorTab, 1);
}

void MiscDock::initializeSoundSourcePage()
{
    if (m_soundSourceHostWidget == nullptr || m_soundSourcePage != nullptr)
    {
        return;
    }

    QVBoxLayout* const hostLayout = buildHostLayout(m_soundSourceHostWidget);
    m_soundSourcePage = new ks::misc::SoundSourcePage(0U, 0U, m_soundSourceHostWidget);
    hostLayout->addWidget(m_soundSourcePage, 1);
}

void MiscDock::initializeSystemTimePage()
{
    if (m_systemTimeHostWidget == nullptr || m_systemTimePage != nullptr)
    {
        return;
    }

    QVBoxLayout* const hostLayout = buildHostLayout(m_systemTimeHostWidget);
    m_systemTimePage = new ks::misc::SystemTimePage(m_systemTimeHostWidget);
    hostLayout->addWidget(m_systemTimePage, 1);
}

void MiscDock::initializeBugcheckGuardPage()
{
    if (m_bugcheckGuardHostWidget == nullptr || m_bugcheckGuardPage != nullptr)
    {
        return;
    }

    QVBoxLayout* const hostLayout = buildHostLayout(m_bugcheckGuardHostWidget);
    m_bugcheckGuardPage = new ks::misc::BugcheckGuardPage(m_bugcheckGuardHostWidget);
    hostLayout->addWidget(m_bugcheckGuardPage, 1);
}

void MiscDock::initializeContextMenuCleanerTab()
{
    if (m_contextMenuCleanerHostWidget == nullptr || m_contextMenuCleanerTab != nullptr)
    {
        return;
    }

    QVBoxLayout* const hostLayout = buildHostLayout(m_contextMenuCleanerHostWidget);
    m_contextMenuCleanerTab = new ks::misc::ContextMenuCleanerTab(m_contextMenuCleanerHostWidget);
    hostLayout->addWidget(m_contextMenuCleanerTab, 1);
}

void MiscDock::initializeDiskEditorTab()
{
    if (m_diskEditorHostWidget == nullptr || m_diskEditorTab != nullptr)
    {
        return;
    }

    QVBoxLayout* const hostLayout = buildHostLayout(m_diskEditorHostWidget);
    m_diskEditorTab = new ks::misc::DiskEditorTab(m_diskEditorHostWidget);
    hostLayout->addWidget(m_diskEditorTab, 1);
}

void MiscDock::initializeApplicationControlPage()
{
    if (m_applicationControlHostWidget == nullptr || m_applicationControlPage != nullptr)
    {
        return;
    }

    QVBoxLayout* const hostLayout = buildHostLayout(m_applicationControlHostWidget);
    m_applicationControlPage = new ks::misc::ApplicationControlPage(m_applicationControlHostWidget);
    hostLayout->addWidget(m_applicationControlPage, 1);
}
