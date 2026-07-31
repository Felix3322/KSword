#include "MiscDock.h"

#include "BootEditor/BootEditorTab.h"
#include "ApplicationControlPage.h"
#include "ContextMenuCleaner/ContextMenuCleanerTab.h"
#include "DiskEditor/DiskEditorTab.h"
#include "SoundSource/SoundSourcePage.h"

#include <QIcon>
#include <QTabWidget>
#include <QVBoxLayout>

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

    m_bootEditorTab = new BootEditorTab(m_mainTabWidget);
    m_mainTabWidget->addTab(m_bootEditorTab, QStringLiteral("引导"));

    // 声音来源页：
    // - R3 连续采样 Core Audio 输出会话峰值并归因到 PID；
    // - R0 复用进程 Cross-View 与 Runtime Detail 交叉核验候选 PID。
    m_soundSourcePage = new ks::misc::SoundSourcePage(0U, 0U, m_mainTabWidget);
    m_mainTabWidget->addTab(
        m_soundSourcePage,
        QIcon(QStringLiteral(":/Icon/sound_source.svg")),
        QStringLiteral("声音来源"));

    // Shell 关联管理页：
    // - 覆盖右键菜单、URL 绑定、打开方式和 Explorer 第三方主页项；
    // - 仅在用户确认后删除表格绑定的精确注册表子树或值。
    m_contextMenuCleanerTab = new ks::misc::ContextMenuCleanerTab(m_mainTabWidget);
    m_mainTabWidget->addTab(
        m_contextMenuCleanerTab,
        QIcon(QStringLiteral(":/Icon/log_track.svg")),
        QStringLiteral("Shell 关联管理"));

    // 磁盘编辑页：
    // - 参考 DiskGenius 类工具布局，提供横向柱形分区图；
    // - 默认只读，用户显式解锁后才允许写回物理磁盘。
    m_diskEditorTab = new ks::misc::DiskEditorTab(m_mainTabWidget);
    m_mainTabWidget->addTab(
        m_diskEditorTab,
        QIcon(QStringLiteral(":/Icon/disk_storage.svg")),
        QStringLiteral("磁盘编辑"));

    // 应用控制页：
    // - 第一版仅做 AppLocker / WDAC / Defender / 事件日志只读诊断；
    // - 不修改、不删除、不禁用任何策略。
    m_applicationControlPage = new ks::misc::ApplicationControlPage(m_mainTabWidget);
    m_mainTabWidget->addTab(
        m_applicationControlPage,
        QIcon(QStringLiteral(":/Icon/process_details.svg")),
        QStringLiteral("应用控制"));

}
