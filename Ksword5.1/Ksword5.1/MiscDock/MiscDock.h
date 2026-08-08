#pragma once

// ============================================================
// MiscDock.h
// 作用：
// 1) 提供“杂项”总入口页；
// 2) 通过内部 Tab 承载子功能模块；
// 3) 当前包含“引导”“声音来源”“系统变速”“Shell 关联”“磁盘编辑”“应用控制”等子模块。
// ============================================================

#include "../Framework.h"

#include <QWidget>

class QTabWidget;
class QVBoxLayout;
class BootEditorTab;
namespace ks::misc
{
    class DiskEditorTab;
    class ContextMenuCleanerTab;
    class ApplicationControlPage;
    class SoundSourcePage;
    class SystemTimePage;
    class BugcheckGuardPage;
}

class MiscDock final : public QWidget
{
    Q_OBJECT

public:
    // 构造函数：
    // - 作用：创建“杂项”根布局与内部 Tab。
    // - 参数 parent：Qt 父控件。
    explicit MiscDock(QWidget* parent = nullptr);
    ~MiscDock() override = default;

private:
    // initializeUi：
    // - 作用：初始化“杂项”页的控件树，只把页签占位控件建出来；
    // - 调用：构造函数中调用一次。
    void initializeUi();

    // ensureTabInitialized：
    // - 作用：按需构造指定页签对应的真实子页，已构造过则直接返回；
    // - 入参 tabIndex：主 Tab 的页签索引，越界或负数会被忽略；
    // - 返回：无。
    void ensureTabInitialized(int tabIndex);

    // initializeXxx 系列：
    // - 作用：把对应子页构造出来并塞进自己的页签占位控件；
    // - 入参：无；
    // - 返回：无；重复调用是安全的空操作。
    void initializeBootEditorTab();
    void initializeSoundSourcePage();
    void initializeSystemTimePage();
    void initializeBugcheckGuardPage();
    void initializeContextMenuCleanerTab();
    void initializeDiskEditorTab();
    void initializeApplicationControlPage();

private:
    QVBoxLayout* m_rootLayout = nullptr;      // m_rootLayout：杂项页根布局。
    QTabWidget* m_mainTabWidget = nullptr;    // m_mainTabWidget：杂项页内部 Tab 容器。

    // ===================== 页签占位控件 =====================
    // 说明：占位控件在构造期就加入 Tab，锁定页签顺序、标题与图标；
    //       真实子页在页签首次被选中时才 new 出来塞进对应占位控件。
    QWidget* m_bootEditorHostWidget = nullptr;          // m_bootEditorHostWidget：引导页占位控件。
    QWidget* m_soundSourceHostWidget = nullptr;         // m_soundSourceHostWidget：声音来源页占位控件。
    QWidget* m_systemTimeHostWidget = nullptr;          // m_systemTimeHostWidget：系统变速页占位控件。
    QWidget* m_bugcheckGuardHostWidget = nullptr;       // m_bugcheckGuardHostWidget：实验性页占位控件。
    QWidget* m_contextMenuCleanerHostWidget = nullptr;  // m_contextMenuCleanerHostWidget：Shell 关联管理页占位控件。
    QWidget* m_diskEditorHostWidget = nullptr;          // m_diskEditorHostWidget：磁盘编辑页占位控件。
    QWidget* m_applicationControlHostWidget = nullptr;  // m_applicationControlHostWidget：应用控制页占位控件。

    // ===================== 页签索引 =====================
    int m_bootEditorTabIndex = -1;          // m_bootEditorTabIndex：引导页页签索引。
    int m_soundSourceTabIndex = -1;         // m_soundSourceTabIndex：声音来源页页签索引。
    int m_systemTimeTabIndex = -1;          // m_systemTimeTabIndex：系统变速页页签索引。
    int m_bugcheckGuardTabIndex = -1;       // m_bugcheckGuardTabIndex：实验性页页签索引。
    int m_contextMenuCleanerTabIndex = -1;  // m_contextMenuCleanerTabIndex：Shell 关联管理页页签索引。
    int m_diskEditorTabIndex = -1;          // m_diskEditorTabIndex：磁盘编辑页页签索引。
    int m_applicationControlTabIndex = -1;  // m_applicationControlTabIndex：应用控制页页签索引。

    // ===================== 子页组件（延迟赋值，未初始化时为 nullptr） =====================
    BootEditorTab* m_bootEditorTab = nullptr; // m_bootEditorTab：引导编辑器页组件。
    ks::misc::DiskEditorTab* m_diskEditorTab = nullptr; // m_diskEditorTab：磁盘编辑器页组件。
    ks::misc::ContextMenuCleanerTab* m_contextMenuCleanerTab = nullptr; // m_contextMenuCleanerTab：右键菜单清理页组件。
    ks::misc::ApplicationControlPage* m_applicationControlPage = nullptr; // m_applicationControlPage：应用控制页组件。
    ks::misc::SoundSourcePage* m_soundSourcePage = nullptr; // m_soundSourcePage：全局输出声音来源检测页。
    ks::misc::SystemTimePage* m_systemTimePage = nullptr; // m_systemTimePage：系统全局变速控制页。
    ks::misc::BugcheckGuardPage* m_bugcheckGuardPage = nullptr; // m_bugcheckGuardPage：实验性一次性蓝屏缓冲控制页。
};
