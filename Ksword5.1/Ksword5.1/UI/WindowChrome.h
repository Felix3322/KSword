#pragma once

// ============================================================
// WindowChrome.h
// 作用：
// 1) 把主题色同步到所有“原生标题栏”顶层窗口（子窗口、对话框、浮动 Dock）；
// 2) 使用 DWM 属性染色标题栏/边框，解决系统默认白色标题栏与深色主题割裂问题；
// 3) 与 MainWindow 的自绘标题栏分工：主窗口不经过本模块，其余顶层窗口统一接管。
// ============================================================

class QApplication;
class QWidget;

namespace ks::ui
{
    // InstallWindowChrome 作用：
    // - 给 QApplication 安装顶层窗口标题栏主题器；
    // - 捕获后续显示的所有原生标题栏窗口并应用当前主题的标题栏颜色。
    // 参数 appInstance：当前 QApplication 实例；为空时忽略。
    // 返回值：无。
    void InstallWindowChrome(QApplication* appInstance);

    // RefreshAllWindowChrome 作用：
    // - 主题切换后重新染色当前所有已显示的顶层窗口标题栏；
    // - 让深浅色/主题色/主背景色变更立即反映到已打开窗口。
    // 参数：无。
    // 返回值：无。
    void RefreshAllWindowChrome();

    // ApplyWindowChrome 作用：
    // - 对单个顶层窗口应用当前主题的标题栏颜色；
    // - 窗口为空、非顶层、无边框或原生句柄未创建时静默忽略。
    // 参数 topLevelWidget：目标顶层窗口。
    // 返回值：无。
    void ApplyWindowChrome(QWidget* topLevelWidget);
}
