#pragma once

// ============================================================
// GlobalRefreshShortcut.h
// 作用：
// 1) 为全应用提供 Windows 惯例的 F5 = 刷新；
// 2) 各页面的刷新按钮成员名不统一（m_refreshButton / m_refreshServiceButton /
//    m_refreshCallbackEnumButton ...），逐页绑定需要改动数十个文件，
//    这里改为按下 F5 时从焦点控件就近向上查找该页的刷新按钮并触发；
// 3) 找不到刷新按钮时不做任何事，不影响原有按键行为。
// ============================================================

class QApplication;

namespace ks::ui
{
    // InstallGlobalRefreshShortcut 作用：
    // - 给 QApplication 安装 F5 快捷键过滤器；
    // - 命中时点击当前页面中可见且可用的刷新按钮。
    // 参数 appInstance：当前 QApplication 实例；为空时忽略。
    // 返回值：无。
    void InstallGlobalRefreshShortcut(QApplication* appInstance);
}
