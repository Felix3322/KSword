#pragma once

// ============================================================
// GlobalUiBaseStyle.h
// 作用：
// 1) 提供 QApplication 级“基础控件”统一样式块（按钮/输入框/表头/进度条等）；
// 2) 作为全部页面的视觉基线，减少各模块散落 setStyleSheet 的风格漂移；
// 3) 片段带起止标记，交给 MainWindow 的全局样式块替换机制统一管理。
// ============================================================

#include <QString>

namespace ks::ui
{
    // kBaseControlStyleBeginMarker / kBaseControlStyleEndMarker 作用：
    // - 标记 QApplication 样式表中“基础控件基线样式”的起止位置；
    // - 主题或自定义颜色变化时替换旧片段，避免重复追加。
    inline constexpr const char* kBaseControlStyleBeginMarker = "/*KSWORD_BASE_CONTROL_STYLE_BEGIN*/";
    inline constexpr const char* kBaseControlStyleEndMarker = "/*KSWORD_BASE_CONTROL_STYLE_END*/";

    // BuildGlobalBaseControlStyleBlock 作用：
    // - 生成带起止标记的基础控件样式片段；
    // - 覆盖 QPushButton、单行/多行输入框、QGroupBox、QHeaderView、
    //   QProgressBar、QSplitter 等未被专用样式块接管的常用控件；
    // - 规则不加 !important，各页面局部样式仍可按需覆盖基线。
    // 调用方式：MainWindow::applyAppearanceSettings 主题刷新链路内调用。
    // 返回：可直接拼接到 QApplication 样式表的基础控件片段。
    QString BuildGlobalBaseControlStyleBlock();
}
