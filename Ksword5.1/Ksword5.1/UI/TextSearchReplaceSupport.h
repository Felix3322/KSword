#pragma once

// ============================================================
// TextSearchReplaceSupport.h
// 作用：
// 1) 为全应用的多行文本框（QPlainTextEdit / QTextEdit / QTextBrowser）
//    统一提供查找与替换能力，支持正则开关与大小写开关；
// 2) 以 QApplication 级事件过滤器实现，无需逐个改造控件创建点，
//    新增的文本框自动获得同样能力；
// 3) 自带查找面板的编辑器（代码编辑器 / 十六进制编辑器）会被跳过，
//    避免出现两套查找栏。
// 交互：
// - Ctrl+F 打开查找栏，Ctrl+H 打开查找并激活替换输入；
// - Enter / Shift+Enter 查找下一个 / 上一个，Esc 关闭；
// - 只读文本框只显示查找部分，不显示替换部分。
// ============================================================

class QApplication;
class QWidget;

namespace ks::ui
{
    // InstallGlobalTextSearchReplaceSupport 作用：
    // - 安装一次全局事件过滤器，让任意多行文本框响应 Ctrl+F / Ctrl+H；
    // - 查找面板在首次唤出时按需创建，并挂在对应文本框上随其销毁。
    // 调用方法：
    // - main.cpp 在创建 QApplication 后调用一次。
    // 入参 appInstance：
    // - 应用实例，为空时直接返回。
    void InstallGlobalTextSearchReplaceSupport(QApplication* appInstance);

    // OpenTextSearchPanelFor 作用：
    // - 主动为指定文本框弹出查找面板，供右键菜单等入口复用。
    // 入参 editorWidget：
    // - 目标 QPlainTextEdit / QTextEdit；非文本框或被跳过的编辑器返回 false。
    // 入参 focusReplaceField：
    // - true 时同时展开并聚焦替换输入框（只读文本框会忽略该请求）。
    // 返回值：
    // - 成功弹出返回 true。
    bool OpenTextSearchPanelFor(QWidget* editorWidget, bool focusReplaceField);
}
