#pragma once

class QApplication;

namespace ks::ui
{
    // InstallGlobalSmoothScrollSupport 作用：
    // - 安装一次全局滚轮事件过滤器，覆盖表格、列表、文本区和滚动页；
    // - 实际是否启用由 SetGlobalSmoothScrollingEnabled 在运行时切换。
    void InstallGlobalSmoothScrollSupport(QApplication* appInstance);

    // SetGlobalSmoothScrollingEnabled 作用：
    // - 即时启用或关闭全局滚轮缓动；
    // - 启用时项目视图切换到像素滚动，关闭时恢复各控件原始滚动模式。
    void SetGlobalSmoothScrollingEnabled(bool enabled);

    bool IsGlobalSmoothScrollingEnabled();
}
