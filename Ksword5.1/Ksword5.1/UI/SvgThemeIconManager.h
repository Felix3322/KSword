#pragma once

// ============================================================
// SvgThemeIconManager.h
// 作用：
// - 在主界面加载阶段集中适配 SVG/扁平图标的主题色；
// - 用像素签名缓存一次性着色结果，避免每个按钮重复渲染；
// - 默认主题色直接跳过，运行期恢复默认时可还原原始图标。
// ============================================================

#include <QColor>
#include <QIcon>
#include <QObject>

#include <functional>

class QAction;
class QApplication;
class QEvent;
class QTabWidget;
class QWidget;

namespace ks::ui
{
    // SvgThemeIconApplyResult：
    // - 保存一次集中着色的可观测结果；
    // - MainWindow 用它记录耗时、遍历量和缓存命中情况。
    struct SvgThemeIconApplyResult
    {
        int visitedWidgetCount = 0; // visitedWidgetCount：本次遍历的 QWidget 数量。
        int recoloredIconCount = 0; // recoloredIconCount：实际替换的图标槽位数量。
        int cacheHitCount = 0;      // cacheHitCount：复用已渲染图标的次数。
        bool skippedDefaultTheme = false; // skippedDefaultTheme：默认主题是否直接跳过。
        qint64 elapsedMilliseconds = 0;   // elapsedMilliseconds：完整批处理耗时。
    };

    // SvgThemeIconManager：
    // - 调用 applyToApplication() 完成启动期或主题切换时的集中处理；
    // - 全局事件过滤器只接管后续懒加载页面，调用点无需再自行着色。
    class SvgThemeIconManager final : public QObject
    {
    public:
        // instance：
        // - 返回进程内唯一管理器；
        // - 第一次应用主题时由管理器自行安装全局事件过滤器。
        static SvgThemeIconManager& instance();

        // applyToApplication：
        // - application：当前 QApplication；
        // - themeColor：当前主题强调色；
        // - isDefaultThemeColor：true 时按契约跳过首次批量着色；
        // - progressCallback：回传已处理/总控件数，供启动进度条展示；
        // - 返回批处理统计结果。
        SvgThemeIconApplyResult applyToApplication(
            QApplication* application,
            const QColor& themeColor,
            bool isDefaultThemeColor,
            const std::function<void(int, int)>& progressCallback = {});

    protected:
        // eventFilter：
        // - 集中处理主题应用后才创建的懒加载控件与动作；
        // - 命中缓存时不会重新执行 SVG/像素着色。
        bool eventFilter(QObject* watchedObject, QEvent* eventObject) override;

    private:
        SvgThemeIconManager() = default;
        ~SvgThemeIconManager() override = default;
        SvgThemeIconManager(const SvgThemeIconManager&) = delete;
        SvgThemeIconManager& operator=(const SvgThemeIconManager&) = delete;

        // 下列函数分别处理 QWidget、QAction、Tab 和单个 QIcon。
        int applyToWidget(QWidget* widgetPointer, int* cacheHitCount);
        bool applyToAction(QAction* actionPointer, int* cacheHitCount);
        int applyToTabWidget(QTabWidget* tabWidgetPointer, int* cacheHitCount);
        QIcon themedIcon(const QIcon& sourceIcon, bool* cacheHitOut);

        bool m_filterInstalled = false; // m_filterInstalled：全局事件过滤器是否已安装。
        bool m_customTintActive = false; // m_customTintActive：当前是否使用非默认主题着色。
        QColor m_themeColor; // m_themeColor：本轮集中着色使用的强调色。
    };
}
