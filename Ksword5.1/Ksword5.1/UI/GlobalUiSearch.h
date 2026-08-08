#pragma once

// ============================================================
// GlobalUiSearch.h
// 作用：
// 1) 提供标题栏“搜索”模式的全局页面文本搜索：
//    遍历各主功能 Dock 的控件树，收集标签/按钮/分组框/页签/表头/
//    占位符/下拉项等可见文本并做关键词匹配；
// 2) 在标题栏输入框下方弹出结果面板，每条结果直接显示
//    匹配文本与“Dock › 内部页签 › 分组”形式的页面路径；
// 3) 激活结果时自动初始化并置前目标 Dock、逐层切换内部
//    Tab/Stacked 页、滚动到目标控件，并以主题强调色脉冲高亮；
// 4) 组件不直接依赖 MainWindow：Dock 列表、懒加载初始化与
//    Dock 激活均通过回调注入，便于复用与单元验证。
// ============================================================

#include <QObject>
#include <QPointer>
#include <QString>
#include <QVector>

#include <functional>

class QEvent;
class QFrame;
class QLabel;
class QLineEdit;
class QListWidget;
class QTimer;
class QWidget;

namespace ads
{
    class CDockWidget;
}

namespace ks::ui
{
    // ============================================================
    // UiSearchHit
    // 说明：
    // - 描述一条页面文本搜索命中；
    // - dock 与目标控件都用 QPointer 持有，激活时先判空防止悬空。
    // ============================================================
    struct UiSearchHit
    {
        QPointer<ads::CDockWidget> pageDockWidget; // pageDockWidget：命中文本所属的主功能 Dock。
        QPointer<QWidget> targetWidget;            // targetWidget：承载命中文本的具体控件（页签命中时为页签对应页面）。
        QString matchedText;                       // matchedText：命中控件的完整原始文本（单行化处理后）。
        QString pagePathText;                      // pagePathText：形如“内核 › 回调审计”的页面路径文本。
        int matchRank = 2;                         // matchRank：排序权重（0=整串相等，1=前缀，2=包含）。
    };

    // ============================================================
    // GlobalUiSearchController
    // 说明：
    // - 标题栏搜索模式的总控：防抖搜索、结果弹层、键盘导航、
    //   结果激活跳转与目标高亮；
    // - 弹层实现为宿主主窗口的子控件（非独立顶层窗口），
    //   避免无边框窗口下焦点/激活状态被弹窗抢占。
    // ============================================================
    class GlobalUiSearchController final : public QObject
    {
        Q_OBJECT

    public:
        // DockListProvider：返回参与搜索的 Dock 列表（按展示顺序）。
        using DockListProvider = std::function<QList<ads::CDockWidget*>()>;
        // DockPreparer：确保 Dock 懒加载内容已初始化（重入安全）。
        using DockPreparer = std::function<void(ads::CDockWidget*)>;
        // DockActivator：把 Dock 置前并设为当前页签（含关闭态恢复）。
        using DockActivator = std::function<void(ads::CDockWidget*)>;

        // 构造函数：
        // - 作用：创建搜索控制器并安装输入框/应用级事件过滤器；
        // - 调用：MainWindow 初始化标题栏后创建；
        // - 传入 popupHostWindow：结果弹层的父窗口（主窗口）；
        // - 传入 searchInputEdit：标题栏中间输入框；
        // - 传入 popupAnchorWidget：弹层水平对齐的锚点控件（输入组容器）；
        // - 传入 parentObject：Qt 父对象。
        GlobalUiSearchController(
            QWidget* popupHostWindow,
            QLineEdit* searchInputEdit,
            QWidget* popupAnchorWidget,
            QObject* parentObject = nullptr);

        // setDockListProvider：
        // - 作用：注入参与搜索的 Dock 列表回调；
        // - 调用：MainWindow 接线时调用一次。
        void setDockListProvider(DockListProvider dockListProvider);

        // setDockPreparer：
        // - 作用：注入 Dock 懒加载初始化回调（搜索前逐个调用）；
        // - 调用：MainWindow 接线时调用一次。
        void setDockPreparer(DockPreparer dockPreparer);

        // setDockActivator：
        // - 作用：注入 Dock 置前激活回调（激活结果时调用）；
        // - 调用：MainWindow 接线时调用一次。
        void setDockActivator(DockActivator dockActivator);

    public slots:
        // handleQueryEdited：
        // - 作用：接收标题栏搜索文本变化并触发防抖搜索；
        // - 触发：CustomTitleBar::searchTextEdited；
        // - 传入 queryText：当前输入框文本（未修剪）。
        void handleQueryEdited(const QString& queryText);

        // setSearchInputActive：
        // - 作用：同步标题栏当前是否处于“搜索”输入模式；
        // - 触发：CustomTitleBar::inputModeChanged；
        // - 传入 searchModeActive：false 时立即收起结果弹层。
        void setSearchInputActive(bool searchModeActive);

        // dismissPopup：
        // - 作用：收起结果弹层并停止未决的防抖搜索。
        void dismissPopup();

    protected:
        // eventFilter：
        // - 作用：
        //   1) 输入框：Up/Down 选择结果、Enter 激活、Esc 收起、
        //      聚焦时按需重新展示结果；
        //   2) 宿主窗口：尺寸/位置变化时重新贴齐弹层、失活时收起；
        //   3) 应用级：点击弹层与输入组之外区域时收起。
        bool eventFilter(QObject* watchedObject, QEvent* eventObject) override;

    private:
        // ensurePopupCreated：
        // - 作用：首次需要时构建结果弹层控件树（列表+空态提示）。
        void ensurePopupCreated();

        // runSearchNow：
        // - 作用：立即执行一次搜索（防抖定时器到期或显式触发）；
        // - 说明：查询过短时等效于收起弹层。
        void runSearchNow();

        // rebuildResultList：
        // - 作用：按命中列表重建弹层列表项（含富文本高亮与路径行）。
        void rebuildResultList();

        // showPopupPanel：
        // - 作用：应用当前主题样式、计算尺寸并显示/置前弹层。
        void showPopupPanel();

        // repositionPopupPanel：
        // - 作用：把弹层水平居中贴到锚点下方并夹取进宿主窗口范围。
        void repositionPopupPanel();

        // activateHitAtRow：
        // - 作用：激活列表某一行对应的搜索命中；
        // - 传入 rowIndex：列表行号，越界时忽略。
        void activateHitAtRow(int rowIndex);

        // moveSelection：
        // - 作用：键盘上下键在结果列表中移动当前行（带边界夹取）；
        // - 传入 rowDelta：+1 向下，-1 向上。
        void moveSelection(int rowDelta);

        // isQueryLongEnough：
        // - 作用：判断查询是否达到最小搜索长度；
        // - 规则：≥2 个字符，或单个 CJK 等宽字符（U+2E80 起）。
        static bool isQueryLongEnough(const QString& queryText);

    private:
        QPointer<QWidget> m_popupHostWindow;      // m_popupHostWindow：弹层父窗口（主窗口）。
        QPointer<QLineEdit> m_searchInputEdit;    // m_searchInputEdit：标题栏中间输入框。
        QPointer<QWidget> m_popupAnchorWidget;    // m_popupAnchorWidget：弹层对齐锚点（输入组容器）。

        DockListProvider m_dockListProvider;      // m_dockListProvider：Dock 列表回调。
        DockPreparer m_dockPreparer;              // m_dockPreparer：Dock 懒加载初始化回调。
        DockActivator m_dockActivator;            // m_dockActivator：Dock 置前激活回调。

        QFrame* m_popupPanel = nullptr;           // m_popupPanel：结果弹层容器（宿主窗口子控件）。
        QListWidget* m_resultListWidget = nullptr;// m_resultListWidget：结果列表。
        QLabel* m_emptyHintLabel = nullptr;       // m_emptyHintLabel：无结果时的空态提示。
        QTimer* m_searchDebounceTimer = nullptr;  // m_searchDebounceTimer：输入防抖定时器。

        QString m_pendingQueryText;               // m_pendingQueryText：最近一次输入的查询文本。
        QVector<UiSearchHit> m_currentHitList;    // m_currentHitList：当前展示的命中列表（与列表行一一对应）。
        bool m_searchModeActive = true;           // m_searchModeActive：标题栏是否处于搜索输入模式。
    };
}
