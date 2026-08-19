#pragma once

// ============================================================
// DetailLayoutHost.h
// 作用：
// - 把严格命中页面的“数据视图 + CodeEditorWidget”统一适配为四种详情布局；
// - 页面仍负责生成详情文本，本类只负责布局、展开状态和文本镜像；
// - 使用 QPersistentModelIndex 跟踪合成详情行，避免插入行后缓存索引漂移。
// ============================================================

#include "../SettingsDock/AppearanceSettings.h"

#include <QList>
#include <QObject>
#include <QPersistentModelIndex>
#include <QPointer>
#include <QString>
#include <QVariant>

class CodeEditorWidget;
class QAbstractItemView;
class QDialog;
class QEvent;
class QPlainTextEdit;
class QSplitter;
class QToolButton;
class QTreeWidgetItem;
class QWidget;

namespace ks::ui
{
    // DetailLayoutHost：单个页面的详情布局控制器。
    // 调用方式：页面完成表格和 CodeEditorWidget 创建后交给 DetailLayoutRegistry 注册。
    class DetailLayoutHost final : public QObject
    {
    public:
        // 构造函数：记录视图、详情编辑器和页面宿主，并立即建立统一分隔器。
        // 入参 tableView/detailEditor/ownerWidget：数据视图、原详情控件和页面宿主。
        DetailLayoutHost(
            QAbstractItemView* tableView,
            CodeEditorWidget* detailEditor,
            QWidget* ownerWidget);
        ~DetailLayoutHost() override;

        // setTableView / setDetailEditor：供注册表或页面在延迟创建控件后重新绑定。
        // 入参为目标控件；无业务返回值。
        void setTableView(QAbstractItemView* tableView);
        void setDetailEditor(CodeEditorWidget* detailEditor);

        // applyScheme：切换当前页面布局；会清理旧模式的临时合成行/窗口状态。
        void applyScheme(ks::settings::DetailDisplayScheme scheme);

        // clearEmbeddedDetails：移除所有行内详情并恢复源行图标。
        void clearEmbeddedDetails();

        // prepareDataRebuild：页面重建表格数据前调用；当前等价于清理行内详情。
        void prepareDataRebuild();

        // detailEditor：返回当前页面原始 CodeEditorWidget，供注册表去重。
        CodeEditorWidget* detailEditor() const;

    protected:
        // eventFilter：监听独立窗口激活状态，按要求切换 100%/30% 不透明度。
        bool eventFilter(QObject* watchedObject, QEvent* eventObject) override;

    private:
        // EmbeddedEntry：保存一个源行与其合成详情控件的稳定对应关系。
        struct EmbeddedEntry
        {
            QPersistentModelIndex sourceIndex;
            QPointer<QPlainTextEdit> textEditor;
            QTreeWidgetItem* treeSourceItem = nullptr;
            QTreeWidgetItem* treeDetailItem = nullptr;
        };

        // initializeHostUi / initializeConnections：创建统一分隔器、箭头并绑定文本/点击事件。
        void initializeHostUi();
        void initializeConnections();

        // ensureManagedSplitter：复用既有分隔器或把直接布局中的表格/详情包装进新分隔器。
        void ensureManagedSplitter();

        // updateBottomExpanded：更新下方详情显隐、箭头方向和默认分隔比例。
        void updateBottomExpanded(bool expanded);

        // handleViewClicked：按当前方案处理一次用户行点击。
        void handleViewClicked(const QPersistentModelIndex& sourceIndex);

        // handleDetailChanged：同步原详情文本到当前合成行或独立窗口。
        void handleDetailChanged(const QString& detailText);

        // toggleEmbeddedDetail：为当前源行插入或移除只读 QPlainTextEdit 详情行。
        void toggleEmbeddedDetail(const QPersistentModelIndex& sourceIndex);

        // insertTableEmbeddedDetail / insertTreeEmbeddedDetail：分别适配表格和树视图。
        void insertTableEmbeddedDetail(const QPersistentModelIndex& sourceIndex, const QString& detailText);
        void insertTreeEmbeddedDetail(const QPersistentModelIndex& sourceIndex, const QString& detailText);

        // removeEmbeddedEntry：移除指定源行的合成详情；返回 true 表示已找到并移除。
        bool removeEmbeddedEntry(const QPersistentModelIndex& sourceIndex);

        // refreshEmbeddedIndicators：给可展开源行绘制右/下箭头，并跳过合成详情行。
        void refreshEmbeddedIndicators();
        void restoreEmbeddedIndicators();
        void setSourceExpandedIndicator(const QPersistentModelIndex& sourceIndex, bool expanded);

        // showFloatingWindow / destroyFloatingWindow：管理当前页面唯一的非模态详情窗口。
        void showFloatingWindow();
        void destroyFloatingWindow();

        // isEmbeddedMarker：判断模型索引是否为本类插入的合成详情行/节点。
        bool isEmbeddedMarker(const QPersistentModelIndex& modelIndex) const;

        QPointer<QAbstractItemView> m_tableView;       // m_tableView：页面原始表格或树。
        QPointer<CodeEditorWidget> m_detailEditor;     // m_detailEditor：页面原始详情编辑器。
        QPointer<QWidget> m_ownerWidget;               // m_ownerWidget：生命周期宿主。
        QPointer<QSplitter> m_splitter;                // m_splitter：统一承载表格和原详情区。
        QPointer<QWidget> m_detailPane;                // m_detailPane：分隔器中的完整详情面板。
        QPointer<QWidget> m_toggleBar;                  // m_toggleBar：占满页面宽度的箭头承载条，避免固定宽按钮压窄分隔器。
        QPointer<QToolButton> m_toggleButton;           // m_toggleButton：下方折叠方案的箭头按钮。
        QPointer<QDialog> m_floatingWindow;             // m_floatingWindow：当前页面唯一详情窗口。
        QPointer<CodeEditorWidget> m_floatingEditor;    // m_floatingEditor：独立窗口中的只读镜像编辑器。
        QList<EmbeddedEntry> m_embeddedEntries;         // m_embeddedEntries：当前已展开的多行详情。
        ks::settings::DetailDisplayScheme m_scheme =
            ks::settings::DetailDisplayScheme::BottomCollapsed;
        bool m_bottomExpanded = false;                  // m_bottomExpanded：下方详情是否展开。
        bool m_internalModelChange = false;             // m_internalModelChange：防止合成行变更递归响应。
        bool m_tableSortingStateCaptured = false;       // m_tableSortingStateCaptured：是否已保存表格原排序状态。
        bool m_tableSortingWasEnabled = false;          // m_tableSortingWasEnabled：退出行内模式时恢复的排序状态。
    };
}
