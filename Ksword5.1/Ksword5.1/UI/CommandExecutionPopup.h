#pragma once

// ============================================================
// CommandExecutionPopup.h
// 作用说明：
// 1) 为标题栏 CMD 模式提供输入框下方的命令执行配置弹层；
// 2) 集中收集工作目录、用户令牌、权限级别和 CMD 窗口显示选项；
// 3) 只负责展示与收集参数，真正的 CreateProcess 调用由 MainWindow 执行。
// ============================================================

#include <QFrame>
#include <QPointer>
#include <QString>
#include <QtGlobal>

class QCheckBox;
class QComboBox;
class QEvent;
class QLabel;
class QLineEdit;
class QToolButton;
class QWidget;

namespace ks::ui
{
    // ============================================================
    // CommandExecutionOptions
    // 说明：描述一次标题栏 CMD 命令的启动选项，供 UI 与 MainWindow 之间传递。
    // ============================================================
    struct CommandExecutionOptions
    {
        // UserMode：选择创建命令进程时使用的用户令牌来源。
        enum class UserMode : int
        {
            CurrentUser = 0, // 跟随当前 KSword 进程的用户令牌。
            System = 1,      // 使用 SYSTEM 进程令牌（PID 4）。
            ProcessToken = 2 // 使用用户指定 PID 的进程令牌。
        };

        // PrivilegeMode：选择当前用户模式下的目标权限级别。
        enum class PrivilegeMode : int
        {
            Current = 0,      // 继承当前 KSword 权限。
            Administrator = 1, // 通过 UAC 请求管理员权限。
            Standard = 2      // 已提升时使用交互式 Shell 的普通用户令牌。
        };

        QString workingDirectory; // workingDirectory：cmd.exe 的初始工作目录。
        UserMode userMode = UserMode::CurrentUser; // userMode：用户令牌来源。
        quint32 tokenSourcePid = 0; // tokenSourcePid：ProcessToken 模式下的源进程 PID。
        PrivilegeMode privilegeMode = PrivilegeMode::Current; // privilegeMode：权限选择。
        bool openConsoleWindow = true; // openConsoleWindow：是否创建可见且保持打开的 CMD 窗口。
    };

    // ============================================================
    // CommandExecutionPopup
    // 说明：
    // - 作为主窗口子控件显示在标题栏输入组下方，视觉上与全局搜索弹层一致；
    // - 弹层关闭后保留控件状态，下一次切回 CMD 模式时继续使用上次选择；
    // - 不直接执行外部命令，避免 UI 层绕过 MainWindow 的权限与错误处理。
    // ============================================================
    class CommandExecutionPopup final : public QFrame
    {
        Q_OBJECT

    public:
        // 构造函数：创建命令选项控件，并把弹层锚定到标题栏输入组。
        // 参数 popupHostWindow：承载弹层的主窗口；
        // 参数 popupAnchorWidget：标题栏输入组，弹层显示在其下方；
        // 参数 commandInputEdit：标题栏 CMD 输入框，用于读取命令和监听焦点；
        // 参数 parentObject：Qt 父对象。
        explicit CommandExecutionPopup(
            QWidget* popupHostWindow,
            QWidget* popupAnchorWidget,
            QLineEdit* commandInputEdit,
            QObject* parentObject = nullptr);

        // setCommandModeActive：同步当前是否处于 CMD 模式，并按需显示/隐藏弹层。
        // 参数 commandModeActive：true=CMD 模式，false=搜索模式。
        void setCommandModeActive(bool commandModeActive);

        // currentOptions：读取当前控件状态，供 MainWindow 组装启动请求。
        CommandExecutionOptions currentOptions() const;

        // isPopupVisible：返回配置弹层当前是否可见。
        bool isPopupVisible() const;

    public slots:
        // dismissPopup：收起弹层但保留用户已选择的参数。
        void dismissPopup();

    signals:
        // executeRequested：用户点击弹层执行按钮时发出命令和参数快照。
        void executeRequested(
            const QString& commandText,
            const CommandExecutionOptions& options);

    protected:
        // eventFilter：处理输入框焦点、主窗口移动/缩放与弹层外点击。
        bool eventFilter(QObject* watchedObject, QEvent* eventObject) override;

    private:
        // initializeUi：创建弹层内的标题、目录、用户、权限和窗口选项控件。
        void initializeUi();

        // refreshTextAndStyle：按当前主题和语言包刷新弹层文本与不透明背景样式。
        void refreshTextAndStyle();

        // showPopupPanel：计算尺寸并把弹层放到标题栏输入组下方。
        void showPopupPanel();

        // repositionPopupPanel：窗口移动或尺寸变化时重新对齐弹层。
        void repositionPopupPanel();

        // updateUserModeUi：根据用户令牌来源显示 PID 输入并限制不适用的权限选项。
        void updateUserModeUi();

        // selectWorkingDirectory：打开目录选择器并回填工作目录输入框。
        void selectWorkingDirectory();

        // requestExecution：校验当前输入后发出执行请求。
        void requestExecution();

        // widgetBelongsToBranch：判断控件是否属于指定父控件分支。
        static bool widgetBelongsToBranch(QWidget* widget, QWidget* branchRoot);

        // isComboPopupEvent：识别用户/权限下拉框的独立 Qt Popup 事件，避免点击选项时误收起父弹层。
        bool isComboPopupEvent(QObject* watchedObject) const;

        // text：读取语义化语言键，fallbackText 作为语言包缺失时的中文回退。
        static QString text(const QString& key, const QString& fallbackText);

    private:
        QPointer<QWidget> m_popupHostWindow; // m_popupHostWindow：主窗口宿主。
        QPointer<QWidget> m_popupAnchorWidget; // m_popupAnchorWidget：标题栏输入组锚点。
        QPointer<QLineEdit> m_commandInputEdit; // m_commandInputEdit：标题栏命令输入框。

        QLabel* m_titleLabel = nullptr; // m_titleLabel：弹层标题。
        QToolButton* m_closeButton = nullptr; // m_closeButton：收起弹层按钮。
        QLabel* m_workingDirectoryLabel = nullptr; // m_workingDirectoryLabel：目录字段标签。
        QLineEdit* m_workingDirectoryEdit = nullptr; // m_workingDirectoryEdit：工作目录输入框。
        QToolButton* m_browseDirectoryButton = nullptr; // m_browseDirectoryButton：选择目录按钮。
        QLabel* m_userModeLabel = nullptr; // m_userModeLabel：用户字段标签。
        QComboBox* m_userModeCombo = nullptr; // m_userModeCombo：用户令牌来源下拉框。
        QLabel* m_tokenPidLabel = nullptr; // m_tokenPidLabel：令牌 PID 字段标签。
        QLineEdit* m_tokenPidEdit = nullptr; // m_tokenPidEdit：指定进程令牌 PID 输入框。
        QLabel* m_privilegeLabel = nullptr; // m_privilegeLabel：权限字段标签。
        QComboBox* m_privilegeCombo = nullptr; // m_privilegeCombo：权限级别下拉框。
        QCheckBox* m_openConsoleCheckBox = nullptr; // m_openConsoleCheckBox：CMD 窗口显示开关。
        QLabel* m_hintLabel = nullptr; // m_hintLabel：回车、/K、/C 行为说明。
        QToolButton* m_executeButton = nullptr; // m_executeButton：发出命令执行请求的按钮。

        bool m_commandModeActive = false; // m_commandModeActive：当前是否处于 CMD 模式。
    };
}
