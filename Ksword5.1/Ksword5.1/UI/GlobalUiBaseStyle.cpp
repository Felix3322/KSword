#include "GlobalUiBaseStyle.h"

#include "../theme.h"

namespace ks::ui
{
    QString BuildGlobalBaseControlStyleBlock()
    {
        // 所有颜色都来自 KswordTheme 动态角色，深浅色与自定义主题色变化时整块重建。
        QString baseControlStyle = QString::fromLatin1(
            "\n__BEGIN_MARKER__\n"

            // ---------- 按钮基线 ----------
            // 未被局部样式接管的普通按钮统一为“中性表面 + 主题色交互”。
            // 基线只允许颜色/边框属性：min-height、padding 等几何属性会穿透
            // 局部样式改变紧凑布局（如标题栏图标按钮）的尺寸，一律禁止。
            "QPushButton{"
            "  background-color:__SURFACE_ALT__;"
            "  color:__TEXT__;"
            "  border:1px solid __BORDER__;"
            "  border-radius:3px;"
            "}"
            "QPushButton:hover{"
            "  background-color:__SURFACE_MUTED__;"
            "  border-color:__ACCENT__;"
            "}"
            "QPushButton:pressed{"
            "  background-color:__ACCENT_PRESSED__;"
            "  color:__ON_ACCENT__;"
            "  border-color:__ACCENT_PRESSED__;"
            "}"
            "QPushButton:checked{"
            "  background-color:__ACCENT__;"
            "  color:__ON_ACCENT__;"
            "  border-color:__ACCENT__;"
            "}"
            "QPushButton:default{"
            "  border-color:__ACCENT__;"
            "}"
            "QPushButton:disabled{"
            "  background-color:__SURFACE_MUTED__;"
            "  color:__TEXT_DISABLED__;"
            "  border-color:__BORDER__;"
            "}"
            "QPushButton:flat{"
            "  background-color:transparent;"
            "  border:none;"
            "}"

            // ---------- 输入控件基线 ----------
            // 选择器组必须与“{”写在同一字符串片段内，i18n 审计才能识别为 QSS 而非 UI 文本。
            "QLineEdit,QPlainTextEdit,QTextEdit,QSpinBox,QDoubleSpinBox,QDateEdit,QTimeEdit,QDateTimeEdit{"
            "  background-color:__SURFACE__;"
            "  color:__TEXT__;"
            "  border:1px solid __BORDER__;"
            "  border-radius:3px;"
            "  selection-background-color:__ACCENT__;"
            "  selection-color:__ON_ACCENT__;"
            "}"
            "QLineEdit:hover,QPlainTextEdit:hover,QTextEdit:hover,QSpinBox:hover,QDoubleSpinBox:hover,QDateEdit:hover,QTimeEdit:hover,QDateTimeEdit:hover{"
            "  border-color:__BORDER_STRONG__;"
            "}"
            "QLineEdit:focus,QPlainTextEdit:focus,QTextEdit:focus,QSpinBox:focus,QDoubleSpinBox:focus,QDateEdit:focus,QTimeEdit:focus,QDateTimeEdit:focus{"
            "  border-color:__ACCENT__;"
            "}"
            "QLineEdit:disabled,QPlainTextEdit:disabled,QTextEdit:disabled,QSpinBox:disabled,QDoubleSpinBox:disabled,QDateEdit:disabled,QTimeEdit:disabled,QDateTimeEdit:disabled{"
            "  background-color:__SURFACE_MUTED__;"
            "  color:__TEXT_DISABLED__;"
            "}"
            // 只读输入框必须与可编辑的区分开：项目里有上百处 setReadOnly(true)
            // 的展示型输入框（进程详情的路径、命令行等），它们此前与可编辑控件
            // 外观完全一致——有边框、能获得焦点、悬停还会高亮，用户会反复尝试
            // 修改并以为程序卡了。这里给只读态一个明确的“非输入面”底色，
            // 但保留文字颜色与可选中能力，因为内容仍然需要被阅读和复制。
            "QLineEdit:read-only,QPlainTextEdit:read-only,QTextEdit:read-only,QSpinBox:read-only,QDoubleSpinBox:read-only,QDateEdit:read-only,QTimeEdit:read-only,QDateTimeEdit:read-only{"
            "  background-color:__SURFACE_MUTED__;"
            "}"
            "QLineEdit:read-only:hover,QPlainTextEdit:read-only:hover,QTextEdit:read-only:hover,QSpinBox:read-only:hover,QDoubleSpinBox:read-only:hover,QDateEdit:read-only:hover,QTimeEdit:read-only:hover,QDateTimeEdit:read-only:hover{"
            "  border-color:__BORDER__;"
            "}"
            "QLineEdit:read-only:focus,QPlainTextEdit:read-only:focus,QTextEdit:read-only:focus,QSpinBox:read-only:focus,QDoubleSpinBox:read-only:focus,QDateEdit:read-only:focus,QTimeEdit:read-only:focus,QDateTimeEdit:read-only:focus{"
            "  border-color:__BORDER__;"
            "}"

            // ---------- 分组框基线 ----------
            // margin-top 是标题行所需的最小空间，与 Qt 原生标题高度一致。
            "QGroupBox{"
            "  border:1px solid __BORDER__;"
            "  border-radius:4px;"
            "  margin-top:12px;"
            "}"
            "QGroupBox::title{"
            "  subcontrol-origin:margin;"
            "  subcontrol-position:top left;"
            "  left:8px;"
            "  padding:0px 4px;"
            "  color:__TEXT_SECONDARY__;"
            "  font-weight:600;"
            "}"

            // ---------- 表头基线 ----------
            // 统一各页面表格/树的表头为“中性次级表面 + 底部分隔线”。
            "QHeaderView{"
            "  background-color:transparent;"
            "  border:none;"
            "}"
            "QHeaderView::section{"
            "  background-color:__SURFACE_ALT__;"
            "  color:__TEXT__;"
            "  border:none;"
            "  border-right:1px solid __BORDER__;"
            "  border-bottom:1px solid __BORDER_STRONG__;"
            "}"
            "QHeaderView::section:hover{"
            "  background-color:__SURFACE_MUTED__;"
            "}"

            // ---------- 进度条基线 ----------
            "QProgressBar{"
            "  background-color:__SURFACE_MUTED__;"
            "  color:__TEXT__;"
            "  border:1px solid __BORDER__;"
            "  border-radius:3px;"
            "  text-align:center;"
            "}"
            "QProgressBar::chunk{"
            "  background-color:__ACCENT__;"
            "  border-radius:2px;"
            "}"

            // ---------- 分割条基线 ----------
            "QSplitter::handle{"
            "  background-color:transparent;"
            "}"
            "QSplitter::handle:hover{"
            "  background-color:__ACCENT__;"
            "}"

            // ---------- 状态栏基线 ----------
            "QStatusBar{"
            "  background-color:__WINDOW__;"
            "  color:__TEXT_SECONDARY__;"
            "}"
            "QStatusBar::item{"
            "  border:none;"
            "}"

            "__END_MARKER__\n");

        baseControlStyle.replace(QStringLiteral("__BEGIN_MARKER__"), QString::fromLatin1(kBaseControlStyleBeginMarker));
        baseControlStyle.replace(QStringLiteral("__END_MARKER__"), QString::fromLatin1(kBaseControlStyleEndMarker));
        baseControlStyle.replace(QStringLiteral("__WINDOW__"), KswordTheme::MainBackgroundColorHex());
        baseControlStyle.replace(QStringLiteral("__SURFACE__"), KswordTheme::SurfaceColorHex());
        baseControlStyle.replace(QStringLiteral("__SURFACE_ALT__"), KswordTheme::SurfaceAltColorHex());
        baseControlStyle.replace(QStringLiteral("__SURFACE_MUTED__"), KswordTheme::SurfaceMutedColorHex());
        baseControlStyle.replace(QStringLiteral("__BORDER_STRONG__"), KswordTheme::BorderStrongColorHex());
        baseControlStyle.replace(QStringLiteral("__BORDER__"), KswordTheme::BorderColorHex());
        baseControlStyle.replace(QStringLiteral("__TEXT_SECONDARY__"), KswordTheme::TextSecondaryColorHex());
        baseControlStyle.replace(QStringLiteral("__TEXT_DISABLED__"), KswordTheme::TextDisabledColorHex());
        baseControlStyle.replace(QStringLiteral("__TEXT__"), KswordTheme::TextPrimaryColorHex());
        baseControlStyle.replace(QStringLiteral("__ACCENT_PRESSED__"), KswordTheme::ControlAccentPressedHex());
        baseControlStyle.replace(QStringLiteral("__ACCENT__"), KswordTheme::ControlAccentHex());
        baseControlStyle.replace(
            QStringLiteral("__ON_ACCENT__"),
            KswordTheme::ThemeColorName(
                KswordTheme::MaximumContrastMonochromeColor(KswordTheme::ControlAccentColor())));
        return baseControlStyle;
    }
}
