#include "ScannerDock.h"

#include "Internationalization/LanguageManager.h"
#include "ksword/scanner/binary_scanner.h"
#include "theme.h"

#include <QAction>
#include <QHeaderView>
#include <QHBoxLayout>
#include <QMenu>
#include <QPointer>
#include <QPushButton>
#include <QTableWidget>
#include <QTableWidgetItem>
#include <QVBoxLayout>

#include <algorithm>
#include <memory>
#include <vector>

namespace
{
    // fromBackendUtf8 作用：把扫描后端的 UTF-8 标识与回退文本转换为 Qt 字符串。
    QString fromBackendUtf8(const std::string& value)
    {
        return QString::fromUtf8(value.data(), static_cast<qsizetype>(value.size()));
    }
}

QString ScannerDock::localizedTableTitle(
    const std::string& tableId,
    const std::string& fallback) const
{
    const QString id = fromBackendUtf8(tableId).toLower();
    if (id == QStringLiteral("sections"))
    {
        return translated("scanner.table.sections", "节区");
    }
    if (id == QStringLiteral("segments"))
    {
        return translated("scanner.table.segments", "段");
    }
    if (id == QStringLiteral("imports"))
    {
        return translated("scanner.table.imports", "导入");
    }
    if (id == QStringLiteral("exports"))
    {
        return translated("scanner.table.exports", "导出");
    }
    if (id == QStringLiteral("symbols"))
    {
        return translated("scanner.table.symbols", "符号");
    }
    if (id == QStringLiteral("load_commands"))
    {
        return translated("scanner.table.load_commands", "加载命令");
    }
    if (id == QStringLiteral("fat_architectures") ||
        id == QStringLiteral("architectures") ||
        id == QStringLiteral("slices"))
    {
        return translated("scanner.table.architectures", "架构切片");
    }
    if (id == QStringLiteral("dynamic_entries") ||
        id == QStringLiteral("dynamic_dependencies"))
    {
        return translated("scanner.table.dynamic_entries", "动态链接条目");
    }
    if (id == QStringLiteral("dynamic_libraries"))
    {
        return translated("scanner.table.dynamic_libraries", "动态库");
    }
    if (id == QStringLiteral("program_headers"))
    {
        return translated("scanner.table.program_headers", "程序头");
    }
    return ks::i18n::sourceText(fromBackendUtf8(fallback));
}

QString ScannerDock::localizedColumnTitle(const std::string& fallback) const
{
    const QString value = fromBackendUtf8(fallback);
    const QString normalized = value.trimmed().toLower();
    if (normalized == QStringLiteral("name"))
    {
        return translated("scanner.column.name", "名称");
    }
    if (normalized == QStringLiteral("value"))
    {
        return translated("scanner.column.value", "值");
    }
    if (normalized == QStringLiteral("index"))
    {
        return translated("scanner.column.index", "索引");
    }
    if (normalized == QStringLiteral("type"))
    {
        return translated("scanner.column.type", "类型");
    }
    if (normalized == QStringLiteral("flags"))
    {
        return translated("scanner.column.flags", "标志");
    }
    if (normalized == QStringLiteral("offset") || normalized == QStringLiteral("file offset"))
    {
        return translated("scanner.column.offset", "偏移");
    }
    if (normalized == QStringLiteral("size") || normalized == QStringLiteral("file size"))
    {
        return translated("scanner.column.size", "大小");
    }
    if (normalized == QStringLiteral("address") ||
        normalized == QStringLiteral("virtual address"))
    {
        return translated("scanner.column.address", "地址");
    }
    if (normalized == QStringLiteral("format"))
    {
        return translated("scanner.column.format", "格式");
    }
    if (normalized == QStringLiteral("byte order"))
    {
        return translated("scanner.column.byte_order", "字节序");
    }
    if (normalized == QStringLiteral("module") || normalized == QStringLiteral("library"))
    {
        return translated("scanner.column.module", "模块");
    }
    if (normalized == QStringLiteral("ordinal"))
    {
        return translated("scanner.column.ordinal", "序号");
    }
    return ks::i18n::sourceText(value);
}

QString ScannerDock::diagnosticSeverityText(const int severity) const
{
    switch (static_cast<ks::scanner::DiagnosticSeverity>(severity))
    {
    case ks::scanner::DiagnosticSeverity::Information:
        return translated("scanner.severity.information", "信息");
    case ks::scanner::DiagnosticSeverity::Warning:
        return translated("scanner.severity.warning", "警告");
    case ks::scanner::DiagnosticSeverity::Error:
        return translated("scanner.severity.error", "错误");
    default:
        return translated("scanner.severity.unknown", "未知");
    }
}

QWidget* ScannerDock::createStructuredTablePage(
    QTableWidget* table,
    const int columnCount) const
{
    // 五列以内无需拆组；返回原表可避免增加无意义的控制条。
    if (table == nullptr || columnCount <= 5)
    {
        return table;
    }

    // page/pageLayout：宽表页由紧贴的 A/B/C 控件和原只读表组成。
    auto* page = new QWidget(m_resultTabs); // page：本结构表的外层页面。
    auto* pageLayout = new QVBoxLayout(page); // pageLayout：纵向排列列组按钮与数据表。
    pageLayout->setContentsMargins(0, 0, 0, 0);
    pageLayout->setSpacing(4);
    auto* buttonLayout = new QHBoxLayout(); // buttonLayout：无间距排列 A/B/C 按钮。
    buttonLayout->setContentsMargins(0, 0, 0, 0);
    buttonLayout->setSpacing(0);

    // groupCount：最多三组；第一列作为识别键在各组保留，其余列平均分配。
    const int remainingColumns = columnCount - 1; // remainingColumns：除识别列外的字段数。
    const int groupCount = std::clamp((remainingColumns + 3) / 4, 2, 3); // groupCount：实际列组数。
    const int columnsPerGroup = (remainingColumns + groupCount - 1) / groupCount; // columnsPerGroup：每组字段上限。
    auto groups = std::make_shared<std::vector<std::vector<int>>>(); // groups：每个预设显示的列索引。
    auto buttons = std::make_shared<std::vector<QPointer<QPushButton>>>(); // buttons：可安全失效的列组按钮。

    // activeStyle/inactiveStyle：当前预设使用主题强调色；自定义显隐时全部取消着色。
    const QString activeStyle = QStringLiteral(
        "QPushButton { background:%1; color:%2; border:1px solid %1; padding:3px 10px; }")
        .arg(
            KswordTheme::AccentHex(KswordTheme::AccentRole::Blue),
            KswordTheme::OnAccentHex()); // activeStyle：激活预设的样式。
    const QString inactiveStyle = QStringLiteral(
        "QPushButton { background:%1; color:%2; border:1px solid %3; padding:3px 10px; }"
        "QPushButton:hover { background:%4; }")
        .arg(
            KswordTheme::SurfaceColorHex(),
            KswordTheme::TextPrimaryColorHex(),
            KswordTheme::BorderColorHex(),
            KswordTheme::SurfaceAltColorHex()); // inactiveStyle：未选中或自定义布局样式。

    for (int groupIndex = 0; groupIndex < groupCount; ++groupIndex)
    {
        // columns：每组保留第 0 列，并加入属于本组的互补字段。
        std::vector<int> columns{ 0 }; // columns：当前 A/B/C 预设的可见列。
        const int firstColumn = 1 + groupIndex * columnsPerGroup; // firstColumn：当前分组首列。
        const int endColumn = std::min(columnCount, firstColumn + columnsPerGroup); // endColumn：当前分组尾后列。
        for (int column = firstColumn; column < endColumn; ++column)
        {
            columns.push_back(column);
        }
        groups->push_back(std::move(columns));

        // groupButton：A/B/C 采用紧贴布局，并通过悬停说明当前行为。
        const char16_t groupLetter = static_cast<char16_t>(u'A' + groupIndex); // groupLetter：当前组的字母标识。
        auto* groupButton = new QPushButton(
            QString(QChar(groupLetter)),
            page); // groupButton：切换到当前互补字段组。
        groupButton->setMinimumWidth(36);
        groupButton->setToolTip(
            translated(
                "scanner.column_view.tooltip",
                "列组 %1：显示一组互补字段；可在表头右键自定义列。")
                .arg(groupButton->text()));
        groupButton->setStyleSheet(groupIndex == 0 ? activeStyle : inactiveStyle);
        buttons->push_back(groupButton);
        buttonLayout->addWidget(groupButton);
    }
    buttonLayout->addStretch(1);
    pageLayout->addLayout(buttonLayout);
    pageLayout->addWidget(table, 1);

    // applyGroup：切换预设时先隐藏所有列，再仅显示目标组并更新按钮主题。
    const auto applyGroup =
        [table, groups, buttons, activeStyle, inactiveStyle](const int groupIndex)
        {
            for (int column = 0; column < table->columnCount(); ++column)
            {
                table->setColumnHidden(column, true);
            }
            for (const int column : groups->at(static_cast<std::size_t>(groupIndex)))
            {
                table->setColumnHidden(column, false);
            }
            for (int buttonIndex = 0; buttonIndex < static_cast<int>(buttons->size()); ++buttonIndex)
            {
                if (buttons->at(static_cast<std::size_t>(buttonIndex)))
                {
                    buttons->at(static_cast<std::size_t>(buttonIndex))->setStyleSheet(
                        buttonIndex == groupIndex ? activeStyle : inactiveStyle);
                }
            }
        };

    for (int groupIndex = 0; groupIndex < static_cast<int>(buttons->size()); ++groupIndex)
    {
        // groupButton：当前按钮连接到自己的预设索引，点击不会改变表内数据。
        QPushButton* groupButton = buttons->at(static_cast<std::size_t>(groupIndex)); // groupButton：待连接按钮。
        connect(
            groupButton,
            &QPushButton::clicked,
            page,
            [applyGroup, groupIndex]() { applyGroup(groupIndex); });
    }
    applyGroup(0);

    // 表头右键菜单允许逐列显隐；每次手动调整后取消 A/B/C 激活色，表示自定义布局。
    QHeaderView* tableHeader = table->horizontalHeader(); // tableHeader：承载列菜单的表头。
    tableHeader->setContextMenuPolicy(Qt::CustomContextMenu);
    connect(
        tableHeader,
        &QHeaderView::customContextMenuRequested,
        page,
        [this, table, tableHeader, buttons, inactiveStyle](const QPoint& position)
        {
            QMenu menu(tableHeader); // menu：仅在当前右键操作期间存在的列显隐菜单。
            menu.setStyleSheet(QStringLiteral(
                "QMenu { background:%1; color:%2; border:1px solid %3; }"
                "QMenu::item { padding:5px 22px; }"
                "QMenu::item:selected { background:%4; color:%5; }"
                "QMenu::item:disabled { color:%6; }")
                .arg(
                    KswordTheme::SurfaceColorHex(),
                    KswordTheme::TextPrimaryColorHex(),
                    KswordTheme::BorderColorHex(),
                    KswordTheme::AccentHex(KswordTheme::AccentRole::Blue),
                    KswordTheme::OnAccentHex(),
                    KswordTheme::TextDisabledColorHex()));

            // columnAction：勾选状态直接反映当前列可见性。
            for (int column = 0; column < table->columnCount(); ++column)
            {
                QAction* columnAction = menu.addAction( // columnAction：控制单列显隐的菜单项。
                    table->horizontalHeaderItem(column) != nullptr
                        ? table->horizontalHeaderItem(column)->text()
                        : translated("scanner.column.unnamed", "未命名列"));
                columnAction->setCheckable(true);
                columnAction->setChecked(!table->isColumnHidden(column));
                connect(
                    columnAction,
                    &QAction::toggled,
                    &menu,
                    [table, column, buttons, inactiveStyle](const bool visible)
                    {
                        table->setColumnHidden(column, !visible);
                        for (const QPointer<QPushButton>& button : *buttons)
                        {
                            if (button)
                            {
                                button->setStyleSheet(inactiveStyle);
                            }
                        }
                    });
            }
            menu.exec(tableHeader->mapToGlobal(position));
        });
    return page;
}
