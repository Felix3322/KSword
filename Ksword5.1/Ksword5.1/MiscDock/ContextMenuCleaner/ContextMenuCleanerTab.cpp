#include "ContextMenuCleanerTab.h"
#include "../../Framework/PrivilegeElevationPrompt.h"
#include "../../UI/VisibleTableWidget.h"

#include "ContextMenuCleanerTab.Internal.h"
#include "../../theme.h"

#include <QAbstractItemView>
#include <QAction>
#include <QApplication>
#include <QClipboard>
#include <QHeaderView>
#include <QHBoxLayout>
#include <QIcon>
#include <QItemSelectionModel>
#include <QLabel>
#include <QLineEdit>
#include <QMenu>
#include <QMessageBox>
#include <QPushButton>
#include <QTableWidget>
#include <QTableWidgetItem>
#include <QTabWidget>
#include <QVBoxLayout>
#include <QStringList>

#include <array>

namespace ks::misc
{

using namespace context_menu_cleaner_detail;

ContextMenuCleanerTab::ContextMenuCleanerTab(QWidget* parent)
    : QWidget(parent)
{
    initializeUi();
    refreshArea(MenuArea::InternetExplorer);

    kLogEvent event;
    info << event << "[ContextMenuCleanerTab] 右键菜单清理页初始化完成。" << eol;
}

void ContextMenuCleanerTab::initializeUi()
{
    // 根布局：上方风险说明，下方七类 Shell 关联子页。
    m_rootLayout = new QVBoxLayout(this);
    m_rootLayout->setContentsMargins(6, 6, 6, 6);
    m_rootLayout->setSpacing(6);

    m_hintLabel = new QLabel(
        QStringLiteral("提示：本页统一管理右键菜单、URL 绑定、文件打开方式和资源管理器主页第三方程序。URL 绑定删除前会自动备份并可一键恢复；其他分类不会自动备份。操作前请确认来源，更改后通常需要重启 Explorer 或相关程序才会完全刷新。"),
        this);
    m_hintLabel->setWordWrap(true);
    m_hintLabel->setStyleSheet(QStringLiteral("color:%1;").arg(KswordTheme::TextSecondaryHex()));
    m_rootLayout->addWidget(m_hintLabel);

    m_areaTabWidget = new QTabWidget(this);
    m_areaTabWidget->setObjectName(QStringLiteral("ksContextMenuCleanerAreaTabs"));
    m_rootLayout->addWidget(m_areaTabWidget, 1);

    createAreaPage(MenuArea::InternetExplorer);
    createAreaPage(MenuArea::Desktop);
    createAreaPage(MenuArea::File);
    createAreaPage(MenuArea::UrlBinding);
    createAreaPage(MenuArea::OpenWith);
    createAreaPage(MenuArea::FormatMenu);
    createAreaPage(MenuArea::ExplorerHome);

    // 页签按需加载：
    // - URL/格式菜单会扫描大量 Classes 子键，不在杂项页构造时一次性阻塞 UI；
    // - 用户首次切换到分类时枚举一次，之后仅由刷新按钮主动重扫。
    const std::array<MenuArea, 7> orderedAreas{
        MenuArea::InternetExplorer,
        MenuArea::Desktop,
        MenuArea::File,
        MenuArea::UrlBinding,
        MenuArea::OpenWith,
        MenuArea::FormatMenu,
        MenuArea::ExplorerHome
    };
    connect(
        m_areaTabWidget,
        &QTabWidget::currentChanged,
        this,
        [this, orderedAreas](const int tabIndex) {
            if (tabIndex < 0
                || tabIndex >= static_cast<int>(orderedAreas.size()))
            {
                return;
            }
            const MenuArea area = orderedAreas[static_cast<std::size_t>(tabIndex)];
            AreaWidgets* areaWidgets = widgetsForArea(area);
            if (areaWidgets != nullptr && !areaWidgets->hasLoaded)
            {
                refreshArea(area);
            }
        });
}

void ContextMenuCleanerTab::createAreaPage(const MenuArea area)
{
    AreaWidgets* areaWidgets = widgetsForArea(area);
    if (areaWidgets == nullptr)
    {
        return;
    }

    areaWidgets->page = new QWidget(m_areaTabWidget);
    areaWidgets->layout = new QVBoxLayout(areaWidgets->page);
    areaWidgets->layout->setContentsMargins(0, 0, 0, 0);
    areaWidgets->layout->setSpacing(6);

    areaWidgets->toolbarWidget = new QWidget(areaWidgets->page);
    QHBoxLayout* toolbarLayout = new QHBoxLayout(areaWidgets->toolbarWidget);
    toolbarLayout->setContentsMargins(0, 0, 0, 0);
    toolbarLayout->setSpacing(6);
    areaWidgets->layout->addWidget(areaWidgets->toolbarWidget);

    areaWidgets->refreshButton = new QPushButton(QIcon(QStringLiteral(":/Icon/process_refresh.svg")), QStringLiteral("刷新"), areaWidgets->toolbarWidget);
    areaWidgets->refreshButton->setToolTip(QStringLiteral("重新枚举当前分类的 Shell 关联注册表项目"));
    areaWidgets->deleteButton = new QPushButton(QIcon(QStringLiteral(":/Icon/process_terminate.svg")), QStringLiteral("删除选中"), areaWidgets->toolbarWidget);
    areaWidgets->deleteButton->setToolTip(QStringLiteral("删除表格选中项对应的注册表子树或值"));
    if (area == MenuArea::UrlBinding)
    {
        areaWidgets->restoreButton = new QPushButton(
            QIcon(QStringLiteral(":/Icon/process_refresh.svg")),
            QStringLiteral("恢复上次删除"),
            areaWidgets->toolbarWidget);
        areaWidgets->restoreButton->setToolTip(QStringLiteral("恢复上一次 URL 绑定删除前自动保存的注册表树"));
    }
    areaWidgets->copyButton = new QPushButton(QIcon(QStringLiteral(":/Icon/log_copy.svg")), QStringLiteral("复制路径"), areaWidgets->toolbarWidget);
    areaWidgets->copyButton->setToolTip(QStringLiteral("复制选中项的注册表路径"));
    areaWidgets->filterEdit = new QLineEdit(areaWidgets->toolbarWidget);
    areaWidgets->filterEdit->setClearButtonEnabled(true);
    areaWidgets->filterEdit->setPlaceholderText(QStringLiteral("筛选：名称/显示名/命令/注册表路径/CLSID"));
    areaWidgets->filterEdit->setStyleSheet(buildInputStyle());

    areaWidgets->refreshButton->setStyleSheet(KswordTheme::ThemedButtonStyle());
    areaWidgets->deleteButton->setStyleSheet(KswordTheme::ThemedButtonStyle());
    if (areaWidgets->restoreButton != nullptr)
    {
        areaWidgets->restoreButton->setStyleSheet(KswordTheme::ThemedButtonStyle());
    }
    areaWidgets->copyButton->setStyleSheet(KswordTheme::ThemedButtonStyle());

    toolbarLayout->addWidget(areaWidgets->refreshButton);
    toolbarLayout->addWidget(areaWidgets->deleteButton);
    if (areaWidgets->restoreButton != nullptr)
    {
        toolbarLayout->addWidget(areaWidgets->restoreButton);
    }
    toolbarLayout->addWidget(areaWidgets->copyButton);
    toolbarLayout->addWidget(areaWidgets->filterEdit, 1);

    areaWidgets->table = new ks::ui::VisibleTableWidget(areaWidgets->page);
    areaWidgets->table->setColumnCount(kColumnCount);
    areaWidgets->table->setHorizontalHeaderLabels(QStringList{
        QStringLiteral("名称"),
        QStringLiteral("显示名"),
        QStringLiteral("类型"),
        QStringLiteral("来源"),
        QStringLiteral("命令/处理器"),
        QStringLiteral("注册表位置"),
        QStringLiteral("状态"),
        QStringLiteral("详情") });
    areaWidgets->table->setSelectionBehavior(QAbstractItemView::SelectRows);
    areaWidgets->table->setSelectionMode(QAbstractItemView::ExtendedSelection);
    areaWidgets->table->setEditTriggers(QAbstractItemView::NoEditTriggers);
    areaWidgets->table->setAlternatingRowColors(true);
    areaWidgets->table->setContextMenuPolicy(Qt::CustomContextMenu);
    areaWidgets->table->setHorizontalScrollMode(QAbstractItemView::ScrollPerPixel);
    areaWidgets->table->setSortingEnabled(true);
    areaWidgets->table->verticalHeader()->setVisible(false);
    areaWidgets->table->horizontalHeader()->setStyleSheet(buildHeaderStyle());
    areaWidgets->table->horizontalHeader()->setSectionResizeMode(kColumnName, QHeaderView::ResizeToContents);
    areaWidgets->table->horizontalHeader()->setSectionResizeMode(kColumnDisplayName, QHeaderView::ResizeToContents);
    areaWidgets->table->horizontalHeader()->setSectionResizeMode(kColumnKind, QHeaderView::ResizeToContents);
    areaWidgets->table->horizontalHeader()->setSectionResizeMode(kColumnSource, QHeaderView::ResizeToContents);
    areaWidgets->table->horizontalHeader()->setSectionResizeMode(kColumnCommandOrHandler, QHeaderView::Stretch);
    areaWidgets->table->horizontalHeader()->setSectionResizeMode(kColumnRegistryPath, QHeaderView::Stretch);
    areaWidgets->table->horizontalHeader()->setSectionResizeMode(kColumnStatus, QHeaderView::ResizeToContents);
    areaWidgets->table->horizontalHeader()->setSectionResizeMode(kColumnDetail, QHeaderView::Stretch);
    areaWidgets->layout->addWidget(areaWidgets->table, 1);

    areaWidgets->statusLabel = new QLabel(QStringLiteral("尚未刷新。"), areaWidgets->page);
    areaWidgets->statusLabel->setWordWrap(true);
    areaWidgets->layout->addWidget(areaWidgets->statusLabel);

    connect(areaWidgets->refreshButton, &QPushButton::clicked, this, [this, area]() {
        refreshArea(area);
    });
    connect(areaWidgets->deleteButton, &QPushButton::clicked, this, [this, area]() {
        deleteSelectedEntries(area);
    });
    if (areaWidgets->restoreButton != nullptr)
    {
        connect(areaWidgets->restoreButton, &QPushButton::clicked, this, [this]() {
            restoreLastUrlBindingBackup();
        });
    }
    connect(areaWidgets->copyButton, &QPushButton::clicked, this, [this, area]() {
        copySelectedEntries(area);
    });
    connect(areaWidgets->filterEdit, &QLineEdit::textChanged, this, [this, area](const QString&) {
        rebuildAreaTable(area);
    });
    connect(areaWidgets->table, &QTableWidget::customContextMenuRequested, this, [this, area](const QPoint& localPosition) {
        showAreaContextMenu(area, localPosition);
    });

    m_areaTabWidget->addTab(areaWidgets->page, QIcon(areaIconPath(area)), areaTitle(area));
}

void ContextMenuCleanerTab::refreshArea(const MenuArea area)
{
    AreaWidgets* areaWidgets = widgetsForArea(area);
    if (areaWidgets == nullptr)
    {
        return;
    }

    const QVector<ContextMenuEntry> newEntries = enumerateEntriesForArea(area);
    areaWidgets->entries = newEntries;
    areaWidgets->hasLoaded = true;
    rebuildAreaTable(area);

    kLogEvent event;
    info << event
        << "[ContextMenuCleanerTab] 刷新分类完成, area="
        << areaTitle(area).toStdString()
        << ", count="
        << newEntries.size()
        << eol;
}

void ContextMenuCleanerTab::rebuildAreaTable(const MenuArea area)
{
    AreaWidgets* areaWidgets = widgetsForArea(area);
    if (areaWidgets == nullptr || areaWidgets->table == nullptr)
    {
        return;
    }

    const QString filterText = areaWidgets->filterEdit != nullptr
        ? areaWidgets->filterEdit->text().trimmed().toLower()
        : QString();

    areaWidgets->table->setSortingEnabled(false);
    areaWidgets->table->setRowCount(0);

    int visibleCount = 0;
    for (int entryIndex = 0; entryIndex < areaWidgets->entries.size(); ++entryIndex)
    {
        const ContextMenuEntry& entry = areaWidgets->entries.at(entryIndex);
        const QString searchableText = QStringList{
            entry.itemName,
            entry.displayName,
            entry.entryKind,
            entry.sourceGroup,
            entry.commandOrHandler,
            registryTargetPathText(
                entry.rootLabel,
                entry.subKeyPath,
                entry.deleteKind == DeleteKind::RegistryValue,
                entry.valueName),
            entry.statusText,
            entry.detailText,
            entry.clsidText }.join('\n').toLower();
        if (!filterText.isEmpty() && !searchableText.contains(filterText))
        {
            continue;
        }

        const int row = visibleCount++;
        areaWidgets->table->insertRow(row);

        const auto makeItem = [entryIndex](const QString& text) -> QTableWidgetItem*
        {
            QTableWidgetItem* item = new QTableWidgetItem(text);
            item->setData(Qt::UserRole, entryIndex);
            item->setToolTip(text);
            return item;
        };

        areaWidgets->table->setItem(row, kColumnName, makeItem(entry.itemName));
        areaWidgets->table->setItem(row, kColumnDisplayName, makeItem(entry.displayName));
        areaWidgets->table->setItem(row, kColumnKind, makeItem(entry.entryKind));
        areaWidgets->table->setItem(row, kColumnSource, makeItem(entry.sourceGroup));
        areaWidgets->table->setItem(row, kColumnCommandOrHandler, makeItem(entry.commandOrHandler));
        areaWidgets->table->setItem(
            row,
            kColumnRegistryPath,
            makeItem(registryTargetPathText(
                entry.rootLabel,
                entry.subKeyPath,
                entry.deleteKind == DeleteKind::RegistryValue,
                entry.valueName)));
        areaWidgets->table->setItem(row, kColumnStatus, makeItem(entry.statusText));
        areaWidgets->table->setItem(row, kColumnDetail, makeItem(entry.detailText));
    }

    areaWidgets->table->setSortingEnabled(true);
    if (areaWidgets->statusLabel != nullptr)
    {
        areaWidgets->statusLabel->setText(QStringLiteral("%1：共枚举 %2 项，当前显示 %3 项。")
            .arg(areaTitle(area))
            .arg(areaWidgets->entries.size())
            .arg(visibleCount));
    }
}

void ContextMenuCleanerTab::showAreaContextMenu(const MenuArea area, const QPoint& localPosition)
{
    AreaWidgets* areaWidgets = widgetsForArea(area);
    if (areaWidgets == nullptr || areaWidgets->table == nullptr)
    {
        return;
    }

    QMenu menu(areaWidgets->table);
    menu.setStyleSheet(KswordTheme::ContextMenuStyle());
    QAction* copyAction = menu.addAction(QIcon(QStringLiteral(":/Icon/log_copy.svg")), QStringLiteral("复制注册表路径"));
    QAction* deleteAction = menu.addAction(QIcon(QStringLiteral(":/Icon/process_terminate.svg")), QStringLiteral("删除选中项"));

    const QVector<int> selectedIndexes = selectedEntryIndexes(area);
    bool hasDeleteableEntry = false;
    for (const int entryIndex : selectedIndexes)
    {
        if (entryIndex >= 0
            && entryIndex < areaWidgets->entries.size()
            && areaWidgets->entries.at(entryIndex).canDelete)
        {
            hasDeleteableEntry = true;
            break;
        }
    }
    copyAction->setEnabled(!selectedIndexes.isEmpty());
    deleteAction->setEnabled(hasDeleteableEntry);

    QAction* selectedAction = menu.exec(areaWidgets->table->viewport()->mapToGlobal(localPosition));
    if (selectedAction == copyAction)
    {
        copySelectedEntries(area);
    }
    else if (selectedAction == deleteAction)
    {
        deleteSelectedEntries(area);
    }
}

void ContextMenuCleanerTab::deleteSelectedEntries(const MenuArea area)
{
    AreaWidgets* areaWidgets = widgetsForArea(area);
    if (areaWidgets == nullptr)
    {
        return;
    }

    const QVector<int> selectedIndexes = selectedEntryIndexes(area);
    if (selectedIndexes.isEmpty())
    {
        QMessageBox::information(this, QStringLiteral("Shell 关联管理"), QStringLiteral("请先选择需要删除的注册表项目。"));
        return;
    }

    QStringList targetPaths;
    QVector<int> deleteableIndexes;
    int machineScopeTargetCount = 0;
    for (const int entryIndex : selectedIndexes)
    {
        if (entryIndex < 0 || entryIndex >= areaWidgets->entries.size())
        {
            continue;
        }
        const ContextMenuEntry& entry = areaWidgets->entries.at(entryIndex);
        if (!entry.canDelete
            || (area == MenuArea::UrlBinding && !isUrlBindingDeletionAllowed(entry)))
        {
            continue;
        }
        deleteableIndexes.push_back(entryIndex);
        if (entry.rootKey == HKEY_LOCAL_MACHINE)
        {
            ++machineScopeTargetCount;
        }
        targetPaths.push_back(registryTargetPathText(
            entry.rootLabel,
            entry.subKeyPath,
            entry.deleteKind == DeleteKind::RegistryValue,
            entry.valueName));
    }
    if (deleteableIndexes.isEmpty())
    {
        QMessageBox::information(
            this,
            QStringLiteral("Shell 关联管理"),
            QStringLiteral("选中项属于受保护的系统注册，当前页面不允许删除。"));
        return;
    }

    const QString previewText = targetPaths.mid(0, 8).join('\n');
    const QString moreText = targetPaths.size() > 8
        ? QStringLiteral("\n... 另有 %1 项").arg(targetPaths.size() - 8)
        : QString();
    const QString machineScopeWarning = machineScopeTargetCount > 0
        ? QStringLiteral("\n\n高风险警告：其中 %1 项位于 HKLM，修改会影响所有用户，错误删除可能使协议、应用入口或系统功能失效。KSword 不限制此操作，但只应在确认目标属于第三方软件时继续；恢复 HKLM 备份需要管理员权限。")
            .arg(machineScopeTargetCount)
        : QString();
    const QString confirmationText = area == MenuArea::UrlBinding
        ? QStringLiteral("将删除 %1 个 URL 绑定注册表子树。删除前会自动备份，可通过“恢复上次删除”还原。%2\n\n%3%4")
            .arg(targetPaths.size())
            .arg(machineScopeWarning)
            .arg(previewText)
            .arg(moreText)
        : QStringLiteral("将删除 %1 个注册表子树或值。此操作不会自动备份，删除后通常需要重启 Explorer 或相关程序才会完全生效。\n\n%2%3")
            .arg(targetPaths.size())
            .arg(previewText)
            .arg(moreText);
    const QMessageBox::StandardButton confirmButton = QMessageBox::warning(
        this,
        QStringLiteral("确认删除注册表项目"),
        confirmationText,
        QMessageBox::Yes | QMessageBox::No,
        QMessageBox::No);
    if (confirmButton != QMessageBox::Yes)
    {
        return;
    }

    if (area == MenuArea::UrlBinding)
    {
        QString backupError;
        if (!createUrlBindingBackup(deleteableIndexes, &backupError))
        {
            QMessageBox::critical(
                this,
                QStringLiteral("URL 绑定备份失败"),
                QStringLiteral("删除已取消，因为无法建立可恢复备份：\n\n%1").arg(backupError));
            return;
        }
    }

    QStringList failedMessages;
    int successCount = 0;
    for (const int entryIndex : deleteableIndexes)
    {
        if (entryIndex < 0 || entryIndex >= areaWidgets->entries.size())
        {
            continue;
        }
        const ContextMenuEntry& entry = areaWidgets->entries.at(entryIndex);
        if (area == MenuArea::UrlBinding && !isUrlBindingDeletionAllowed(entry))
        {
            failedMessages.push_back(QStringLiteral("%1：执行时安全校验拒绝删除")
                .arg(registryTargetPathText(
                    entry.rootLabel,
                    entry.subKeyPath,
                    entry.deleteKind == DeleteKind::RegistryValue,
                    entry.valueName)));
            continue;
        }
        QString errorText;
        const bool deleteOk = entry.deleteKind == DeleteKind::RegistryValue
            ? deleteRegistryValueWithView(
                entry.rootKey,
                entry.subKeyPath,
                entry.valueName,
                entry.viewFlag,
                entry.cleanupOpenWithMru,
                &errorText)
            : deleteRegistryTreeWithView(
                entry.rootKey,
                entry.subKeyPath,
                entry.viewFlag,
                &errorText);
        const QString targetPath = registryTargetPathText(
            entry.rootLabel,
            entry.subKeyPath,
            entry.deleteKind == DeleteKind::RegistryValue,
            entry.valueName);
        if (deleteOk)
        {
            ++successCount;
            kLogEvent event;
            warn << event
                << "[ContextMenuCleanerTab] 删除 Shell 关联注册表项目成功, path="
                << targetPath.toStdString()
                << eol;
        }
        else
        {
            (void)ks::ui::promptForPrivilegeFailure(
                this,
                QStringLiteral("清理 Shell 关联注册表项目"),
                errorText);
            failedMessages.push_back(QStringLiteral("%1：%2")
                .arg(targetPath, errorText));
            kLogEvent event;
            err << event
                << "[ContextMenuCleanerTab] 删除 Shell 关联注册表项目失败, path="
                << targetPath.toStdString()
                << ", error="
                << errorText.toStdString()
                << eol;
        }
    }

    refreshArea(area);

    if (failedMessages.isEmpty())
    {
        QMessageBox::information(
            this,
            QStringLiteral("Shell 关联管理"),
            QStringLiteral("已删除 %1 项。建议重启 Explorer 或相关程序后确认变化。").arg(successCount));
    }
    else
    {
        QMessageBox::warning(
            this,
            QStringLiteral("Shell 关联管理"),
            QStringLiteral("成功删除 %1 项，失败 %2 项：\n\n%3")
                .arg(successCount)
                .arg(failedMessages.size())
                .arg(failedMessages.join('\n')));
    }
}

void ContextMenuCleanerTab::copySelectedEntries(const MenuArea area) const
{
    const AreaWidgets* areaWidgets = widgetsForArea(area);
    if (areaWidgets == nullptr)
    {
        return;
    }

    const QVector<int> selectedIndexes = selectedEntryIndexes(area);
    if (selectedIndexes.isEmpty())
    {
        QMessageBox::information(const_cast<ContextMenuCleanerTab*>(this), QStringLiteral("复制注册表路径"), QStringLiteral("请先选择需要复制的行。"));
        return;
    }

    QStringList lines;
    for (const int entryIndex : selectedIndexes)
    {
        if (entryIndex < 0 || entryIndex >= areaWidgets->entries.size())
        {
            continue;
        }
        const ContextMenuEntry& entry = areaWidgets->entries.at(entryIndex);
        lines.push_back(registryTargetPathText(
            entry.rootLabel,
            entry.subKeyPath,
            entry.deleteKind == DeleteKind::RegistryValue,
            entry.valueName));
    }

    if (QClipboard* clipboard = QApplication::clipboard())
    {
        clipboard->setText(lines.join('\n'));
    }
}


QVector<int> ContextMenuCleanerTab::selectedEntryIndexes(const MenuArea area) const
{
    const AreaWidgets* areaWidgets = widgetsForArea(area);
    QVector<int> indexes;
    if (areaWidgets == nullptr || areaWidgets->table == nullptr || areaWidgets->table->selectionModel() == nullptr)
    {
        return indexes;
    }

    const QModelIndexList selectedRows = areaWidgets->table->selectionModel()->selectedRows();
    for (const QModelIndex& modelIndex : selectedRows)
    {
        const QTableWidgetItem* item = areaWidgets->table->item(modelIndex.row(), kColumnName);
        if (item == nullptr)
        {
            continue;
        }
        const int entryIndex = item->data(Qt::UserRole).toInt();
        if (!indexes.contains(entryIndex))
        {
            indexes.push_back(entryIndex);
        }
    }
    return indexes;
}

ContextMenuCleanerTab::AreaWidgets* ContextMenuCleanerTab::widgetsForArea(const MenuArea area)
{
    switch (area)
    {
    case MenuArea::InternetExplorer:
        return &m_ieWidgets;
    case MenuArea::Desktop:
        return &m_desktopWidgets;
    case MenuArea::File:
        return &m_fileWidgets;
    case MenuArea::UrlBinding:
        return &m_urlBindingWidgets;
    case MenuArea::OpenWith:
        return &m_openWithWidgets;
    case MenuArea::FormatMenu:
        return &m_formatMenuWidgets;
    case MenuArea::ExplorerHome:
        return &m_explorerHomeWidgets;
    }
    return &m_fileWidgets;
}

const ContextMenuCleanerTab::AreaWidgets* ContextMenuCleanerTab::widgetsForArea(const MenuArea area) const
{
    switch (area)
    {
    case MenuArea::InternetExplorer:
        return &m_ieWidgets;
    case MenuArea::Desktop:
        return &m_desktopWidgets;
    case MenuArea::File:
        return &m_fileWidgets;
    case MenuArea::UrlBinding:
        return &m_urlBindingWidgets;
    case MenuArea::OpenWith:
        return &m_openWithWidgets;
    case MenuArea::FormatMenu:
        return &m_formatMenuWidgets;
    case MenuArea::ExplorerHome:
        return &m_explorerHomeWidgets;
    }
    return &m_fileWidgets;
}

QString ContextMenuCleanerTab::areaTitle(const MenuArea area)
{
    switch (area)
    {
    case MenuArea::InternetExplorer:
        return QStringLiteral("IE右键菜单");
    case MenuArea::Desktop:
        return QStringLiteral("桌面右键菜单");
    case MenuArea::File:
        return QStringLiteral("文件右键菜单");
    case MenuArea::UrlBinding:
        return QStringLiteral("URL 绑定");
    case MenuArea::OpenWith:
        return QStringLiteral("文件打开方式");
    case MenuArea::FormatMenu:
        return QStringLiteral("格式右键菜单");
    case MenuArea::ExplorerHome:
        return QStringLiteral("资源管理器主页第三方程序");
    }
    return QStringLiteral("文件右键菜单");
}

QString ContextMenuCleanerTab::areaIconPath(const MenuArea area)
{
    switch (area)
    {
    case MenuArea::InternetExplorer:
        return QStringLiteral(":/Icon/process_list.svg");
    case MenuArea::Desktop:
        return QStringLiteral(":/Icon/desktop_switch.svg");
    case MenuArea::File:
        return QStringLiteral(":/Icon/process_open_folder.svg");
    case MenuArea::UrlBinding:
        return QStringLiteral(":/Icon/log_track.svg");
    case MenuArea::OpenWith:
        return QStringLiteral(":/Icon/process_open_folder.svg");
    case MenuArea::FormatMenu:
        return QStringLiteral(":/Icon/process_list.svg");
    case MenuArea::ExplorerHome:
        return QStringLiteral(":/Icon/desktop_switch.svg");
    }
    return QStringLiteral(":/Icon/process_open_folder.svg");
}

} // namespace ks::misc
