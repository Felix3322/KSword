#include "StartupDock.Internal.h"
#include "../OnlineScan/SandboxUploadActions.h"
#include "../Framework/PrivilegeElevationPrompt.h"

#include <QMetaObject>

#include <winsvc.h>

#pragma comment(lib, "Advapi32.lib")

using namespace startup_dock_detail;

namespace
{
    // splitRegistryLocation 作用：
    // - 把 "HKLM\\..." 形式位置拆成根键与子键。
    bool splitRegistryLocation(const QString& locationText, HKEY* rootKeyOut, QString* subKeyOut)
    {
        if (rootKeyOut == nullptr || subKeyOut == nullptr)
        {
            return false;
        }

        const int slashIndex = locationText.indexOf('\\');
        if (slashIndex <= 0)
        {
            return false;
        }

        const QString rootKeyText = locationText.left(slashIndex).trimmed().toUpper();
        *subKeyOut = locationText.mid(slashIndex + 1).trimmed();
        if (rootKeyText == QStringLiteral("HKCU"))
        {
            *rootKeyOut = HKEY_CURRENT_USER;
            return true;
        }
        if (rootKeyText == QStringLiteral("HKLM"))
        {
            *rootKeyOut = HKEY_LOCAL_MACHINE;
            return true;
        }
        if (rootKeyText == QStringLiteral("HKCR"))
        {
            *rootKeyOut = HKEY_CLASSES_ROOT;
            return true;
        }
        return false;
    }

    // deleteRegistryValueByPath 作用：
    // - 删除指定注册表值。
    bool deleteRegistryValueByPath(HKEY rootKey, const QString& subKeyText, const QString& valueNameText, QString* errorTextOut)
    {
        HKEY openedKey = nullptr;
        const LONG openResult = ::RegOpenKeyExW(
            rootKey,
            reinterpret_cast<LPCWSTR>(subKeyText.utf16()),
            0,
            KEY_SET_VALUE,
            &openedKey);
        if (openResult != ERROR_SUCCESS || openedKey == nullptr)
        {
            if (errorTextOut != nullptr)
            {
                *errorTextOut = winErrorText(static_cast<DWORD>(openResult));
            }
            return false;
        }

        const LONG deleteResult = ::RegDeleteValueW(
            openedKey,
            valueNameText.trimmed().isEmpty() ? nullptr : reinterpret_cast<LPCWSTR>(valueNameText.utf16()));
        ::RegCloseKey(openedKey);
        if (deleteResult != ERROR_SUCCESS)
        {
            if (errorTextOut != nullptr)
            {
                *errorTextOut = winErrorText(static_cast<DWORD>(deleteResult));
            }
            return false;
        }
        return true;
    }

    // deleteRegistryTreeByPath 作用：
    // - 删除指定注册表子树。
    bool deleteRegistryTreeByPath(HKEY rootKey, const QString& subKeyText, QString* errorTextOut)
    {
        const LONG deleteResult = ::RegDeleteTreeW(
            rootKey,
            reinterpret_cast<LPCWSTR>(subKeyText.utf16()));
        if (deleteResult != ERROR_SUCCESS)
        {
            if (errorTextOut != nullptr)
            {
                *errorTextOut = winErrorText(static_cast<DWORD>(deleteResult));
            }
            return false;
        }
        return true;
    }

    // deleteScmObjectByName 作用：
    // - 删除服务或驱动服务注册项。
    bool deleteScmObjectByName(const QString& serviceNameText, QString* errorTextOut)
    {
        SC_HANDLE scmHandle = ::OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
        if (scmHandle == nullptr)
        {
            if (errorTextOut != nullptr)
            {
                *errorTextOut = winErrorText(::GetLastError());
            }
            return false;
        }

        SC_HANDLE serviceHandle = ::OpenServiceW(
            scmHandle,
            reinterpret_cast<LPCWSTR>(serviceNameText.utf16()),
            DELETE);
        if (serviceHandle == nullptr)
        {
            if (errorTextOut != nullptr)
            {
                *errorTextOut = winErrorText(::GetLastError());
            }
            ::CloseServiceHandle(scmHandle);
            return false;
        }

        const BOOL deleteOk = ::DeleteService(serviceHandle);
        if (deleteOk == FALSE && errorTextOut != nullptr)
        {
            *errorTextOut = winErrorText(::GetLastError());
        }
        ::CloseServiceHandle(serviceHandle);
        ::CloseServiceHandle(scmHandle);
        return deleteOk != FALSE;
    }

    QString startupToggleActionText(const bool enabled)
    {
        return enabled
            ? startupText("startup.menu.enable", QStringLiteral("启用"))
            : startupText("startup.menu.disable", QStringLiteral("禁用"));
    }

    QString startupToggleImpactText(
        const ks::startup::StartupActionKind actionKind,
        const bool enabled)
    {
        switch (actionKind)
        {
        case ks::startup::StartupActionKind::RegistryRunValue:
            return enabled
                ? startupText(
                    "startup.dialog.toggle.impact.registry.enable",
                    QStringLiteral("将已停放的 Run 注册表值恢复到原位置；若原位置已被占用，不会覆盖现有值。"))
                : startupText(
                    "startup.dialog.toggle.impact.registry.disable",
                    QStringLiteral("将 Run 注册表值移入 KSword 的可恢复备份；原值数据会保留，便于重新启用。"));
        case ks::startup::StartupActionKind::StartupFolderFile:
            return enabled
                ? startupText(
                    "startup.dialog.toggle.impact.startup_folder.enable",
                    QStringLiteral("将启动文件从 KSword 专用停放位置移回“启动”文件夹；若目标路径已存在，不会覆盖现有文件。"))
                : startupText(
                    "startup.dialog.toggle.impact.startup_folder.disable",
                    QStringLiteral("将启动文件移到 KSword 专用停放位置；文件内容会保留，之后可以重新启用。"));
        case ks::startup::StartupActionKind::ScheduledTask:
            return enabled
                ? startupText(
                    "startup.dialog.toggle.impact.task.enable",
                    QStringLiteral("重新启用计划任务，并保留其现有触发器与操作配置。"))
                : startupText(
                    "startup.dialog.toggle.impact.task.disable",
                    QStringLiteral("禁用计划任务，但保留任务定义、触发器与操作配置，之后可以重新启用。"));
        case ks::startup::StartupActionKind::None:
        default:
            return enabled
                ? startupText(
                    "startup.dialog.toggle.impact.generic.enable",
                    QStringLiteral("后端将使用已保存的结构化定位信息恢复该启动项。"))
                : startupText(
                    "startup.dialog.toggle.impact.generic.disable",
                    QStringLiteral("后端将保留恢复信息并以可逆方式禁用该启动项。"));
        }
    }

    QString startupActionStatusText(const ks::startup::StartupActionStatus status)
    {
        switch (status)
        {
        case ks::startup::StartupActionStatus::Success:
            return startupText("startup.dialog.toggle.status.success", QStringLiteral("成功"));
        case ks::startup::StartupActionStatus::NoChange:
            return startupText("startup.dialog.toggle.status.no_change", QStringLiteral("状态未变化"));
        case ks::startup::StartupActionStatus::InvalidEntry:
            return startupText("startup.dialog.toggle.status.invalid_entry", QStringLiteral("条目无效"));
        case ks::startup::StartupActionStatus::NotSupported:
            return startupText("startup.dialog.toggle.status.not_supported", QStringLiteral("来源类型不受支持"));
        case ks::startup::StartupActionStatus::ProtectedEntry:
            return startupText("startup.dialog.toggle.status.protected", QStringLiteral("条目受保护"));
        case ks::startup::StartupActionStatus::Conflict:
            return startupText("startup.dialog.toggle.status.conflict", QStringLiteral("目标位置存在冲突"));
        case ks::startup::StartupActionStatus::NotFound:
            return startupText("startup.dialog.toggle.status.not_found", QStringLiteral("来源或备份不存在"));
        case ks::startup::StartupActionStatus::AccessDenied:
            return startupText("startup.dialog.toggle.status.access_denied", QStringLiteral("权限不足"));
        case ks::startup::StartupActionStatus::WriteFailed:
            return startupText("startup.dialog.toggle.status.write_failed", QStringLiteral("写入失败"));
        case ks::startup::StartupActionStatus::VerificationFailed:
            return startupText("startup.dialog.toggle.status.verification_failed", QStringLiteral("操作后验证失败"));
        case ks::startup::StartupActionStatus::RollbackFailed:
            return startupText("startup.dialog.toggle.status.rollback_failed", QStringLiteral("回滚失败"));
        case ks::startup::StartupActionStatus::ProcessFailed:
            return startupText("startup.dialog.toggle.status.process_failed", QStringLiteral("系统命令执行失败"));
        default:
            return startupText("startup.dialog.toggle.status.unknown", QStringLiteral("未知错误"));
        }
    }

    QString startupActionFailureText(const ks::startup::ActionResult& actionResult)
    {
        const QString backendMessageText = QString::fromUtf8(
            actionResult.messageText.c_str(),
            static_cast<qsizetype>(actionResult.messageText.size())).trimmed();
        const QString messageText = backendMessageText.isEmpty()
            ? backendMessageText
            : ks::i18n::sourceText(backendMessageText);
        QString detailText = startupText(
            "startup.dialog.toggle.failed.details",
            QStringLiteral("状态：%1\n详细信息：%2"))
            .arg(startupActionStatusText(actionResult.status))
            .arg(messageText.isEmpty()
                ? startupText(
                    "startup.dialog.toggle.failed.no_details",
                    QStringLiteral("后端未提供附加错误信息。"))
                : messageText);

        if (actionResult.errorCode != ERROR_SUCCESS)
        {
            detailText += QStringLiteral("\n");
            detailText += startupText(
                "startup.dialog.toggle.failed.win32",
                QStringLiteral("Win32 错误：%1"))
                .arg(winErrorText(actionResult.errorCode));
        }

        if (actionResult.rollbackAttempted)
        {
            detailText += QStringLiteral("\n");
            detailText += actionResult.rollbackSucceeded
                ? startupText(
                    "startup.dialog.toggle.rollback.succeeded",
                    QStringLiteral("安全回滚：已成功恢复操作前状态。"))
                : startupText(
                    "startup.dialog.toggle.rollback.failed",
                    QStringLiteral("安全回滚：失败，请在刷新后核对启动项和备份状态。"));
        }
        return detailText;
    }

    bool isStartupPrivilegeFailure(const ks::startup::ActionResult& actionResult)
    {
        return actionResult.status == ks::startup::StartupActionStatus::AccessDenied
            || actionResult.errorCode == ERROR_ACCESS_DENIED
            || actionResult.errorCode == ERROR_PRIVILEGE_NOT_HELD
            || actionResult.errorCode == ERROR_ELEVATION_REQUIRED;
    }

    QString startupTsvField(QString fieldText)
    {
        // 用可见控制字符替代 TSV 的行/列分隔符，确保一条启动项恒定占一行。
        fieldText.replace(QChar('\t'), QStringLiteral("␉"));
        fieldText.replace(QChar('\r'), QStringLiteral("␍"));
        fieldText.replace(QChar('\n'), QStringLiteral("␊"));
        return fieldText;
    }

    QString startupEntryTsvRow(const StartupDock::StartupEntry& entry)
    {
        QStringList fieldList{
            entry.itemNameText,
            entry.publisherText,
            entry.imagePathText,
            entry.commandText,
            entry.locationText,
            ks::i18n::sourceText(entry.userText),
            buildStatusText(entry.enabled),
            ks::i18n::sourceText(entry.sourceTypeText),
            startupLocalizedDetailText(entry.detailText)
        };
        for (QString& fieldText : fieldList)
        {
            fieldText = startupTsvField(fieldText);
        }
        return fieldList.join(QChar('\t'));
    }

    class StartupActionFlagReset final
    {
    public:
        explicit StartupActionFlagReset(std::atomic_bool& actionFlag)
            : m_actionFlag(&actionFlag)
        {
        }

        ~StartupActionFlagReset()
        {
            if (m_actionFlag != nullptr)
            {
                m_actionFlag->store(false);
            }
        }

        StartupActionFlagReset(const StartupActionFlagReset&) = delete;
        StartupActionFlagReset& operator=(const StartupActionFlagReset&) = delete;

        void dismiss()
        {
            m_actionFlag = nullptr;
        }

    private:
        std::atomic_bool* m_actionFlag;
    };

}

void StartupDock::initializeConnections()
{
    connect(m_refreshButton, &QPushButton::clicked, this, [this]()
        {
            requestAsyncRefresh(true);
        });
    connect(m_exportButton, &QPushButton::clicked, this, [this]()
        {
            exportCurrentView();
        });
    connect(m_copyButton, &QPushButton::clicked, this, [this]()
        {
            copySelectedRow(currentCategory(), currentCategoryTable());
        });
    connect(m_filterEdit, &QLineEdit::textChanged, this, [this](const QString&)
        {
            applyFilterAndRefresh();
        });
    connect(m_hideMicrosoftCheck, &QCheckBox::toggled, this, [this](const bool)
        {
            applyFilterAndRefresh();
        });
    connect(m_hideEmptyPathCheck, &QCheckBox::toggled, this, [this](const bool)
        {
            applyFilterAndRefresh();
        });

    const auto bindTableContextMenu =
        [this](const StartupCategory category, QTableWidget* tableWidget)
        {
            if (tableWidget == nullptr)
            {
                return;
            }
            connect(tableWidget, &QWidget::customContextMenuRequested, this, [this, category, tableWidget](const QPoint& localPos)
                {
                    showEntryContextMenu(category, tableWidget, localPos);
                });
            connect(tableWidget, &QTableWidget::cellDoubleClicked, this, [this, category, tableWidget](const int row, const int /*column*/)
                {
                    if (row < 0)
                    {
                        return;
                    }
                    openSelectedFileLocation(category, tableWidget);
                });
        };

    bindTableContextMenu(StartupCategory::All, m_allTable);
    bindTableContextMenu(StartupCategory::Logon, m_logonTable);
    bindTableContextMenu(StartupCategory::Services, m_servicesTable);
    bindTableContextMenu(StartupCategory::Drivers, m_driversTable);
    bindTableContextMenu(StartupCategory::Tasks, m_tasksTable);
    bindTableContextMenu(StartupCategory::Wmi, m_wmiTable);

    if (m_registryTree != nullptr)
    {
        connect(m_registryTree, &QWidget::customContextMenuRequested, this, [this](const QPoint& localPos)
            {
                showRegistryContextMenu(localPos);
            });
        connect(m_registryTree, &QTreeWidget::itemDoubleClicked, this, [this](QTreeWidgetItem* treeItem, int)
            {
                if (treeItem == nullptr)
                {
                    return;
                }

                const StartupTreeNodeKind nodeKind = static_cast<StartupTreeNodeKind>(
                    treeItem->data(0, kStartupTreeNodeKindRole).toInt());
                if (nodeKind == StartupTreeNodeKind::Entry)
                {
                    openSelectedFileLocation(StartupCategory::Registry, nullptr);
                }
                else if (nodeKind == StartupTreeNodeKind::Group
                    || nodeKind == StartupTreeNodeKind::Placeholder)
                {
                    openSelectedRegistryLocation(StartupCategory::Registry, nullptr);
                }
            });
    }
}

void StartupDock::refreshAllStartupEntries()
{
    requestAsyncRefresh(true);
}

void StartupDock::showEntryContextMenu(
    const StartupCategory category,
    QTableWidget* tableWidget,
    const QPoint& localPos)
{
    if (tableWidget == nullptr)
    {
        return;
    }

    QTableWidgetItem* clickedItem = tableWidget->itemAt(localPos);
    if (clickedItem == nullptr)
    {
        return;
    }
    tableWidget->setCurrentItem(clickedItem);

    const int entryIndex = findEntryIndexByTableRow(category, clickedItem->row());
    if (entryIndex < 0 || entryIndex >= static_cast<int>(m_entryList.size()))
    {
        return;
    }

    const StartupEntry entry = m_entryList[static_cast<std::size_t>(entryIndex)];
    QMenu contextMenu(this);
    // 显式填充菜单背景，避免浅色模式下继承透明样式出现黑底。
    contextMenu.setStyleSheet(KswordTheme::ContextMenuStyle());
    QAction* detailAction = contextMenu.addAction(
        createBlueIcon(":/Icon/process_details.svg"),
        startupText("startup.menu.entry_details", QStringLiteral("查看启动项详细信息")));
    QAction* copyAction = contextMenu.addAction(
        createBlueIcon(":/Icon/log_copy.svg"),
        startupText("startup.menu.copy_row", QStringLiteral("复制整行")));
    QAction* openFileAction = contextMenu.addAction(
        createBlueIcon(":/Icon/process_open_folder.svg"),
        startupText("startup.menu.open_file", QStringLiteral("打开文件位置")));
    QAction* filePropertiesAction = contextMenu.addAction(
        createBlueIcon(":/Icon/process_details.svg"),
        startupText("startup.menu.file_properties", QStringLiteral("转到文件属性")));
    QAction* openRegistryAction = contextMenu.addAction(
        createBlueIcon(":/Icon/file_find.svg"),
        startupText("startup.menu.open_registry", QStringLiteral("打开注册表位置")));
    QAction* gotoServiceAction = contextMenu.addAction(
        createBlueIcon(":/Icon/process_list.svg"),
        startupText("startup.menu.goto_service", QStringLiteral("转到服务管理")));
    QAction* uploadVirusTotalAction = ks::online_scan::addVirusTotalSandboxMenu(
        &contextMenu,
        this,
        [entry]() -> ks::online_scan::SandboxUploadTarget
        {
            // 输入：启动项缓存行。
            // 处理：把镜像路径或命令行交给统一路径提取器。
            // 返回：待上传路径和来源说明。
            ks::online_scan::SandboxUploadTarget uploadTarget;
            uploadTarget.filePath = entry.imagePathText;
            uploadTarget.sourceText = startupText(
                "startup.source.autostart",
                QStringLiteral("自启动项 %1"))
                .arg(entry.itemNameText);
            return uploadTarget;
        });
    contextMenu.addSeparator();
    const bool targetEnabled = !entry.enabled;
    QAction* toggleAction = contextMenu.addAction(
        createBlueIcon(targetEnabled ? ":/Icon/process_start.svg" : ":/Icon/process_pause.svg"),
        startupToggleActionText(targetEnabled));
    QAction* protectedReasonAction = nullptr;
    if (entry.backendEntry.isProtected)
    {
        protectedReasonAction = contextMenu.addAction(
            createBlueIcon(":/Icon/process_details.svg"),
            startupText(
                "startup.menu.protected_reason",
                QStringLiteral("受保护：%1"))
                .arg(startupRiskReasonText(entry.backendEntry)));
        protectedReasonAction->setEnabled(false);
    }
    QAction* deleteAction = contextMenu.addAction(
        createBlueIcon(":/Icon/log_clear.svg"),
        startupText("startup.menu.delete", QStringLiteral("删除项")));
    openFileAction->setEnabled(entry.canOpenFileLocation);
    filePropertiesAction->setEnabled(entry.canOpenFileLocation);
    if (uploadVirusTotalAction != nullptr)
    {
        uploadVirusTotalAction->setEnabled(entry.canOpenFileLocation && !entry.imagePathText.trimmed().isEmpty());
    }
    openRegistryAction->setEnabled(entry.canOpenRegistryLocation);
    gotoServiceAction->setEnabled(
        entry.category == StartupCategory::Services
        || entry.sourceTypeText == QStringLiteral("AutoService"));
    const bool toggleSupported = targetEnabled
        ? entry.backendEntry.canEnable
        : entry.backendEntry.canDisable;
    toggleAction->setEnabled(
        toggleSupported
        && !entry.backendEntry.isProtected
        && !m_startupActionInProgress.load());
    deleteAction->setEnabled(
        entry.canDelete
        && !entry.backendEntry.isProtected
        && !m_startupActionInProgress.load());

    QAction* selectedAction = contextMenu.exec(tableWidget->viewport()->mapToGlobal(localPos));
    if (selectedAction == detailAction)
    {
        showSelectedEntryDetails(category, tableWidget);
    }
    else if (selectedAction == copyAction)
    {
        copySelectedRow(category, tableWidget);
    }
    else if (selectedAction == openFileAction)
    {
        openSelectedFileLocation(category, tableWidget);
    }
    else if (selectedAction == filePropertiesAction)
    {
        openSelectedFileProperties(category, tableWidget);
    }
    else if (selectedAction == openRegistryAction)
    {
        openSelectedRegistryLocation(category, tableWidget);
    }
    else if (selectedAction == gotoServiceAction)
    {
        QString serviceNameText;
        if (entry.uniqueIdText.startsWith(QStringLiteral("SERVICE|"), Qt::CaseInsensitive))
        {
            serviceNameText = entry.uniqueIdText.mid(QStringLiteral("SERVICE|").size()).trimmed();
        }
        if (serviceNameText.isEmpty())
        {
            const int lastSlashIndex = entry.locationText.lastIndexOf('\\');
            serviceNameText = (lastSlashIndex >= 0)
                ? entry.locationText.mid(lastSlashIndex + 1).trimmed()
                : entry.itemNameText.trimmed();
        }

        QWidget* mainWindowWidget = window();
        if (mainWindowWidget != nullptr && !serviceNameText.isEmpty())
        {
            QMetaObject::invokeMethod(
                mainWindowWidget,
                "focusServiceDockByName",
                Qt::QueuedConnection,
                Q_ARG(QString, serviceNameText));
        }
    }
    else if (selectedAction == uploadVirusTotalAction)
    {
        return;
    }
    else if (selectedAction == toggleAction)
    {
        setStartupEntryEnabled(entry, targetEnabled);
    }
    else if (selectedAction == deleteAction)
    {
        deleteStartupEntry(entry);
    }
}

void StartupDock::showRegistryContextMenu(const QPoint& localPos)
{
    if (m_registryTree == nullptr)
    {
        return;
    }

    QTreeWidgetItem* treeItem = m_registryTree->itemAt(localPos);
    if (treeItem == nullptr)
    {
        return;
    }

    m_registryTree->setCurrentItem(treeItem);

    const StartupTreeNodeKind nodeKind = static_cast<StartupTreeNodeKind>(
        treeItem->data(0, kStartupTreeNodeKindRole).toInt());
    const int entryIndex = findEntryIndexByRegistryTreeItem(treeItem);
    const QString locationText = treeItem->data(0, kStartupTreeLocationRole).toString().trimmed();

    QMenu contextMenu(this);
    // 显式填充菜单背景，避免浅色模式下继承透明样式出现黑底。
    contextMenu.setStyleSheet(KswordTheme::ContextMenuStyle());
    QAction* detailAction = contextMenu.addAction(
        createBlueIcon(":/Icon/process_details.svg"),
        startupText("startup.menu.entry_details", QStringLiteral("查看启动项详细信息")));
    QAction* copyAction = contextMenu.addAction(
        createBlueIcon(":/Icon/log_copy.svg"),
        startupText("startup.menu.copy", QStringLiteral("复制")));
    QAction* openFileAction = contextMenu.addAction(
        createBlueIcon(":/Icon/process_open_folder.svg"),
        startupText("startup.menu.open_file", QStringLiteral("打开文件位置")));
    QAction* filePropertiesAction = contextMenu.addAction(
        createBlueIcon(":/Icon/process_details.svg"),
        startupText("startup.menu.file_properties", QStringLiteral("转到文件属性")));
    QAction* openRegistryAction = contextMenu.addAction(
        createBlueIcon(":/Icon/file_find.svg"),
        startupText("startup.menu.open_registry", QStringLiteral("打开注册表位置")));
    const bool hasRegistryEntry =
        entryIndex >= 0 && entryIndex < static_cast<int>(m_entryList.size());
    const StartupEntry registryEntry = hasRegistryEntry
        ? m_entryList[static_cast<std::size_t>(entryIndex)]
        : StartupEntry{};
    QAction* uploadVirusTotalAction = ks::online_scan::addVirusTotalSandboxMenu(
        &contextMenu,
        this,
        [hasRegistryEntry, registryEntry]() -> ks::online_scan::SandboxUploadTarget
        {
            // 输入：高级注册表树当前叶子条目。
            // 处理：只有叶子条目才从 imagePathText 提取上传文件。
            // 返回：待上传路径和来源说明。
            ks::online_scan::SandboxUploadTarget uploadTarget;
            if (!hasRegistryEntry)
            {
                uploadTarget.errorText = startupText(
                    "startup.upload.error.invalid_node",
                    QStringLiteral("当前注册表节点不是可上传的启动项。"));
                return uploadTarget;
            }
            uploadTarget.filePath = registryEntry.imagePathText;
            uploadTarget.sourceText = startupText(
                "startup.source.autostart_registry",
                QStringLiteral("自启动注册表项 %1"))
                .arg(registryEntry.itemNameText);
            return uploadTarget;
        });
    contextMenu.addSeparator();
    const bool targetEnabled = !hasRegistryEntry || !registryEntry.enabled;
    QAction* toggleAction = contextMenu.addAction(
        createBlueIcon(targetEnabled ? ":/Icon/process_start.svg" : ":/Icon/process_pause.svg"),
        startupToggleActionText(targetEnabled));
    QAction* protectedReasonAction = nullptr;
    if (hasRegistryEntry && registryEntry.backendEntry.isProtected)
    {
        protectedReasonAction = contextMenu.addAction(
            createBlueIcon(":/Icon/process_details.svg"),
            startupText(
                "startup.menu.protected_reason",
                QStringLiteral("受保护：%1"))
                .arg(startupRiskReasonText(registryEntry.backendEntry)));
        protectedReasonAction->setEnabled(false);
    }
    QAction* deleteAction = contextMenu.addAction(
        createBlueIcon(":/Icon/log_clear.svg"),
        startupText("startup.menu.delete", QStringLiteral("删除项")));

    if (nodeKind == StartupTreeNodeKind::Group
        || nodeKind == StartupTreeNodeKind::Placeholder)
    {
        openFileAction->setEnabled(false);
        filePropertiesAction->setEnabled(false);
        if (uploadVirusTotalAction != nullptr)
        {
            uploadVirusTotalAction->setEnabled(false);
        }
        openRegistryAction->setEnabled(!locationText.isEmpty());
        toggleAction->setEnabled(false);
        deleteAction->setEnabled(false);
    }
    else if (entryIndex >= 0 && entryIndex < static_cast<int>(m_entryList.size()))
    {
        const StartupEntry& entry = registryEntry;
        openFileAction->setEnabled(entry.canOpenFileLocation);
        filePropertiesAction->setEnabled(entry.canOpenFileLocation);
        if (uploadVirusTotalAction != nullptr)
        {
            uploadVirusTotalAction->setEnabled(entry.canOpenFileLocation && !entry.imagePathText.trimmed().isEmpty());
        }
        openRegistryAction->setEnabled(entry.canOpenRegistryLocation);
        const bool toggleSupported = targetEnabled
            ? entry.backendEntry.canEnable
            : entry.backendEntry.canDisable;
        toggleAction->setEnabled(
            toggleSupported
            && !entry.backendEntry.isProtected
            && !m_startupActionInProgress.load());
        deleteAction->setEnabled(
            entry.canDelete
            && !entry.backendEntry.isProtected
            && !m_startupActionInProgress.load());
    }
    else
    {
        openFileAction->setEnabled(false);
        filePropertiesAction->setEnabled(false);
        if (uploadVirusTotalAction != nullptr)
        {
            uploadVirusTotalAction->setEnabled(false);
        }
        openRegistryAction->setEnabled(false);
        toggleAction->setEnabled(false);
        deleteAction->setEnabled(false);
    }

    QAction* selectedAction = contextMenu.exec(m_registryTree->viewport()->mapToGlobal(localPos));
    if (selectedAction == detailAction)
    {
        showSelectedEntryDetails(StartupCategory::Registry, nullptr);
    }
    else if (selectedAction == copyAction)
    {
        copySelectedRow(StartupCategory::Registry, nullptr);
    }
    else if (selectedAction == openFileAction)
    {
        openSelectedFileLocation(StartupCategory::Registry, nullptr);
    }
    else if (selectedAction == filePropertiesAction)
    {
        openSelectedFileProperties(StartupCategory::Registry, nullptr);
    }
    else if (selectedAction == openRegistryAction)
    {
        openSelectedRegistryLocation(StartupCategory::Registry, nullptr);
    }
    else if (selectedAction == uploadVirusTotalAction)
    {
        return;
    }
    else if (selectedAction == toggleAction && hasRegistryEntry)
    {
        setStartupEntryEnabled(registryEntry, targetEnabled);
    }
    else if (selectedAction == deleteAction && hasRegistryEntry)
    {
        deleteStartupEntry(registryEntry);
    }
}

void StartupDock::openSelectedFileLocation(const StartupCategory category, QTableWidget* tableWidget)
{
    int entryIndex = -1;
    if (category == StartupCategory::Registry)
    {
        entryIndex = findEntryIndexByRegistryTreeItem(
            m_registryTree != nullptr ? m_registryTree->currentItem() : nullptr);
    }
    else if (tableWidget != nullptr && tableWidget->currentRow() >= 0)
    {
        entryIndex = findEntryIndexByTableRow(category, tableWidget->currentRow());
    }
    if (entryIndex < 0 || entryIndex >= static_cast<int>(m_entryList.size()))
    {
        return;
    }

    const StartupEntry& entry = m_entryList[static_cast<std::size_t>(entryIndex)];
    if (!entry.canOpenFileLocation || entry.imagePathText.trimmed().isEmpty())
    {
        QMessageBox::information(
            this,
            startupText("startup.dialog.title", QStringLiteral("启动项")),
            startupText(
                "startup.dialog.open_file.no_path",
                QStringLiteral("该条目没有可打开的文件路径。")));
        return;
    }

    QProcess::startDetached(
        QStringLiteral("explorer.exe"),
        { QStringLiteral("/select,%1").arg(QDir::toNativeSeparators(entry.imagePathText)) });
}

void StartupDock::openSelectedRegistryLocation(const StartupCategory category, QTableWidget* tableWidget)
{
    QString locationText;
    if (category == StartupCategory::Registry)
    {
        QTreeWidgetItem* currentItem = (m_registryTree != nullptr) ? m_registryTree->currentItem() : nullptr;
        if (currentItem == nullptr)
        {
            return;
        }

        const StartupTreeNodeKind nodeKind = static_cast<StartupTreeNodeKind>(
            currentItem->data(0, kStartupTreeNodeKindRole).toInt());
        if (nodeKind == StartupTreeNodeKind::Group || nodeKind == StartupTreeNodeKind::Placeholder)
        {
            locationText = currentItem->data(0, kStartupTreeLocationRole).toString().trimmed();
        }
        else
        {
            const int entryIndex = findEntryIndexByRegistryTreeItem(currentItem);
            if (entryIndex >= 0 && entryIndex < static_cast<int>(m_entryList.size()))
            {
                locationText = m_entryList[static_cast<std::size_t>(entryIndex)].locationText;
            }
        }
    }
    else if (tableWidget != nullptr && tableWidget->currentRow() >= 0)
    {
        const int entryIndex = findEntryIndexByTableRow(category, tableWidget->currentRow());
        if (entryIndex >= 0 && entryIndex < static_cast<int>(m_entryList.size()))
        {
            locationText = m_entryList[static_cast<std::size_t>(entryIndex)].locationText;
        }
    }
    if (locationText.trimmed().isEmpty())
    {
        QMessageBox::information(
            this,
            startupText("startup.dialog.title", QStringLiteral("启动项")),
            startupText(
                "startup.dialog.open_registry.no_path",
                QStringLiteral("该条目没有可打开的注册表位置。")));
        return;
    }

    QApplication::clipboard()->setText(locationText);
    QProcess::startDetached(QStringLiteral("regedit.exe"), {});
    QMessageBox::information(
        this,
        startupText("startup.dialog.title", QStringLiteral("启动项")),
        startupText(
            "startup.dialog.open_registry.success",
            QStringLiteral("已复制注册表路径到剪贴板，并尝试打开 regedit。")));
}

void StartupDock::copySelectedRow(const StartupCategory category, QTableWidget* tableWidget)
{
    if (category == StartupCategory::Registry)
    {
        QTreeWidgetItem* currentItem = (m_registryTree != nullptr) ? m_registryTree->currentItem() : nullptr;
        if (currentItem == nullptr)
        {
            return;
        }

        const StartupTreeNodeKind nodeKind = static_cast<StartupTreeNodeKind>(
            currentItem->data(0, kStartupTreeNodeKindRole).toInt());
        if (nodeKind == StartupTreeNodeKind::Group || nodeKind == StartupTreeNodeKind::Placeholder)
        {
            QApplication::clipboard()->setText(currentItem->data(0, kStartupTreeLocationRole).toString());
            return;
        }

        const int entryIndex = findEntryIndexByRegistryTreeItem(currentItem);
        if (entryIndex < 0 || entryIndex >= static_cast<int>(m_entryList.size()))
        {
            return;
        }

        const StartupEntry& entry = m_entryList[static_cast<std::size_t>(entryIndex)];
        QApplication::clipboard()->setText(startupEntryTsvRow(entry));
        return;
    }

    if (tableWidget == nullptr || tableWidget->currentRow() < 0)
    {
        return;
    }

    const int entryIndex = findEntryIndexByTableRow(category, tableWidget->currentRow());
    if (entryIndex < 0 || entryIndex >= static_cast<int>(m_entryList.size()))
    {
        return;
    }

    const StartupEntry& entry = m_entryList[static_cast<std::size_t>(entryIndex)];
    QApplication::clipboard()->setText(startupEntryTsvRow(entry));
}

void StartupDock::exportCurrentView()
{
    const QString outputPath = QFileDialog::getSaveFileName(
        this,
        startupText("startup.dialog.export.title", QStringLiteral("导出启动项")),
        QStringLiteral("StartupEntries.txt"),
        QStringLiteral("Text Files (*.txt);;All Files (*.*)"));
    if (outputPath.trimmed().isEmpty())
    {
        return;
    }

    QFile outputFile(outputPath);
    if (!outputFile.open(QIODevice::WriteOnly | QIODevice::Text))
    {
        QMessageBox::warning(
            this,
            startupText("startup.dialog.title", QStringLiteral("启动项")),
            startupText("startup.dialog.export.failed", QStringLiteral("导出失败：%1"))
                .arg(outputFile.errorString()));
        return;
    }

    QTextStream outputStream(&outputFile);
    outputStream.setEncoding(QStringConverter::Utf8);
    outputStream << startupTableHeaders().join(QChar('\t')) << '\n';
    if (currentCategory() == StartupCategory::Registry)
    {
        if (m_registryTree == nullptr)
        {
            return;
        }

        for (int rootIndex = 0; rootIndex < m_registryTree->topLevelItemCount(); ++rootIndex)
        {
            QTreeWidgetItem* groupItem = m_registryTree->topLevelItem(rootIndex);
            if (groupItem == nullptr)
            {
                continue;
            }

            for (int childIndex = 0; childIndex < groupItem->childCount(); ++childIndex)
            {
                QTreeWidgetItem* childItem = groupItem->child(childIndex);
                const int entryIndex = findEntryIndexByRegistryTreeItem(childItem);
                if (entryIndex < 0 || entryIndex >= static_cast<int>(m_entryList.size()))
                {
                    continue;
                }

                const StartupEntry& entry = m_entryList[static_cast<std::size_t>(entryIndex)];
                outputStream << startupEntryTsvRow(entry) << '\n';
            }
        }
    }
    else
    {
        QTableWidget* tableWidget = currentCategoryTable();
        if (tableWidget == nullptr)
        {
            return;
        }

        for (int rowIndex = 0; rowIndex < tableWidget->rowCount(); ++rowIndex)
        {
            const int entryIndex = findEntryIndexByTableRow(currentCategory(), rowIndex);
            if (entryIndex < 0 || entryIndex >= static_cast<int>(m_entryList.size()))
            {
                continue;
            }

            const StartupEntry& entry = m_entryList[static_cast<std::size_t>(entryIndex)];
            outputStream << startupEntryTsvRow(entry) << '\n';
        }
    }
}

void StartupDock::applyFilterAndRefresh()
{
    rebuildAllTables();
    if (m_statusLabel != nullptr)
    {
        m_statusLabel->setText(
            startupText("startup.status.summary", QStringLiteral("状态：共 %1 条，当前分类 %2"))
                .arg(m_entryList.size())
                .arg(categoryToText(currentCategory())));
    }
}

void StartupDock::setStartupEntryEnabled(StartupEntry entry, const bool enabled)
{
    const QString actionText = startupToggleActionText(enabled);
    const QString operationTitle = startupText(
        "startup.dialog.toggle.operation.title",
        QStringLiteral("%1启动项"))
        .arg(actionText);

    if (entry.backendEntry.isProtected)
    {
        QMessageBox::information(
            this,
            operationTitle,
            startupText(
                "startup.dialog.toggle.protected",
                QStringLiteral("该条目受保护，不能更改启用状态。\n\n条目：%1\n保护原因：%2"))
                .arg(entry.itemNameText)
                .arg(startupRiskReasonText(entry.backendEntry)));
        return;
    }

    const bool actionSupported = enabled
        ? entry.backendEntry.canEnable
        : entry.backendEntry.canDisable;
    if (!actionSupported)
    {
        QMessageBox::information(
            this,
            operationTitle,
            startupText(
                "startup.dialog.toggle.unsupported",
                QStringLiteral("后端未允许对该条目执行“%1”。请刷新后查看最新状态。"))
                .arg(actionText));
        return;
    }

    const QString locationText = entry.locationText.trimmed().isEmpty()
        ? startupText("startup.value.empty", QStringLiteral("<空>"))
        : entry.locationText;
    const QMessageBox::StandardButton confirmButton = QMessageBox::warning(
        this,
        startupText(
            "startup.dialog.toggle.confirm.title",
            QStringLiteral("确认%1"))
            .arg(operationTitle),
        startupText(
            "startup.dialog.toggle.confirm.message",
            QStringLiteral("%1\n\n条目：%2\n来源：%3\n目标状态：%4\n风险提示：%5\n\n此操作可恢复；完成后可以通过右键菜单改回原状态。是否继续？"))
            .arg(startupToggleImpactText(entry.backendEntry.actionKind, enabled))
            .arg(entry.itemNameText)
            .arg(locationText)
            .arg(buildStatusText(enabled))
            .arg(startupRiskReasonText(entry.backendEntry)),
        QMessageBox::Yes | QMessageBox::No,
        QMessageBox::No);
    if (confirmButton != QMessageBox::Yes)
    {
        return;
    }

    bool expectedIdle = false;
    if (!m_startupActionInProgress.compare_exchange_strong(expectedIdle, true))
    {
        QMessageBox::information(
            this,
            operationTitle,
            startupText(
                "startup.dialog.toggle.busy",
                QStringLiteral("已有一个启动项启停操作正在执行，请等待其完成后重试。")));
        return;
    }

    const ks::startup::StartupEntry backendEntry = entry.backendEntry;
    const QString itemNameText = entry.itemNameText;
    const QString sourceTypeText = entry.sourceTypeText;
    const QString entryLocationText = entry.locationText;
    if (m_actionThread != nullptr && m_actionThread->joinable())
    {
        m_actionThread->join();
    }
    m_actionThread = std::make_unique<std::thread>(
        [this,
         backendEntry,
         enabled,
         actionText,
         operationTitle,
         itemNameText,
         sourceTypeText,
         entryLocationText]()
    {
        const ks::startup::ActionResult actionResult =
            ks::startup::SetStartupEntryEnabled(backendEntry, enabled);
        if (m_destroying.load())
        {
            return;
        }

        const bool callbackQueued = QMetaObject::invokeMethod(
            this,
            [this,
             actionResult,
             enabled,
             actionText,
             operationTitle,
             itemNameText,
             sourceTypeText,
             entryLocationText]()
            {
                if (m_destroying.load())
                {
                    return;
                }

                m_startupActionInProgress.store(false);
                refreshAllStartupEntries();
                if (!actionResult.success)
                {
                    const QString failureText = startupActionFailureText(actionResult);
                    bool privilegePromptHandled = false;
                    if (isStartupPrivilegeFailure(actionResult))
                    {
                        if (actionResult.errorCode != ERROR_SUCCESS)
                        {
                            privilegePromptHandled = ks::ui::promptForPrivilegeFailure(
                                this,
                                operationTitle,
                                static_cast<unsigned long>(actionResult.errorCode));
                        }
                        if (!privilegePromptHandled)
                        {
                            privilegePromptHandled = ks::ui::promptForPrivilegeFailure(
                                this,
                                operationTitle,
                                failureText);
                        }
                    }
                    if (!privilegePromptHandled)
                    {
                        QMessageBox::warning(
                            this,
                            startupText(
                                "startup.dialog.toggle.failed.title",
                                QStringLiteral("%1失败"))
                                .arg(operationTitle),
                            failureText);
                    }
                    return;
                }

                kLogEvent actionEvent;
                info << actionEvent
                    << startupText(
                        "startup.log.toggle.succeeded",
                        QStringLiteral("[StartupDock] 可逆启停成功, action=%1, changed=%2, targetEnabled=%3, type=%4, name=%5, location=%6"))
                           .arg(actionText)
                           .arg(actionResult.changed ? QStringLiteral("true") : QStringLiteral("false"))
                           .arg(enabled ? QStringLiteral("true") : QStringLiteral("false"))
                           .arg(sourceTypeText)
                           .arg(itemNameText)
                           .arg(entryLocationText)
                           .toStdString()
                    << eol;
            },
            Qt::QueuedConnection);
        if (!callbackQueued)
        {
            m_startupActionInProgress.store(false);
        }
    });
}

void StartupDock::deleteStartupEntry(StartupEntry entry)
{
    if (entry.backendEntry.isProtected)
    {
        QMessageBox::warning(
            this,
            startupText(
                "startup.dialog.delete.protected.title",
                QStringLiteral("受保护的启动项")),
            startupText(
                "startup.dialog.delete.protected.message",
                QStringLiteral("该条目受保护，永久删除已被阻止。\n\n条目：%1\n保护原因：%2"))
                .arg(entry.itemNameText)
                .arg(startupRiskReasonText(entry.backendEntry)));
        return;
    }
    if (!entry.canDelete)
    {
        QMessageBox::information(
            this,
            startupText("startup.dialog.title", QStringLiteral("启动项")),
            startupText("startup.dialog.delete.unsupported", QStringLiteral("该条目当前不支持删除。")));
        return;
    }

    const QMessageBox::StandardButton confirmButton = QMessageBox::warning(
        this,
        startupText(
            "startup.dialog.delete.confirm.irreversible.title",
            QStringLiteral("永久删除启动项")),
        startupText(
            "startup.dialog.delete.confirm.irreversible.message",
            QStringLiteral("即将永久删除以下启动项及其来源记录：\n\n%1\n来源：%2\n\n此操作不可通过 KSword 恢复。若只是暂时停止启动，请取消并使用“禁用”。\n\n确定仍要永久删除吗？"))
            .arg(entry.itemNameText)
            .arg(entry.locationText),
        QMessageBox::Yes | QMessageBox::No,
        QMessageBox::No);
    if (confirmButton != QMessageBox::Yes)
    {
        return;
    }

    bool expectedIdle = false;
    if (!m_startupActionInProgress.compare_exchange_strong(expectedIdle, true))
    {
        QMessageBox::information(
            this,
            startupText("startup.dialog.title", QStringLiteral("启动项")),
            startupText(
                "startup.dialog.operation.busy",
                QStringLiteral("已有一个启动项修改操作正在执行，请等待其完成后重试。")));
        return;
    }
    StartupActionFlagReset actionFlagReset(m_startupActionInProgress);

    QString errorText;
    bool deleteOk = false;

    if (entry.sourceTypeText == QStringLiteral("StartupFolder"))
    {
        deleteOk = QFile::remove(entry.imagePathText);
        if (!deleteOk)
        {
            errorText = startupText("startup.delete.file_failed", QStringLiteral("删除文件失败：%1"))
                .arg(entry.imagePathText);
        }
    }
    else if (entry.category == StartupCategory::Logon || entry.category == StartupCategory::Registry)
    {
        HKEY rootKey = nullptr;
        QString subKeyText;
        if (!splitRegistryLocation(entry.locationText, &rootKey, &subKeyText))
        {
            errorText = startupText(
                "startup.delete.registry_location_failed",
                QStringLiteral("解析注册表位置失败。"));
            deleteOk = false;
        }
        else if (entry.deleteRegistryTree)
        {
            deleteOk = deleteRegistryTreeByPath(rootKey, subKeyText, &errorText);
        }
        else
        {
            const QString valueNameText = entry.registryValueNameText.trimmed().isEmpty()
                ? entry.itemNameText
                : entry.registryValueNameText;
            deleteOk = deleteRegistryValueByPath(rootKey, subKeyText, valueNameText, &errorText);
        }

        if (!deleteOk && errorText.isEmpty())
        {
            errorText = startupText(
                "startup.delete.registry_failed",
                QStringLiteral("删除注册表启动项失败。"));
        }
    }
    else if (entry.sourceTypeText == QStringLiteral("AutoService")
        || entry.sourceTypeText == QStringLiteral("Driver"))
    {
        const int lastSlashIndex = entry.locationText.lastIndexOf('\\');
        const QString serviceNameText = (lastSlashIndex >= 0)
            ? entry.locationText.mid(lastSlashIndex + 1)
            : entry.itemNameText;
        deleteOk = deleteScmObjectByName(serviceNameText, &errorText);
    }
    else if (entry.sourceTypeText == QStringLiteral("ScheduledTask"))
    {
        const StartupEntry taskEntry = entry;
        if (m_actionThread != nullptr && m_actionThread->joinable())
        {
            m_actionThread->join();
        }
        m_actionThread = std::make_unique<std::thread>([this, taskEntry]()
        {
            QProcess processObject;
            processObject.setProgram(QStringLiteral("schtasks.exe"));
            processObject.setArguments({
                QStringLiteral("/Delete"),
                QStringLiteral("/TN"),
                taskEntry.locationText,
                QStringLiteral("/F")
                });
            processObject.start();
            bool taskDeleteOk = processObject.waitForStarted(1500) && processObject.waitForFinished(10000)
                && processObject.exitStatus() == QProcess::NormalExit
                && processObject.exitCode() == 0;
            QString taskErrorText;
            if (!taskDeleteOk)
            {
                taskErrorText = QString::fromLocal8Bit(processObject.readAllStandardError()).trimmed();
                if (taskErrorText.isEmpty())
                {
                    taskErrorText = QString::fromLocal8Bit(processObject.readAllStandardOutput()).trimmed();
                }
                if (taskErrorText.isEmpty())
                {
                    taskErrorText = startupText("startup.delete.schtasks_failed", QStringLiteral("schtasks 删除失败。"));
                }
            }

            if (m_destroying.load())
            {
                return;
            }
            const bool callbackQueued = QMetaObject::invokeMethod(
                this,
                [this, taskEntry, taskDeleteOk, taskErrorText]()
                {
                    if (m_destroying.load())
                    {
                        return;
                    }
                    m_startupActionInProgress.store(false);
                    if (!taskDeleteOk)
                    {
                        // privilegePromptHandled：恢复提示已覆盖失败时不再叠加删除错误框。
                        const bool privilegePromptHandled = ks::ui::promptForPrivilegeFailure(
                            this,
                            startupText(
                                "startup.dialog.delete.operation.title",
                                QStringLiteral("删除启动项")),
                            taskErrorText);
                        if (!privilegePromptHandled)
                        {
                            QMessageBox::warning(
                                this,
                                startupText("startup.dialog.title", QStringLiteral("启动项")),
                                startupText("startup.dialog.delete.failed", QStringLiteral("删除失败：%1"))
                                    .arg(taskErrorText));
                        }
                        return;
                    }

                    kLogEvent deleteEvent;
                    info << deleteEvent
                        << startupText(
                            "startup.log.delete.succeeded",
                            QStringLiteral("[StartupDock] 删除启动项成功, type="))
                               .toStdString()
                        << taskEntry.sourceTypeText.toStdString()
                        << ", name="
                        << taskEntry.itemNameText.toStdString()
                        << ", location="
                        << taskEntry.locationText.toStdString()
                        << eol;
                    refreshAllStartupEntries();
                },
                Qt::QueuedConnection);
            if (!callbackQueued)
            {
                m_startupActionInProgress.store(false);
            }
        });
        actionFlagReset.dismiss();
        return;
    }

    if (!deleteOk)
    {
        // privilegePromptHandled：恢复提示已覆盖失败时不再叠加删除错误框。
        const bool privilegePromptHandled = ks::ui::promptForPrivilegeFailure(
            this,
            startupText(
                "startup.dialog.delete.operation.title",
                QStringLiteral("删除启动项")),
            errorText);
        if (!privilegePromptHandled)
        {
            QMessageBox::warning(
                this,
                startupText("startup.dialog.title", QStringLiteral("启动项")),
                startupText("startup.dialog.delete.failed", QStringLiteral("删除失败：%1"))
                    .arg(errorText));
        }
        return;
    }

    kLogEvent deleteEvent;
    info << deleteEvent
        << startupText(
            "startup.log.delete.succeeded",
            QStringLiteral("[StartupDock] 删除启动项成功, type="))
               .toStdString()
        << entry.sourceTypeText.toStdString()
        << ", name="
        << entry.itemNameText.toStdString()
        << ", location="
        << entry.locationText.toStdString()
        << eol;

    refreshAllStartupEntries();
}

int StartupDock::findEntryIndexByTableRow(const StartupCategory category, const int row) const
{
    QTableWidget* tableWidget = nullptr;
    switch (category)
    {
    case StartupCategory::All:
        tableWidget = m_allTable;
        break;
    case StartupCategory::Logon:
        tableWidget = m_logonTable;
        break;
    case StartupCategory::Services:
        tableWidget = m_servicesTable;
        break;
    case StartupCategory::Drivers:
        tableWidget = m_driversTable;
        break;
    case StartupCategory::Tasks:
        tableWidget = m_tasksTable;
        break;
    case StartupCategory::Registry:
        return -1;
    case StartupCategory::Wmi:
        tableWidget = m_wmiTable;
        break;
    default:
        break;
    }

    if (tableWidget == nullptr || row < 0)
    {
        return -1;
    }

    QTableWidgetItem* nameItem = tableWidget->item(row, toStartupColumn(StartupColumn::Name));
    if (nameItem == nullptr)
    {
        return -1;
    }
    return nameItem->data(Qt::UserRole).toInt();
}

bool StartupDock::entryMatchesCurrentFilter(const StartupEntry& entry) const
{
    const QString keywordText = (m_filterEdit != nullptr) ? m_filterEdit->text().trimmed() : QString();
    const bool hideMicrosoft = (m_hideMicrosoftCheck != nullptr) && m_hideMicrosoftCheck->isChecked();

    if (hideMicrosoft)
    {
        const QString publisherLowerText = entry.publisherText.toLower();
        if (publisherLowerText.contains(QStringLiteral("microsoft"))
            || publisherLowerText.contains(QStringLiteral("windows")))
        {
            return false;
        }
    }

    if (keywordText.isEmpty())
    {
        return true;
    }

    const QString haystackText =
        entry.itemNameText + QLatin1Char('\n')
        + entry.publisherText + QLatin1Char('\n')
        + entry.imagePathText + QLatin1Char('\n')
        + entry.commandText + QLatin1Char('\n')
        + entry.locationText + QLatin1Char('\n')
        + entry.userText + QLatin1Char('\n')
        + ks::i18n::sourceText(entry.userText) + QLatin1Char('\n')
        + entry.sourceTypeText + QLatin1Char('\n')
        + ks::i18n::sourceText(entry.sourceTypeText) + QLatin1Char('\n')
        + entry.detailText + QLatin1Char('\n')
        + startupLocalizedDetailText(entry.detailText);
    return haystackText.contains(keywordText, Qt::CaseInsensitive);
}
