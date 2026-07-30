#include "ContextMenuCleanerTab.h"

#include "ContextMenuCleanerTab.Internal.h"

#include <QDateTime>
#include <QMessageBox>
#include <QUuid>

#include <algorithm>

#pragma comment(lib, "Advapi32.lib")

namespace ks::misc
{

using namespace context_menu_cleaner_detail;

namespace
{
    constexpr wchar_t kBackupRootPath[] =
        L"Software\\KSword\\ContextMenuCleaner\\UrlBindingBackups";
    constexpr wchar_t kLastBackupIdValue[] = L"LastBackupId";
    constexpr wchar_t kTargetPathValue[] = L"TargetPath";
    constexpr wchar_t kRootKindValue[] = L"RootKind";
    constexpr wchar_t kViewFlagValue[] = L"ViewFlag";
    constexpr wchar_t kBackupDataKey[] = L"Data";
    constexpr DWORD kRootKindCurrentUser = 1UL;
    constexpr DWORD kRootKindLocalMachine = 2UL;

    // isAllowedUrlBindingPath：
    // - 输入 rootKey/path：准备删除或恢复的根键与子键路径；
    // - 处理：HKLM 仅接受单层 Software\Classes 协议，HKCU 额外接受 UserChoice；
    // - 返回：路径满足 URL 绑定页最小作用域时返回 true。
    bool isAllowedUrlBindingPath(const HKEY rootKey, const QString& path)
    {
        const QString trimmedPath = path.trimmed();
        const QString classesPrefix = QStringLiteral("Software\\Classes\\");
        if (trimmedPath.startsWith(classesPrefix, Qt::CaseInsensitive))
        {
            const QString scheme = trimmedPath.mid(classesPrefix.size());
            return (rootKey == HKEY_CURRENT_USER || rootKey == HKEY_LOCAL_MACHINE)
                && !scheme.isEmpty()
                && !scheme.contains('\\');
        }
        if (rootKey != HKEY_CURRENT_USER)
        {
            return false;
        }

        const QString userChoicePrefix =
            QStringLiteral("Software\\Microsoft\\Windows\\Shell\\Associations\\UrlAssociations\\");
        const QString userChoiceSuffix = QStringLiteral("\\UserChoice");
        if (!trimmedPath.startsWith(userChoicePrefix, Qt::CaseInsensitive)
            || !trimmedPath.endsWith(userChoiceSuffix, Qt::CaseInsensitive))
        {
            return false;
        }

        const QString scheme = trimmedPath.mid(
            userChoicePrefix.size(),
            trimmedPath.size() - userChoicePrefix.size() - userChoiceSuffix.size());
        return !scheme.isEmpty() && !scheme.contains('\\');
    }

    DWORD backupRootKind(const HKEY rootKey)
    {
        if (rootKey == HKEY_CURRENT_USER)
        {
            return kRootKindCurrentUser;
        }
        if (rootKey == HKEY_LOCAL_MACHINE)
        {
            return kRootKindLocalMachine;
        }
        return 0UL;
    }

    HKEY rootKeyFromBackupKind(const DWORD rootKind)
    {
        if (rootKind == kRootKindCurrentUser)
        {
            return HKEY_CURRENT_USER;
        }
        if (rootKind == kRootKindLocalMachine)
        {
            return HKEY_LOCAL_MACHINE;
        }
        return nullptr;
    }

    // isSupportedViewFlag：
    // - 输入 viewFlag：条目保存的 WOW64 视图；
    // - 处理：拒绝混入访问权限位或未知标志；
    // - 返回：仅接受默认、32 位或 64 位视图。
    bool isSupportedViewFlag(const REGSAM viewFlag)
    {
        return viewFlag == 0
            || viewFlag == KEY_WOW64_32KEY
            || viewFlag == KEY_WOW64_64KEY;
    }

    // writeStringValue：
    // - 输入 key/name/value：目标键、值名和 UTF-16 文本；
    // - 处理：写入包含结尾空字符的 REG_SZ；
    // - 返回：Win32 状态码。
    LSTATUS writeStringValue(HKEY key, const wchar_t* name, const QString& value)
    {
        const DWORD byteCount = static_cast<DWORD>((value.size() + 1) * sizeof(wchar_t));
        return ::RegSetValueExW(
            key,
            name,
            0,
            REG_SZ,
            reinterpret_cast<const BYTE*>(value.utf16()),
            byteCount);
    }

    // readStringValue：
    // - 输入 key/name：目标键和值名；
    // - 处理：两阶段读取 REG_SZ/REG_EXPAND_SZ；
    // - 返回：成功时写出文本并返回 ERROR_SUCCESS。
    LSTATUS readStringValue(HKEY key, const wchar_t* name, QString* valueOut)
    {
        if (valueOut == nullptr)
        {
            return ERROR_INVALID_PARAMETER;
        }
        valueOut->clear();

        DWORD valueType = REG_NONE;
        DWORD byteCount = 0;
        LSTATUS status = ::RegQueryValueExW(
            key,
            name,
            nullptr,
            &valueType,
            nullptr,
            &byteCount);
        if (status != ERROR_SUCCESS)
        {
            return status;
        }
        if ((valueType != REG_SZ && valueType != REG_EXPAND_SZ)
            || byteCount < sizeof(wchar_t))
        {
            return ERROR_INVALID_DATA;
        }

        QVector<wchar_t> buffer(
            static_cast<qsizetype>(byteCount / sizeof(wchar_t)) + 1,
            L'\0');
        status = ::RegQueryValueExW(
            key,
            name,
            nullptr,
            &valueType,
            reinterpret_cast<BYTE*>(buffer.data()),
            &byteCount);
        if (status == ERROR_SUCCESS)
        {
            *valueOut = QString::fromWCharArray(buffer.constData()).trimmed();
        }
        return status;
    }

    // cleanupFailedBatch：
    // - 输入 backupRoot/batchId：尚未发布的备份批次；
    // - 处理：删除不完整批次，确保 LastBackupId 永不指向半成品；
    // - 返回：无。
    void cleanupFailedBatch(HKEY backupRoot, const QString& batchId)
    {
        if (backupRoot != nullptr && !batchId.isEmpty())
        {
            (void)::RegDeleteTreeW(
                backupRoot,
                reinterpret_cast<const wchar_t*>(batchId.utf16()));
        }
    }

    // setBackupError：
    // - 输入 errorTextOut/context/status：错误输出、操作说明和 Win32 状态；
    // - 处理：生成可定位失败阶段的文本；
    // - 返回：无。
    void setBackupError(
        QString* errorTextOut,
        const QString& context,
        const LSTATUS status)
    {
        if (errorTextOut != nullptr)
        {
            *errorTextOut = QStringLiteral("%1：%2")
                .arg(context, winErrorText(static_cast<DWORD>(status)));
        }
    }
}

bool ContextMenuCleanerTab::isUrlBindingDeletionAllowed(const ContextMenuEntry& entry)
{
    return entry.area == MenuArea::UrlBinding
        && (entry.rootKey == HKEY_CURRENT_USER || entry.rootKey == HKEY_LOCAL_MACHINE)
        && entry.deleteKind == DeleteKind::RegistryTree
        && isSupportedViewFlag(entry.viewFlag)
        && isAllowedUrlBindingPath(entry.rootKey, entry.subKeyPath)
        && !isProtectedUrlBindingEntry(entry);
}

bool ContextMenuCleanerTab::createUrlBindingBackup(
    const QVector<int>& entryIndexes,
    QString* errorTextOut) const
{
    if (errorTextOut != nullptr)
    {
        errorTextOut->clear();
    }
    if (entryIndexes.isEmpty())
    {
        if (errorTextOut != nullptr)
        {
            *errorTextOut = QStringLiteral("没有可备份的 URL 绑定项目。");
        }
        return false;
    }

    const AreaWidgets* areaWidgets = widgetsForArea(MenuArea::UrlBinding);
    if (areaWidgets == nullptr)
    {
        if (errorTextOut != nullptr)
        {
            *errorTextOut = QStringLiteral("URL 绑定页面状态不可用。");
        }
        return false;
    }

    HKEY backupRoot = nullptr;
    LSTATUS status = ::RegCreateKeyExW(
        HKEY_CURRENT_USER,
        kBackupRootPath,
        0,
        nullptr,
        REG_OPTION_NON_VOLATILE,
        KEY_READ | KEY_WRITE,
        nullptr,
        &backupRoot,
        nullptr);
    if (status != ERROR_SUCCESS || backupRoot == nullptr)
    {
        setBackupError(errorTextOut, QStringLiteral("无法创建备份根键"), status);
        return false;
    }

    const QString batchId = QStringLiteral("%1-%2")
        .arg(
            QDateTime::currentDateTimeUtc().toString(QStringLiteral("yyyyMMdd-HHmmsszzz")),
            QUuid::createUuid().toString(QUuid::WithoutBraces));
    HKEY batchKey = nullptr;
    status = ::RegCreateKeyExW(
        backupRoot,
        reinterpret_cast<const wchar_t*>(batchId.utf16()),
        0,
        nullptr,
        REG_OPTION_NON_VOLATILE,
        KEY_READ | KEY_WRITE,
        nullptr,
        &batchKey,
        nullptr);
    if (status != ERROR_SUCCESS || batchKey == nullptr)
    {
        setBackupError(errorTextOut, QStringLiteral("无法创建备份批次"), status);
        ::RegCloseKey(backupRoot);
        return false;
    }

    for (int itemIndex = 0; itemIndex < entryIndexes.size(); ++itemIndex)
    {
        const int entryIndex = entryIndexes.at(itemIndex);
        if (entryIndex < 0 || entryIndex >= areaWidgets->entries.size())
        {
            status = ERROR_INVALID_INDEX;
            setBackupError(errorTextOut, QStringLiteral("备份条目下标无效"), status);
            break;
        }

        const ContextMenuEntry& entry = areaWidgets->entries.at(entryIndex);
        if (!isUrlBindingDeletionAllowed(entry))
        {
            status = ERROR_ACCESS_DENIED;
            setBackupError(errorTextOut, QStringLiteral("备份安全校验拒绝目标"), status);
            break;
        }

        HKEY sourceKey = nullptr;
        status = ::RegOpenKeyExW(
            entry.rootKey,
            reinterpret_cast<const wchar_t*>(entry.subKeyPath.utf16()),
            0,
            KEY_READ | entry.viewFlag,
            &sourceKey);
        if (status != ERROR_SUCCESS || sourceKey == nullptr)
        {
            setBackupError(
                errorTextOut,
                QStringLiteral("无法打开待备份注册表树 %1").arg(entry.subKeyPath),
                status);
            break;
        }

        const QString itemName = QStringLiteral("%1").arg(itemIndex, 4, 10, QLatin1Char('0'));
        HKEY itemKey = nullptr;
        status = ::RegCreateKeyExW(
            batchKey,
            reinterpret_cast<const wchar_t*>(itemName.utf16()),
            0,
            nullptr,
            REG_OPTION_NON_VOLATILE,
            KEY_READ | KEY_WRITE,
            nullptr,
            &itemKey,
            nullptr);
        if (status == ERROR_SUCCESS && itemKey != nullptr)
        {
            status = writeStringValue(itemKey, kTargetPathValue, entry.subKeyPath);
        }
        if (status == ERROR_SUCCESS)
        {
            const DWORD storedRootKind = backupRootKind(entry.rootKey);
            if (storedRootKind == 0UL)
            {
                status = ERROR_INVALID_PARAMETER;
            }
            else
            {
                status = ::RegSetValueExW(
                    itemKey,
                    kRootKindValue,
                    0,
                    REG_DWORD,
                    reinterpret_cast<const BYTE*>(&storedRootKind),
                    sizeof(storedRootKind));
            }
        }
        if (status == ERROR_SUCCESS)
        {
            const DWORD storedViewFlag = static_cast<DWORD>(entry.viewFlag);
            status = ::RegSetValueExW(
                itemKey,
                kViewFlagValue,
                0,
                REG_DWORD,
                reinterpret_cast<const BYTE*>(&storedViewFlag),
                sizeof(storedViewFlag));
        }

        HKEY dataKey = nullptr;
        if (status == ERROR_SUCCESS)
        {
            status = ::RegCreateKeyExW(
                itemKey,
                kBackupDataKey,
                0,
                nullptr,
                REG_OPTION_NON_VOLATILE,
                KEY_READ | KEY_WRITE,
                nullptr,
                &dataKey,
                nullptr);
        }
        if (status == ERROR_SUCCESS && dataKey != nullptr)
        {
            status = ::RegCopyTreeW(sourceKey, nullptr, dataKey);
        }

        if (dataKey != nullptr)
        {
            ::RegCloseKey(dataKey);
        }
        if (itemKey != nullptr)
        {
            ::RegCloseKey(itemKey);
        }
        ::RegCloseKey(sourceKey);

        if (status != ERROR_SUCCESS)
        {
            setBackupError(
                errorTextOut,
                QStringLiteral("复制注册表树 %1 失败").arg(entry.subKeyPath),
                status);
            break;
        }
    }

    if (status == ERROR_SUCCESS)
    {
        status = writeStringValue(backupRoot, kLastBackupIdValue, batchId);
        if (status != ERROR_SUCCESS)
        {
            setBackupError(errorTextOut, QStringLiteral("无法发布最近备份索引"), status);
        }
    }

    ::RegCloseKey(batchKey);
    if (status != ERROR_SUCCESS)
    {
        cleanupFailedBatch(backupRoot, batchId);
    }
    ::RegCloseKey(backupRoot);
    return status == ERROR_SUCCESS;
}

void ContextMenuCleanerTab::restoreLastUrlBindingBackup()
{
    HKEY backupRoot = nullptr;
    LSTATUS status = ::RegOpenKeyExW(
        HKEY_CURRENT_USER,
        kBackupRootPath,
        0,
        KEY_READ,
        &backupRoot);
    if (status == ERROR_FILE_NOT_FOUND)
    {
        QMessageBox::information(
            this,
            QStringLiteral("恢复 URL 绑定"),
            QStringLiteral("当前没有可恢复的 URL 绑定备份。"));
        return;
    }
    if (status != ERROR_SUCCESS || backupRoot == nullptr)
    {
        QMessageBox::critical(
            this,
            QStringLiteral("恢复 URL 绑定"),
            QStringLiteral("无法打开 URL 绑定备份：%1")
                .arg(winErrorText(static_cast<DWORD>(status))));
        return;
    }

    QString batchId;
    status = readStringValue(backupRoot, kLastBackupIdValue, &batchId);
    ::RegCloseKey(backupRoot);
    if (status != ERROR_SUCCESS || batchId.isEmpty())
    {
        QMessageBox::critical(
            this,
            QStringLiteral("恢复 URL 绑定"),
            QStringLiteral("最近备份索引无效：%1")
                .arg(winErrorText(static_cast<DWORD>(status))));
        return;
    }

    const QString batchPath = QStringLiteral("%1\\%2")
        .arg(QString::fromWCharArray(kBackupRootPath), batchId);
    const QStringList itemNames = enumerateRegistrySubKeys(
        HKEY_CURRENT_USER,
        batchPath,
        0);
    if (itemNames.isEmpty())
    {
        QMessageBox::critical(
            this,
            QStringLiteral("恢复 URL 绑定"),
            QStringLiteral("最近备份不包含任何注册表树。"));
        return;
    }

    QStringList failedItems;
    int restoredCount = 0;
    for (const QString& itemName : itemNames)
    {
        const QString itemPath = QStringLiteral("%1\\%2").arg(batchPath, itemName);
        HKEY itemKey = nullptr;
        status = ::RegOpenKeyExW(
            HKEY_CURRENT_USER,
            reinterpret_cast<const wchar_t*>(itemPath.utf16()),
            0,
            KEY_READ,
            &itemKey);
        QString targetPath;
        DWORD rootKind = kRootKindCurrentUser;
        DWORD viewFlag = 0;
        if (status == ERROR_SUCCESS && itemKey != nullptr)
        {
            status = readStringValue(itemKey, kTargetPathValue, &targetPath);
        }
        if (status == ERROR_SUCCESS)
        {
            DWORD valueType = REG_NONE;
            DWORD byteCount = sizeof(rootKind);
            const LSTATUS rootKindStatus = ::RegQueryValueExW(
                itemKey,
                kRootKindValue,
                nullptr,
                &valueType,
                reinterpret_cast<BYTE*>(&rootKind),
                &byteCount);
            if (rootKindStatus != ERROR_SUCCESS
                && rootKindStatus != ERROR_FILE_NOT_FOUND)
            {
                status = rootKindStatus;
            }
            else if (rootKindStatus == ERROR_SUCCESS
                && (valueType != REG_DWORD || byteCount != sizeof(rootKind)))
            {
                status = ERROR_INVALID_DATA;
            }
        }
        if (status == ERROR_SUCCESS)
        {
            DWORD valueType = REG_NONE;
            DWORD byteCount = sizeof(viewFlag);
            status = ::RegQueryValueExW(
                itemKey,
                kViewFlagValue,
                nullptr,
                &valueType,
                reinterpret_cast<BYTE*>(&viewFlag),
                &byteCount);
            if (status == ERROR_SUCCESS
                && (valueType != REG_DWORD || byteCount != sizeof(viewFlag)))
            {
                status = ERROR_INVALID_DATA;
            }
        }
        const HKEY targetRootKey = rootKeyFromBackupKind(rootKind);
        if (status == ERROR_SUCCESS
            && (targetRootKey == nullptr
                || !isAllowedUrlBindingPath(targetRootKey, targetPath)
                || !isSupportedViewFlag(static_cast<REGSAM>(viewFlag))))
        {
            status = ERROR_ACCESS_DENIED;
        }

        HKEY dataKey = nullptr;
        if (status == ERROR_SUCCESS)
        {
            status = ::RegOpenKeyExW(
                itemKey,
                kBackupDataKey,
                0,
                KEY_READ,
                &dataKey);
        }

        HKEY targetKey = nullptr;
        if (status == ERROR_SUCCESS)
        {
            status = ::RegCreateKeyExW(
                targetRootKey,
                reinterpret_cast<const wchar_t*>(targetPath.utf16()),
                0,
                nullptr,
                REG_OPTION_NON_VOLATILE,
                KEY_READ | KEY_WRITE | static_cast<REGSAM>(viewFlag),
                nullptr,
                &targetKey,
                nullptr);
        }
        if (status == ERROR_SUCCESS && dataKey != nullptr && targetKey != nullptr)
        {
            status = ::RegCopyTreeW(dataKey, nullptr, targetKey);
        }

        if (targetKey != nullptr)
        {
            ::RegCloseKey(targetKey);
        }
        if (dataKey != nullptr)
        {
            ::RegCloseKey(dataKey);
        }
        if (itemKey != nullptr)
        {
            ::RegCloseKey(itemKey);
        }

        if (status == ERROR_SUCCESS)
        {
            ++restoredCount;
        }
        else
        {
            failedItems.push_back(QStringLiteral("%1：%2")
                .arg(
                    targetPath.isEmpty() ? itemName : targetPath,
                    winErrorText(static_cast<DWORD>(status))));
        }
    }

    refreshArea(MenuArea::UrlBinding);
    if (failedItems.isEmpty())
    {
        QMessageBox::information(
            this,
            QStringLiteral("恢复 URL 绑定"),
            QStringLiteral("已从最近备份恢复 %1 个 URL 绑定注册表树。").arg(restoredCount));
    }
    else
    {
        QMessageBox::warning(
            this,
            QStringLiteral("恢复 URL 绑定"),
            QStringLiteral("成功恢复 %1 项，失败 %2 项：\n\n%3")
                .arg(restoredCount)
                .arg(failedItems.size())
                .arg(failedItems.join('\n')));
    }
}

} // namespace ks::misc
