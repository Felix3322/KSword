#include "ServiceDock.Internal.h"

#include <QDateTime>
#include <QHash>
#include <QMutex>
#include <QMutexLocker>

#include <Softpub.h>
#include <wintrust.h>

using namespace service_dock_detail;

#pragma comment(lib, "Wintrust.lib")

namespace
{
    // kSignatureCacheEntryLimit 作用：
    // - 限制签名结果缓存条目上限；
    // - 触顶后整体清空，避免进程长时间运行后缓存无界增长。
    constexpr int kSignatureCacheEntryLimit = 4096;

    // signatureCacheMutex 作用：保护签名结果缓存。
    // 入参：无。
    // 返回：进程级唯一互斥量引用；全量枚举线程与单条刷新任务会并发访问缓存。
    QMutex& signatureCacheMutex()
    {
        static QMutex mutexInstance;
        return mutexInstance;
    }

    // signatureCacheMap 作用：缓存 WinVerifyTrust 的判定结论。
    // 入参：无。
    // 返回：以“小写路径|最后写入毫秒|文件字节数”为键的结果表引用。
    QHash<QString, bool>& signatureCacheMap()
    {
        static QHash<QString, bool> cacheInstance;
        return cacheInstance;
    }

    // verifyFileTrustByWinTrust 作用：真正执行一次 WinVerifyTrust 签名校验。
    // 入参：filePathText 为已去掉首尾空白的文件路径。
    // 返回：Windows 信任该文件时返回 true。
    bool verifyFileTrustByWinTrust(const QString& filePathText)
    {
        const std::wstring utf16Path = filePathText.toStdWString();
        WINTRUST_FILE_INFO fileInfo{};
        fileInfo.cbStruct = sizeof(fileInfo);
        fileInfo.pcwszFilePath = utf16Path.c_str();

        WINTRUST_DATA trustData{};
        trustData.cbStruct = sizeof(trustData);
        trustData.dwUIChoice = WTD_UI_NONE;
        trustData.fdwRevocationChecks = WTD_REVOKE_NONE;
        trustData.dwUnionChoice = WTD_CHOICE_FILE;
        trustData.dwStateAction = WTD_STATEACTION_VERIFY;
        trustData.dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL;
        trustData.pFile = &fileInfo;

        GUID policyGuid = WINTRUST_ACTION_GENERIC_VERIFY_V2;
        const LONG verifyResult = ::WinVerifyTrust(nullptr, &policyGuid, &trustData);

        trustData.dwStateAction = WTD_STATEACTION_CLOSE;
        ::WinVerifyTrust(nullptr, &policyGuid, &trustData);
        return verifyResult == ERROR_SUCCESS;
    }

    // isFileTrustedByWindows 作用：带缓存的签名校验入口。
    // 入参：filePathText 为 UI 侧持有的文件路径文本。
    // 返回：Windows 信任该文件时返回 true。
    // 说明：目录签名（catalog）仍要搜 CatRoot 数据库并对文件做哈希，
    //       单个文件典型几十到数百毫秒；这里按“路径 + 最后写入时间 + 大小”
    //       缓存结论，避免同一个 exe 在列表刷新与单条刷新之间被反复验签。
    bool isFileTrustedByWindows(const QString& filePathText)
    {
        const QString normalizedPathText = filePathText.trimmed();
        if (normalizedPathText.isEmpty())
        {
            return false;
        }

        const QFileInfo targetFileInfo(normalizedPathText);
        if (!targetFileInfo.exists() || !targetFileInfo.isFile())
        {
            return false;
        }

        const QString cacheKeyText = QStringLiteral("%1|%2|%3")
            .arg(QDir::toNativeSeparators(normalizedPathText).toLower())
            .arg(targetFileInfo.lastModified().toMSecsSinceEpoch())
            .arg(targetFileInfo.size());

        {
            QMutexLocker cacheLocker(&signatureCacheMutex());
            const QHash<QString, bool>::const_iterator cachedIterator =
                signatureCacheMap().constFind(cacheKeyText);
            if (cachedIterator != signatureCacheMap().constEnd())
            {
                return cachedIterator.value();
            }
        }

        const bool trustedByWindows = verifyFileTrustByWinTrust(normalizedPathText);

        {
            QMutexLocker cacheLocker(&signatureCacheMutex());
            if (signatureCacheMap().size() >= kSignatureCacheEntryLimit)
            {
                signatureCacheMap().clear();
            }
            signatureCacheMap().insert(cacheKeyText, trustedByWindows);
        }
        return trustedByWindows;
    }

    // queryFailureCommandTextByServiceName reads failure-action command via ks::service.
    // Input: serviceNameText is the SCM short name from the UI cache.
    // Processing: the reusable layer owns QueryServiceConfig2W and string ownership.
    // Return: command text, or empty when missing/unreadable.
    QString queryFailureCommandTextByServiceName(const QString& serviceNameText)
    {
        ks::service::FailureSettings settings;
        if (!ks::service::QueryServiceFailureSettings(serviceNameText.toStdWString(), &settings))
        {
            return QString();
        }
        return QString::fromStdWString(settings.command).trimmed();
    }

    // queryServiceDllPathFromRegistry reads Parameters\ServiceDll.
    // Input: serviceNameText is the SCM short name.
    // Processing: this remains registry access, not SCM access, so it stays in UI helper scope.
    // Return: expanded native path or an empty string when absent.
    QString queryServiceDllPathFromRegistry(const QString& serviceNameText)
    {
        const QString registryPathText = QStringLiteral(
            "SYSTEM\\CurrentControlSet\\Services\\%1\\Parameters").arg(serviceNameText.trimmed());
        HKEY openedKey = nullptr;
        const LONG openResult = ::RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            reinterpret_cast<LPCWSTR>(registryPathText.utf16()),
            0,
            KEY_READ,
            &openedKey);
        if (openResult != ERROR_SUCCESS || openedKey == nullptr)
        {
            return QString();
        }

        DWORD valueType = 0;
        DWORD requiredBytes = 0;
        LONG queryResult = ::RegQueryValueExW(openedKey, L"ServiceDll", nullptr, &valueType, nullptr, &requiredBytes);
        if (queryResult != ERROR_SUCCESS || requiredBytes == 0 || (valueType != REG_EXPAND_SZ && valueType != REG_SZ))
        {
            ::RegCloseKey(openedKey);
            return QString();
        }

        std::vector<wchar_t> valueBuffer((requiredBytes / sizeof(wchar_t)) + 2, L'\0');
        queryResult = ::RegQueryValueExW(
            openedKey,
            L"ServiceDll",
            nullptr,
            &valueType,
            reinterpret_cast<LPBYTE>(valueBuffer.data()),
            &requiredBytes);
        ::RegCloseKey(openedKey);
        if (queryResult != ERROR_SUCCESS)
        {
            return QString();
        }

        QString rawPathText = QString::fromWCharArray(valueBuffer.data()).trimmed();
        if (rawPathText.isEmpty())
        {
            return QString();
        }

        wchar_t expandedPathBuffer[MAX_PATH * 4] = {};
        const DWORD expandedPathBufferCount =
            static_cast<DWORD>(sizeof(expandedPathBuffer) / sizeof(expandedPathBuffer[0]));
        const DWORD expandedLength = ::ExpandEnvironmentStringsW(
            reinterpret_cast<LPCWSTR>(rawPathText.utf16()),
            expandedPathBuffer,
            expandedPathBufferCount);
        if (expandedLength > 0 && expandedLength < expandedPathBufferCount)
        {
            rawPathText = QString::fromWCharArray(expandedPathBuffer).trimmed();
        }

        return QDir::toNativeSeparators(rawPathText);
    }

    // evaluateRiskTagList generates UI risk tags from an already-built ServiceEntry.
    // Input: entry contains normalized path/account/config fields.
    // Processing: combines file signature, ServiceDll, account, autostart, description and failure command checks.
    // Return: de-duplicated risk labels for the table and detail panes.
    QStringList evaluateRiskTagList(const ServiceDock::ServiceEntry& entry)
    {
        QStringList riskTagList;

        const QFileInfo imageFileInfo(entry.imagePathText);
        if (entry.imagePathText.trimmed().isEmpty() || !imageFileInfo.exists())
        {
            riskTagList.push_back(QStringLiteral("文件不存在"));
        }
        else if (!isFileTrustedByWindows(entry.imagePathText))
        {
            riskTagList.push_back(QStringLiteral("无签名"));
        }

        if ((entry.serviceTypeValue & SERVICE_WIN32_SHARE_PROCESS) != 0)
        {
            if (entry.serviceDllPathText.trimmed().isEmpty())
            {
                riskTagList.push_back(QStringLiteral("ServiceDll缺失"));
            }
            else if (!QFileInfo::exists(entry.serviceDllPathText))
            {
                riskTagList.push_back(QStringLiteral("ServiceDll不存在"));
            }
        }

        const QString accountLowerText = entry.accountText.trimmed().toLower();
        if (!accountLowerText.isEmpty()
            && accountLowerText != QStringLiteral("localsystem")
            && accountLowerText != QStringLiteral("nt authority\\localsystem")
            && accountLowerText != QStringLiteral("nt authority\\localservice")
            && accountLowerText != QStringLiteral("localservice")
            && accountLowerText != QStringLiteral("nt authority\\networkservice")
            && accountLowerText != QStringLiteral("networkservice")
            && accountLowerText != QStringLiteral("n/a"))
        {
            riskTagList.push_back(QStringLiteral("异常账户"));
        }

        if (entry.startTypeValue == SERVICE_AUTO_START)
        {
            const QString imagePathLowerText = QDir::toNativeSeparators(entry.imagePathText).toLower();
            const bool underWindowsDirectory =
                imagePathLowerText.startsWith(QStringLiteral("c:\\windows\\"))
                || imagePathLowerText.startsWith(QStringLiteral("\\windows\\"));
            if (!underWindowsDirectory)
            {
                riskTagList.push_back(QStringLiteral("非微软自动启动"));
            }
        }

        if (entry.descriptionText.trimmed().isEmpty())
        {
            riskTagList.push_back(QStringLiteral("配置缺失"));
        }

        const QString failureCommandText = queryFailureCommandTextByServiceName(entry.serviceNameText).toLower();
        if (failureCommandText.contains(QStringLiteral("powershell"))
            || failureCommandText.contains(QStringLiteral("cmd.exe"))
            || failureCommandText.contains(QStringLiteral("wscript"))
            || failureCommandText.contains(QStringLiteral("cscript"))
            || failureCommandText.contains(QStringLiteral("rundll32")))
        {
            riskTagList.push_back(QStringLiteral("可疑失败命令"));
        }

        riskTagList.removeDuplicates();
        return riskTagList;
    }

    // buildServiceEntryFromRecord converts a Qt-free ks::service record into the UI cache row.
    // Input: serviceRecord is produced by ks::service enumeration/query.
    // Processing: this function only formats text and derives UI-only risk fields.
    // Return: true when a usable row is produced; strict mode fails if config is missing.
    bool buildServiceEntryFromRecord(
        const ks::service::ServiceRecord& serviceRecord,
        ServiceDock::ServiceEntry* entryOut,
        QString* errorTextOut,
        const bool strictConfig)
    {
        if (entryOut == nullptr || serviceRecord.serviceName.empty())
        {
            if (errorTextOut != nullptr)
            {
                *errorTextOut = QStringLiteral("服务记录参数无效");
            }
            return false;
        }

        ServiceDock::ServiceEntry entry;
        entry.serviceNameText = QString::fromStdWString(serviceRecord.serviceName).trimmed();
        entry.displayNameText = QString::fromStdWString(serviceRecord.displayName).trimmed();
        if (entry.displayNameText.isEmpty())
        {
            entry.displayNameText = entry.serviceNameText;
        }

        entry.currentState = serviceRecord.status.currentState;
        entry.stateText = serviceStateToText(entry.currentState);
        entry.controlsAccepted = serviceRecord.status.controlsAccepted;
        entry.processId = serviceRecord.status.processId;
        entry.serviceTypeValue = serviceRecord.status.serviceType;
        entry.serviceTypeText = serviceTypeToText(entry.serviceTypeValue);
        entry.accountText = QStringLiteral("N/A");
        entry.errorControlText = QStringLiteral("未知");
        entry.startTypeText = QStringLiteral("未知");

        if (!serviceRecord.hasConfig)
        {
            const QString errorText = QString::fromUtf8(serviceRecord.configErrorText.c_str());
            if (strictConfig)
            {
                if (errorTextOut != nullptr)
                {
                    *errorTextOut = errorText.isEmpty() ? QStringLiteral("读取服务配置失败") : errorText;
                }
                return false;
            }

            entry.descriptionText = QStringLiteral("读取服务配置失败：%1")
                .arg(errorText.isEmpty() ? QStringLiteral("未知错误") : errorText);
            entry.serviceDllPathText = queryServiceDllPathFromRegistry(entry.serviceNameText);
            entry.riskTagList = evaluateRiskTagList(entry);
            entry.riskSummaryText = entry.riskTagList.isEmpty()
                ? QStringLiteral("低")
                : entry.riskTagList.join(QStringLiteral(" | "));
            entry.hasRisk = !entry.riskTagList.isEmpty();
            *entryOut = std::move(entry);
            return true;
        }

        entry.descriptionText = QString::fromStdWString(serviceRecord.description).trimmed();
        entry.commandLineText = QString::fromStdWString(serviceRecord.config.binaryPath).trimmed();
        entry.imagePathText = normalizeServiceImagePath(entry.commandLineText);
        entry.accountText = serviceRecord.config.accountName.empty()
            ? QStringLiteral("N/A")
            : QString::fromStdWString(serviceRecord.config.accountName).trimmed();
        entry.startTypeValue = serviceRecord.config.startType;
        entry.serviceTypeValue = serviceRecord.config.serviceType;
        entry.errorControlValue = serviceRecord.config.errorControl;
        entry.serviceTypeText = serviceTypeToText(entry.serviceTypeValue);
        entry.errorControlText = errorControlToText(entry.errorControlValue);
        entry.serviceDllPathText = queryServiceDllPathFromRegistry(entry.serviceNameText);
        entry.delayedAutoStart = (entry.startTypeValue == SERVICE_AUTO_START) && serviceRecord.config.delayedAutoStart;
        entry.startTypeText = startTypeToText(entry.startTypeValue, entry.delayedAutoStart);
        entry.riskTagList = evaluateRiskTagList(entry);
        entry.riskSummaryText = entry.riskTagList.isEmpty()
            ? QStringLiteral("低")
            : entry.riskTagList.join(QStringLiteral(" | "));
        entry.hasRisk = !entry.riskTagList.isEmpty();

        *entryOut = std::move(entry);
        return true;
    }
}

void ServiceDock::enumerateServiceList(
    std::vector<ServiceEntry>* serviceListOut,
    QString* errorTextOut) const
{
    if (serviceListOut == nullptr)
    {
        if (errorTextOut != nullptr)
        {
            *errorTextOut = QStringLiteral("输出容器为空");
        }
        return;
    }

    serviceListOut->clear();

    std::vector<ks::service::ServiceRecord> serviceRecordList;
    std::string errorText;
    if (!ks::service::EnumerateServiceRecords(
        SERVICE_WIN32_OWN_PROCESS | SERVICE_WIN32_SHARE_PROCESS,
        SERVICE_STATE_ALL,
        &serviceRecordList,
        &errorText))
    {
        if (errorTextOut != nullptr)
        {
            *errorTextOut = QStringLiteral("枚举服务失败：%1").arg(QString::fromUtf8(errorText.c_str()));
        }
        return;
    }

    serviceListOut->reserve(serviceRecordList.size());
    for (const ks::service::ServiceRecord& serviceRecord : serviceRecordList)
    {
        ServiceEntry serviceEntry;
        QString buildErrorText;
        if (buildServiceEntryFromRecord(serviceRecord, &serviceEntry, &buildErrorText, false))
        {
            serviceListOut->push_back(std::move(serviceEntry));
        }
    }
}

namespace service_dock_detail
{
    // querySingleServiceSnapshot 作用：
    // - 采集单个服务的完整快照（状态 + 配置 + ServiceDll + 风险标签）；
    // - 全程只依赖 ks::service 与 Win32，不触碰任何 QWidget，可在后台线程调用。
    // 入参：serviceNameText 为服务短名；entryOut 接收快照；errorTextOut 接收错误文本。
    // 返回：采集成功返回 true；配置读取失败按严格模式返回 false。
    // 说明：本函数声明未放进共享头 ServiceDock.Internal.h（本次改动不扩展该头），
    //       调用方 ServiceDock.Actions.cpp 就地重复声明同一原型。
    bool querySingleServiceSnapshot(
        const QString& serviceNameText,
        ServiceDock::ServiceEntry* entryOut,
        QString* errorTextOut)
    {
        if (entryOut == nullptr || serviceNameText.trimmed().isEmpty())
        {
            if (errorTextOut != nullptr)
            {
                *errorTextOut = QStringLiteral("querySingleServiceByName 参数无效");
            }
            return false;
        }

        ks::service::ServiceRecord serviceRecord;
        std::string errorText;
        if (!ks::service::QueryServiceRecord(
            serviceNameText.trimmed().toStdWString(),
            &serviceRecord,
            &errorText))
        {
            if (errorTextOut != nullptr)
            {
                *errorTextOut = QStringLiteral("查询服务失败：%1").arg(QString::fromUtf8(errorText.c_str()));
            }
            return false;
        }

        return buildServiceEntryFromRecord(serviceRecord, entryOut, errorTextOut, true);
    }
}

bool ServiceDock::querySingleServiceByName(
    const QString& serviceNameText,
    ServiceEntry* entryOut,
    QString* errorTextOut) const
{
    // 采集逻辑已下沉为可在任意线程复用的自由函数，这里只做转发。
    return service_dock_detail::querySingleServiceSnapshot(serviceNameText, entryOut, errorTextOut);
}
