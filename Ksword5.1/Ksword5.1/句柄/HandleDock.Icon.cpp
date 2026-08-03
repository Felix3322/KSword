#include "HandleDock.h"

// ============================================================
// HandleDock.Icon.cpp
// 作用：
// - 承载句柄模块中“进程图标解析与缓存”逻辑；
// - 缓存严格绑定快照行的 PID + 创建时间，不把复用 PID 的进程当作原实例；
// - 无法验证实例时宁可显示默认图标，也不显示错误的进程路径或图标。
// ============================================================

#include <QFileIconProvider>
#include <QFileInfo>

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>

#include <array>

namespace
{
    QString buildProcessInstanceCacheKey(
        const std::uint32_t processId,
        const std::uint64_t processCreationTime)
    {
        if (processId == 0U || processCreationTime == 0U)
        {
            return {};
        }
        return QStringLiteral("%1|%2")
            .arg(static_cast<qulonglong>(processId))
            .arg(static_cast<qulonglong>(processCreationTime));
    }

    std::uint64_t fileTimeToUint64(const FILETIME& fileTimeValue)
    {
        ULARGE_INTEGER value{};
        value.LowPart = fileTimeValue.dwLowDateTime;
        value.HighPart = fileTimeValue.dwHighDateTime;
        return value.QuadPart;
    }

    QString queryProcessImagePathIfIdentityMatches(
        const std::uint32_t processId,
        const std::uint64_t expectedCreationTime)
    {
        if (processId == 0U || expectedCreationTime == 0U)
        {
            return {};
        }

        const HANDLE processHandle = ::OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION,
            FALSE,
            static_cast<DWORD>(processId));
        if (processHandle == nullptr)
        {
            return {};
        }

        FILETIME creationTime{};
        FILETIME exitTime{};
        FILETIME kernelTime{};
        FILETIME userTime{};
        const bool identityMatches =
            ::GetProcessTimes(
                processHandle,
                &creationTime,
                &exitTime,
                &kernelTime,
                &userTime) != FALSE
            && fileTimeToUint64(creationTime) == expectedCreationTime;
        if (!identityMatches)
        {
            ::CloseHandle(processHandle);
            return {};
        }

        std::array<wchar_t, 32768> imagePathBuffer{};
        DWORD imagePathLength = static_cast<DWORD>(imagePathBuffer.size());
        QString processImagePath;
        if (::QueryFullProcessImageNameW(
            processHandle,
            0,
            imagePathBuffer.data(),
            &imagePathLength) != FALSE
            && imagePathLength > 0U)
        {
            processImagePath = QString::fromWCharArray(
                imagePathBuffer.data(),
                static_cast<int>(imagePathLength));
        }
        ::CloseHandle(processHandle);
        return processImagePath;
    }
}

QIcon HandleDock::resolveProcessIconForRow(const HandleRow& row)
{
    const QString cacheKey =
        buildProcessInstanceCacheKey(row.processId, row.processCreationTime);
    if (cacheKey.isEmpty())
    {
        return QIcon(QStringLiteral(":/Icon/process_main.svg"));
    }

    const auto iconIt = m_processIconCacheByIdentity.constFind(cacheKey);
    if (iconIt != m_processIconCacheByIdentity.constEnd())
    {
        return iconIt.value();
    }

    const QString processImagePath =
        queryProcessImagePathCached(row.processId, row.processCreationTime);
    QIcon processIcon;
    if (!processImagePath.trimmed().isEmpty())
    {
        processIcon = QIcon(processImagePath);
        if (processIcon.isNull())
        {
            QFileIconProvider iconProvider;
            processIcon = iconProvider.icon(QFileInfo(processImagePath));
        }
    }

    if (processIcon.isNull())
    {
        processIcon = QIcon(QStringLiteral(":/Icon/process_main.svg"));
    }

    m_processIconCacheByIdentity.insert(cacheKey, processIcon);
    return processIcon;
}

QString HandleDock::queryProcessImagePathCached(
    const std::uint32_t processId,
    const std::uint64_t expectedCreationTime)
{
    const QString cacheKey =
        buildProcessInstanceCacheKey(processId, expectedCreationTime);
    if (cacheKey.isEmpty())
    {
        return {};
    }

    const auto pathIt = m_processImagePathCacheByIdentity.constFind(cacheKey);
    if (pathIt != m_processImagePathCacheByIdentity.constEnd())
    {
        return pathIt.value();
    }

    const QString processImagePath =
        queryProcessImagePathIfIdentityMatches(processId, expectedCreationTime);
    if (!processImagePath.isEmpty())
    {
        m_processImagePathCacheByIdentity.insert(cacheKey, processImagePath);
    }
    return processImagePath;
}
