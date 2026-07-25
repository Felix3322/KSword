#pragma once

// ============================================================
// ProcessAffinityPersistence.h
// 作用：
// - 将用户明确保存的进程 CPU 亲和性写入当前用户注册表；
// - 以完整可执行文件路径区分同名程序，并在 ProcessDock 发现新实例时恢复；
// - 注册表只保存 Ksword 自己的规则，不修改系统 IFEO/PerfOptions 配置。
// ============================================================

#include "ProcessAffinityUtils.h"

#include <cstdint>
#include <limits>
#include <string>

namespace ks::process
{
    inline constexpr wchar_t kProcessAffinityRegistrySubKey[] =
        L"Software\\Ksword\\ProcessAffinity";

    inline std::wstring utf8ToWide(const std::string& text)
    {
        if (text.empty())
        {
            return {};
        }

        const int characterCount = ::MultiByteToWideChar(
            CP_UTF8,
            MB_ERR_INVALID_CHARS,
            text.data(),
            static_cast<int>(text.size()),
            nullptr,
            0);
        if (characterCount <= 0)
        {
            return {};
        }

        std::wstring result(static_cast<std::size_t>(characterCount), L'\0');
        if (::MultiByteToWideChar(
                CP_UTF8,
                MB_ERR_INVALID_CHARS,
                text.data(),
                static_cast<int>(text.size()),
                result.data(),
                characterCount) != characterCount)
        {
            return {};
        }
        return result;
    }

    inline bool loadPersistedProcessAffinityMask(
        const std::string& imagePath,
        std::uint64_t* const affinityMaskOut,
        bool* const foundOut,
        std::string* const detailTextOut)
    {
        if (affinityMaskOut == nullptr || foundOut == nullptr)
        {
            if (detailTextOut != nullptr)
            {
                *detailTextOut = "invalid persisted affinity read output";
            }
            return false;
        }

        *affinityMaskOut = 0U;
        *foundOut = false;
        const std::wstring valueName = utf8ToWide(imagePath);
        if (valueName.empty())
        {
            if (detailTextOut != nullptr)
            {
                *detailTextOut = "process image path is unavailable";
            }
            return false;
        }

        HKEY registryKey = nullptr;
        const LONG openResult = ::RegOpenKeyExW(
            HKEY_CURRENT_USER,
            kProcessAffinityRegistrySubKey,
            0U,
            KEY_QUERY_VALUE,
            &registryKey);
        if (openResult == ERROR_FILE_NOT_FOUND)
        {
            if (detailTextOut != nullptr)
            {
                detailTextOut->clear();
            }
            return true;
        }
        if (openResult != ERROR_SUCCESS)
        {
            if (detailTextOut != nullptr)
            {
                *detailTextOut = "RegOpenKeyExW failed(" + std::to_string(openResult) + ")";
            }
            return false;
        }

        DWORD valueType = 0U;
        std::uint64_t storedMask = 0U;
        DWORD storedSize = sizeof(storedMask);
        const LONG queryResult = ::RegQueryValueExW(
            registryKey,
            valueName.c_str(),
            nullptr,
            &valueType,
            reinterpret_cast<LPBYTE>(&storedMask),
            &storedSize);
        ::RegCloseKey(registryKey);
        if (queryResult == ERROR_FILE_NOT_FOUND)
        {
            if (detailTextOut != nullptr)
            {
                detailTextOut->clear();
            }
            return true;
        }
        if (queryResult != ERROR_SUCCESS || valueType != REG_QWORD || storedSize != sizeof(storedMask) || storedMask == 0U)
        {
            if (detailTextOut != nullptr)
            {
                *detailTextOut = queryResult != ERROR_SUCCESS
                    ? "RegQueryValueExW failed(" + std::to_string(queryResult) + ")"
                    : "persisted affinity value is invalid";
            }
            return false;
        }

        *affinityMaskOut = storedMask;
        *foundOut = true;
        if (detailTextOut != nullptr)
        {
            detailTextOut->clear();
        }
        return true;
    }

    inline bool savePersistedProcessAffinityMask(
        const std::string& imagePath,
        const std::uint64_t affinityMask,
        std::string* const detailTextOut)
    {
        const std::wstring valueName = utf8ToWide(imagePath);
        if (valueName.empty() || affinityMask == 0U)
        {
            if (detailTextOut != nullptr)
            {
                *detailTextOut = "process image path or affinity mask is invalid";
            }
            return false;
        }

        HKEY registryKey = nullptr;
        const LONG createResult = ::RegCreateKeyExW(
            HKEY_CURRENT_USER,
            kProcessAffinityRegistrySubKey,
            0U,
            nullptr,
            REG_OPTION_NON_VOLATILE,
            KEY_SET_VALUE,
            nullptr,
            &registryKey,
            nullptr);
        if (createResult != ERROR_SUCCESS)
        {
            if (detailTextOut != nullptr)
            {
                *detailTextOut = "RegCreateKeyExW failed(" + std::to_string(createResult) + ")";
            }
            return false;
        }

        const LONG setResult = ::RegSetValueExW(
            registryKey,
            valueName.c_str(),
            0U,
            REG_QWORD,
            reinterpret_cast<const BYTE*>(&affinityMask),
            sizeof(affinityMask));
        ::RegCloseKey(registryKey);
        if (setResult != ERROR_SUCCESS)
        {
            if (detailTextOut != nullptr)
            {
                *detailTextOut = "RegSetValueExW failed(" + std::to_string(setResult) + ")";
            }
            return false;
        }

        if (detailTextOut != nullptr)
        {
            detailTextOut->clear();
        }
        return true;
    }

    inline bool removePersistedProcessAffinityMask(
        const std::string& imagePath,
        std::string* const detailTextOut)
    {
        const std::wstring valueName = utf8ToWide(imagePath);
        if (valueName.empty())
        {
            if (detailTextOut != nullptr)
            {
                *detailTextOut = "process image path is unavailable";
            }
            return false;
        }

        HKEY registryKey = nullptr;
        const LONG openResult = ::RegOpenKeyExW(
            HKEY_CURRENT_USER,
            kProcessAffinityRegistrySubKey,
            0U,
            KEY_SET_VALUE,
            &registryKey);
        if (openResult == ERROR_FILE_NOT_FOUND)
        {
            if (detailTextOut != nullptr)
            {
                detailTextOut->clear();
            }
            return true;
        }
        if (openResult != ERROR_SUCCESS)
        {
            if (detailTextOut != nullptr)
            {
                *detailTextOut = "RegOpenKeyExW failed(" + std::to_string(openResult) + ")";
            }
            return false;
        }

        const LONG deleteResult = ::RegDeleteValueW(registryKey, valueName.c_str());
        ::RegCloseKey(registryKey);
        if (deleteResult != ERROR_SUCCESS && deleteResult != ERROR_FILE_NOT_FOUND)
        {
            if (detailTextOut != nullptr)
            {
                *detailTextOut = "RegDeleteValueW failed(" + std::to_string(deleteResult) + ")";
            }
            return false;
        }

        if (detailTextOut != nullptr)
        {
            detailTextOut->clear();
        }
        return true;
    }

    inline bool restorePersistedProcessAffinityMask(
        const DWORD processId,
        const std::string& imagePath,
        bool* const ruleFoundOut,
        std::string* const detailTextOut)
    {
        if (ruleFoundOut != nullptr)
        {
            *ruleFoundOut = false;
        }

        std::uint64_t storedMask = 0U;
        bool ruleFound = false;
        if (!loadPersistedProcessAffinityMask(imagePath, &storedMask, &ruleFound, detailTextOut))
        {
            return false;
        }
        if (ruleFoundOut != nullptr)
        {
            *ruleFoundOut = ruleFound;
        }
        if (!ruleFound)
        {
            return true;
        }

        ProcessAffinityMasks currentMasks;
        if (!QueryProcessAffinityMasks(processId, &currentMasks, detailTextOut))
        {
            return false;
        }

        const std::uint64_t applicableMask = storedMask & static_cast<std::uint64_t>(currentMasks.systemMask);
        if (applicableMask == 0U || applicableMask > static_cast<std::uint64_t>(std::numeric_limits<ULONG_PTR>::max()))
        {
            if (detailTextOut != nullptr)
            {
                *detailTextOut = "saved mask has no logical processor available in the current processor group";
            }
            return false;
        }
        return SetProcessAffinityMaskByPid(processId, static_cast<ULONG_PTR>(applicableMask), detailTextOut);
    }
}
