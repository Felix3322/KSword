#pragma once

// ============================================================
// ProcessAffinityPersistence.h
// 作用：
// - 将用户明确保存的进程 CPU 亲和性写入当前用户注册表；
// - 使用版本化 REG_BINARY 保存 processor group/逻辑处理器坐标；
// - 兼容读取旧 REG_QWORD 位图，并在成功恢复后自动迁移。
// ============================================================

#include "ProcessAffinityUtils.h"

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <set>
#include <string>
#include <vector>

namespace ks::process
{
    inline constexpr wchar_t kProcessAffinityRegistrySubKey[] =
        L"Software\\Ksword\\ProcessAffinity";

    // utf8ToWide 作用：把进程完整 UTF-8 路径转换为注册表值名。
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

    // loadPersistedProcessAffinityRule 作用：
    // - 读取当前版本 REG_BINARY；
    // - 对旧 REG_QWORD 按 legacyProcessorGroupHint 转换为稳定坐标，但暂不写回。
    inline bool loadPersistedProcessAffinityRule(
        const std::string& imagePath,
        ProcessAffinityRule* const affinityRuleOut,
        bool* const foundOut,
        std::string* const detailTextOut,
        const std::uint16_t legacyProcessorGroupHint = 0U)
    {
        if (affinityRuleOut == nullptr || foundOut == nullptr)
        {
            if (detailTextOut != nullptr)
            {
                *detailTextOut = "invalid persisted affinity read output";
            }
            return false;
        }

        *affinityRuleOut = ProcessAffinityRule{};
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
                *detailTextOut =
                    "RegOpenKeyExW failed(" +
                    std::to_string(openResult) + ")";
            }
            return false;
        }

        DWORD valueType = 0U;
        DWORD storedSize = 0U;
        LONG queryResult = ::RegQueryValueExW(
            registryKey,
            valueName.c_str(),
            nullptr,
            &valueType,
            nullptr,
            &storedSize);
        if (queryResult == ERROR_FILE_NOT_FOUND)
        {
            ::RegCloseKey(registryKey);
            if (detailTextOut != nullptr)
            {
                detailTextOut->clear();
            }
            return true;
        }
        if (queryResult != ERROR_SUCCESS)
        {
            ::RegCloseKey(registryKey);
            if (detailTextOut != nullptr)
            {
                *detailTextOut =
                    "RegQueryValueExW(size) failed(" +
                    std::to_string(queryResult) + ")";
            }
            return false;
        }

        const DWORD maximumStoredSize = static_cast<DWORD>(
            kProcessAffinityRuleHeaderSize +
            kProcessAffinityRuleMaximumProcessorCount *
                kProcessAffinityRuleCoordinateSize);
        if ((valueType == REG_QWORD && storedSize != sizeof(std::uint64_t)) ||
            (valueType == REG_BINARY &&
                (storedSize < kProcessAffinityRuleHeaderSize ||
                    storedSize > maximumStoredSize)) ||
            (valueType != REG_QWORD && valueType != REG_BINARY))
        {
            ::RegCloseKey(registryKey);
            if (detailTextOut != nullptr)
            {
                *detailTextOut =
                    "persisted affinity value type or size is invalid";
            }
            return false;
        }

        std::vector<std::uint8_t> storedBytes(storedSize, 0U);
        DWORD readSize = storedSize;
        queryResult = ::RegQueryValueExW(
            registryKey,
            valueName.c_str(),
            nullptr,
            &valueType,
            storedBytes.data(),
            &readSize);
        ::RegCloseKey(registryKey);
        if (queryResult != ERROR_SUCCESS || readSize != storedSize)
        {
            if (detailTextOut != nullptr)
            {
                *detailTextOut =
                    "RegQueryValueExW(data) failed(" +
                    std::to_string(queryResult) + ")";
            }
            return false;
        }

        ProcessAffinityRule affinityRule;
        if (valueType == REG_QWORD)
        {
            std::uint64_t legacyMask = 0U;
            std::memcpy(
                &legacyMask,
                storedBytes.data(),
                sizeof(legacyMask));
            if (legacyMask == 0U)
            {
                if (detailTextOut != nullptr)
                {
                    *detailTextOut =
                        "persisted legacy affinity mask is empty";
                }
                return false;
            }
            affinityRule = affinityRuleFromLegacyMask(
                legacyMask,
                legacyProcessorGroupHint);
        }
        else if (!deserializeProcessAffinityRule(
                     storedBytes,
                     &affinityRule))
        {
            if (detailTextOut != nullptr)
            {
                *detailTextOut =
                    "persisted affinity rule is invalid or unsupported";
            }
            return false;
        }

        *affinityRuleOut = std::move(affinityRule);
        *foundOut = true;
        if (detailTextOut != nullptr)
        {
            detailTextOut->clear();
        }
        return true;
    }

    // savePersistedProcessAffinityRule 作用：以当前版本 REG_BINARY 原子替换单个路径规则。
    inline bool savePersistedProcessAffinityRule(
        const std::string& imagePath,
        const ProcessAffinityRule& affinityRule,
        std::string* const detailTextOut)
    {
        const std::wstring valueName = utf8ToWide(imagePath);
        std::vector<std::uint8_t> storedBytes;
        if (valueName.empty() ||
            !serializeProcessAffinityRule(affinityRule, &storedBytes))
        {
            if (detailTextOut != nullptr)
            {
                *detailTextOut =
                    "process image path or affinity rule is invalid";
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
                *detailTextOut =
                    "RegCreateKeyExW failed(" +
                    std::to_string(createResult) + ")";
            }
            return false;
        }

        const LONG setResult = ::RegSetValueExW(
            registryKey,
            valueName.c_str(),
            0U,
            REG_BINARY,
            storedBytes.data(),
            static_cast<DWORD>(storedBytes.size()));
        ::RegCloseKey(registryKey);
        if (setResult != ERROR_SUCCESS)
        {
            if (detailTextOut != nullptr)
            {
                *detailTextOut =
                    "RegSetValueExW failed(" +
                    std::to_string(setResult) + ")";
            }
            return false;
        }

        if (detailTextOut != nullptr)
        {
            detailTextOut->clear();
        }
        return true;
    }

    // removePersistedProcessAffinityRule 作用：移除指定完整路径的 Ksword 私有规则。
    inline bool removePersistedProcessAffinityRule(
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
                *detailTextOut =
                    "RegOpenKeyExW failed(" +
                    std::to_string(openResult) + ")";
            }
            return false;
        }

        const LONG deleteResult =
            ::RegDeleteValueW(registryKey, valueName.c_str());
        ::RegCloseKey(registryKey);
        if (deleteResult != ERROR_SUCCESS &&
            deleteResult != ERROR_FILE_NOT_FOUND)
        {
            if (detailTextOut != nullptr)
            {
                *detailTextOut =
                    "RegDeleteValueW failed(" +
                    std::to_string(deleteResult) + ")";
            }
            return false;
        }

        if (detailTextOut != nullptr)
        {
            detailTextOut->clear();
        }
        return true;
    }

    // inferLegacyAffinityGroup 作用：
    // - 旧 QWORD 没有 group 字段；
    // - 当前选择只落在一个 group 时使用该 group，否则按历史默认语义使用 group 0。
    inline std::uint16_t inferLegacyAffinityGroup(
        const ProcessAffinitySnapshot& snapshot)
    {
        std::set<std::uint16_t> selectedGroups;
        for (const LogicalProcessorState& processor : snapshot.processors)
        {
            if (processor.available && processor.selected)
            {
                selectedGroups.insert(processor.coordinate.group);
            }
        }
        return selectedGroups.size() == 1U
            ? *selectedGroups.begin()
            : 0U;
    }

    // filterAffinityRuleForTopology 作用：过滤当前机器不存在的坐标，防止恢复为空选择。
    inline bool filterAffinityRuleForTopology(
        const ProcessAffinityRule& sourceRule,
        const ProcessAffinitySnapshot& snapshot,
        ProcessAffinityRule* const applicableRuleOut,
        std::size_t* const missingCoordinateCountOut)
    {
        if (applicableRuleOut == nullptr)
        {
            return false;
        }
        if (missingCoordinateCountOut != nullptr)
        {
            *missingCoordinateCountOut = 0U;
        }

        ProcessAffinityRule applicableRule = sourceRule;
        applicableRule.migratedFromLegacyQword = false;
        if (!applicableRule.selectAllAvailable)
        {
            normalizeLogicalProcessorCoordinates(
                &applicableRule.processors);
            std::size_t missingCoordinateCount = 0U;
            for (const LogicalProcessorCoordinate& coordinate :
                 applicableRule.processors)
            {
                const bool coordinateAvailable = std::any_of(
                    snapshot.processors.begin(),
                    snapshot.processors.end(),
                    [&coordinate](const LogicalProcessorState& processor)
                    {
                        return processor.available &&
                            processor.coordinate == coordinate;
                    });
                if (!coordinateAvailable)
                {
                    ++missingCoordinateCount;
                }
            }
            if (missingCoordinateCountOut != nullptr)
            {
                *missingCoordinateCountOut = missingCoordinateCount;
            }
            // 不静默缩减规则：拓扑变化后的子集可能仅剩一个处理器并意外限死目标。
            if (applicableRule.processors.empty() ||
                missingCoordinateCount != 0U)
            {
                return false;
            }
        }
        *applicableRuleOut = std::move(applicableRule);
        return true;
    }

    // restorePersistedProcessAffinityRule 作用：
    // - 将稳定坐标映射到当前启动的 CPU Set ID 并恢复；
    // - 旧 QWORD 在成功应用后自动升级为版本化 REG_BINARY。
    inline bool restorePersistedProcessAffinityRule(
        const DWORD processId,
        const std::string& imagePath,
        bool* const ruleFoundOut,
        std::string* const detailTextOut)
    {
        if (ruleFoundOut != nullptr)
        {
            *ruleFoundOut = false;
        }

        ProcessAffinityRule storedRule;
        bool ruleFound = false;
        if (!loadPersistedProcessAffinityRule(
                imagePath,
                &storedRule,
                &ruleFound,
                detailTextOut))
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

        ProcessAffinitySnapshot snapshot;
        if (!QueryProcessAffinityState(
                processId,
                &snapshot,
                detailTextOut))
        {
            return false;
        }

        if (storedRule.migratedFromLegacyQword)
        {
            const std::uint16_t legacyGroup =
                inferLegacyAffinityGroup(snapshot);
            for (LogicalProcessorCoordinate& coordinate :
                 storedRule.processors)
            {
                coordinate.group = legacyGroup;
            }
        }

        ProcessAffinityRule applicableRule;
        std::size_t missingCoordinateCount = 0U;
        if (!filterAffinityRuleForTopology(
                storedRule,
                snapshot,
                &applicableRule,
                &missingCoordinateCount))
        {
            if (detailTextOut != nullptr)
            {
                *detailTextOut = missingCoordinateCount == 0U
                    ? "saved affinity has no logical processor in the current topology"
                    : "saved affinity topology changed; refusing partial restore because " +
                        std::to_string(missingCoordinateCount) +
                        " processor coordinate(s) are unavailable";
            }
            return false;
        }

        if (!SetProcessAffinityRuleByPid(
                processId,
                applicableRule,
                detailTextOut))
        {
            return false;
        }

        if (storedRule.migratedFromLegacyQword &&
            !savePersistedProcessAffinityRule(
                imagePath,
                applicableRule,
                detailTextOut))
        {
            return false;
        }
        return true;
    }
}
