#pragma once

// ============================================================
// ProcessAffinityModel.h
// 作用：
// - 定义与 Windows CPU Set ID 解耦的 processor group/逻辑处理器坐标；
// - 提供版本化持久化数据的纯函数序列化、旧 QWORD 迁移与拓扑重映射；
// - 不依赖 Qt 或 Windows API，便于使用临时 harness 验证多组行为。
// ============================================================

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <string>
#include <utility>
#include <vector>

namespace ks::process
{
    inline constexpr std::uint16_t kProcessAffinityRuleVersion = 1U;
    inline constexpr std::uint32_t kProcessAffinityRuleMagic = 0x4641534BU; // 小端字节序为“KSAF”。
    inline constexpr std::uint16_t kProcessAffinityRuleSelectAllFlag = 0x0001U;
    inline constexpr std::size_t kProcessAffinityRuleHeaderSize = 12U;
    inline constexpr std::size_t kProcessAffinityRuleCoordinateSize = 4U;
    inline constexpr std::size_t kProcessAffinityRuleMaximumProcessorCount = 4096U;

    // LogicalProcessorCoordinate 作用：
    // - group 保存 Windows processor group；
    // - logicalIndex 保存该 group 内的逻辑处理器索引，跨重启不依赖临时 CPU Set ID。
    struct LogicalProcessorCoordinate
    {
        std::uint16_t group = 0U;
        std::uint16_t logicalIndex = 0U;
    };

    inline bool operator==(
        const LogicalProcessorCoordinate& left,
        const LogicalProcessorCoordinate& right)
    {
        return left.group == right.group &&
            left.logicalIndex == right.logicalIndex;
    }

    inline bool operator<(
        const LogicalProcessorCoordinate& left,
        const LogicalProcessorCoordinate& right)
    {
        return left.group < right.group ||
            (left.group == right.group && left.logicalIndex < right.logicalIndex);
    }

    // processorCoordinateAllowedByLegacyAffinity 作用：
    // - 计算 CPU Set 与可读单组/legacy 硬亲和性的实际交集；
    // - 没有硬约束时不削减 Win11 默认跨组进程的可用集合。
    inline bool processorCoordinateAllowedByLegacyAffinity(
        const LogicalProcessorCoordinate& coordinate,
        const bool legacyConstraintAvailable,
        const std::uint16_t legacyProcessorGroup,
        const std::uint64_t legacyProcessorMask)
    {
        if (!legacyConstraintAvailable)
        {
            return true;
        }
        return coordinate.group == legacyProcessorGroup &&
            coordinate.logicalIndex < 64U &&
            (legacyProcessorMask &
                (1ULL << coordinate.logicalIndex)) != 0U;
    }

    // LogicalProcessorState 作用：
    // - 描述一次运行时查询得到的 CPU Set 与稳定坐标映射；
    // - selected 表示当前进程默认 CPU Set/旧亲和性约束下是否选中该处理器。
    struct LogicalProcessorState
    {
        LogicalProcessorCoordinate coordinate;
        std::uint32_t cpuSetId = 0U;
        std::uint16_t coreIndex = 0U;
        std::uint8_t efficiencyClass = 0U;
        bool available = false;
        bool selected = false;
        bool parked = false;
        bool allocated = false;
        bool allocatedToTargetProcess = false;
        bool constrainedByHardAffinity = false;
        std::string topologyLabel;
    };

    // ProcessAffinitySnapshot 作用：承载 UI 与持久化层共享的一次进程亲和性快照。
    struct ProcessAffinitySnapshot
    {
        std::vector<LogicalProcessorState> processors;
        bool usesCpuSets = false;
        bool unrestricted = false;
    };

    // logicalProcessorGroupCount 作用：
    // - 统计当前 UI 实际展示的唯一 processor group 数量；
    // - 单组时允许省略重复的 Gx 前缀和分组标题，多组时仍保留无歧义身份。
    inline std::size_t logicalProcessorGroupCount(
        const std::vector<LogicalProcessorCoordinate>& coordinates)
    {
        std::vector<std::uint16_t> processorGroups;
        processorGroups.reserve(coordinates.size());
        for (const LogicalProcessorCoordinate& coordinate : coordinates)
        {
            processorGroups.push_back(coordinate.group);
        }
        std::sort(processorGroups.begin(), processorGroups.end());
        processorGroups.erase(
            std::unique(processorGroups.begin(), processorGroups.end()),
            processorGroups.end());
        return processorGroups.size();
    }

    inline std::size_t logicalProcessorGroupCount(
        const std::vector<LogicalProcessorState>& processors)
    {
        std::vector<LogicalProcessorCoordinate> coordinates;
        coordinates.reserve(processors.size());
        for (const LogicalProcessorState& processor : processors)
        {
            coordinates.push_back(processor.coordinate);
        }
        return logicalProcessorGroupCount(coordinates);
    }

    // processorDisplayIdentityText 作用：
    // - 日志与持久化继续使用完整 Gx:Ly 稳定身份；
    // - 只有 UI 已确认存在多个 processor group 时才显示 Gx，单组简化为 Ly。
    inline std::string processorDisplayIdentityText(
        const LogicalProcessorCoordinate& coordinate,
        const bool includeProcessorGroup)
    {
        const std::string logicalProcessorText =
            "L" + std::to_string(coordinate.logicalIndex);
        return includeProcessorGroup
            ? "G" + std::to_string(coordinate.group) + ":" +
                logicalProcessorText
            : logicalProcessorText;
    }

    // ProcessAffinityRule 作用：
    // - selectAllAvailable=true 表示清除进程默认 CPU Set 限制并跟随当前可用处理器；
    // - processors 保存显式选择时的稳定 group/index 坐标；
    // - migratedFromLegacyQword 仅用于本次读取后的迁移判断，不写入持久化字节。
    struct ProcessAffinityRule
    {
        std::uint16_t schemaVersion = kProcessAffinityRuleVersion;
        bool selectAllAvailable = false;
        std::vector<LogicalProcessorCoordinate> processors;
        bool migratedFromLegacyQword = false;
    };

    // normalizeLogicalProcessorCoordinates 作用：排序并去重坐标，保证 UI、持久化与比较结果稳定。
    inline void normalizeLogicalProcessorCoordinates(
        std::vector<LogicalProcessorCoordinate>* const coordinates)
    {
        if (coordinates == nullptr)
        {
            return;
        }
        std::sort(coordinates->begin(), coordinates->end());
        coordinates->erase(
            std::unique(coordinates->begin(), coordinates->end()),
            coordinates->end());
    }

    // containsLogicalProcessorCoordinate 作用：判断坐标列表是否包含指定 group/index。
    inline bool containsLogicalProcessorCoordinate(
        const std::vector<LogicalProcessorCoordinate>& coordinates,
        const LogicalProcessorCoordinate& coordinate)
    {
        return std::find(coordinates.begin(), coordinates.end(), coordinate) !=
            coordinates.end();
    }

    // selectAllCpuSetSelectionMatches 作用：
    // - selectAll 只表示清空进程默认 CPU Set 列表；
    // - processor group、线程亲和性和 Job 约束属于独立交集，不能要求快照变成全系统无限制。
    inline bool selectAllCpuSetSelectionMatches(
        const ProcessAffinityRule& rule,
        const std::vector<std::uint32_t>& defaultCpuSetIds)
    {
        return rule.selectAllAvailable &&
            defaultCpuSetIds.empty();
    }

    // affinityRuleFromSnapshot 作用：
    // - 将当前运行时快照转成可保存规则；
    // - 无限制状态保留“全部可用”语义，显式状态只保存已选中且可用的稳定坐标。
    inline ProcessAffinityRule affinityRuleFromSnapshot(
        const ProcessAffinitySnapshot& snapshot)
    {
        ProcessAffinityRule rule;
        rule.selectAllAvailable = snapshot.unrestricted;
        if (!rule.selectAllAvailable)
        {
            for (const LogicalProcessorState& processor : snapshot.processors)
            {
                if (processor.available && processor.selected)
                {
                    rule.processors.push_back(processor.coordinate);
                }
            }
            normalizeLogicalProcessorCoordinates(&rule.processors);
        }
        return rule;
    }

    // affinityRuleFromLegacyMask 作用：
    // - 把旧 REG_QWORD 的位图迁移为指定 processor group 内的稳定逻辑处理器坐标；
    // - 返回规则带 migratedFromLegacyQword 标志，供成功恢复后自动升级注册表格式。
    inline ProcessAffinityRule affinityRuleFromLegacyMask(
        const std::uint64_t legacyMask,
        const std::uint16_t processorGroup)
    {
        ProcessAffinityRule rule;
        rule.migratedFromLegacyQword = true;
        for (std::uint16_t logicalIndex = 0U; logicalIndex < 64U; ++logicalIndex)
        {
            const std::uint64_t processorBit = 1ULL << logicalIndex;
            if ((legacyMask & processorBit) != 0U)
            {
                rule.processors.push_back(
                    LogicalProcessorCoordinate{ processorGroup, logicalIndex });
            }
        }
        return rule;
    }

    // appendAffinityUnsigned 作用：按固定小端顺序向持久化缓冲写入无符号整数。
    inline void appendAffinityUnsigned(
        std::vector<std::uint8_t>* const bytes,
        const std::uint64_t value,
        const std::size_t byteCount)
    {
        if (bytes == nullptr)
        {
            return;
        }
        for (std::size_t byteIndex = 0U; byteIndex < byteCount; ++byteIndex)
        {
            bytes->push_back(static_cast<std::uint8_t>(
                (value >> (byteIndex * 8U)) & 0xFFU));
        }
    }

    // readAffinityUnsigned 作用：从固定小端缓冲读取无符号整数并推进偏移。
    inline bool readAffinityUnsigned(
        const std::vector<std::uint8_t>& bytes,
        std::size_t* const offset,
        const std::size_t byteCount,
        std::uint64_t* const valueOut)
    {
        if (offset == nullptr || valueOut == nullptr ||
            *offset > bytes.size() || byteCount > bytes.size() - *offset)
        {
            return false;
        }

        std::uint64_t value = 0U;
        for (std::size_t byteIndex = 0U; byteIndex < byteCount; ++byteIndex)
        {
            value |= static_cast<std::uint64_t>(bytes[*offset + byteIndex]) <<
                (byteIndex * 8U);
        }
        *offset += byteCount;
        *valueOut = value;
        return true;
    }

    // serializeProcessAffinityRule 作用：
    // - 将版本、标志和稳定坐标编码为 REG_BINARY 数据；
    // - 输入显式空选择、越界逻辑索引或过大列表时返回 false。
    inline bool serializeProcessAffinityRule(
        const ProcessAffinityRule& sourceRule,
        std::vector<std::uint8_t>* const bytesOut)
    {
        if (bytesOut == nullptr)
        {
            return false;
        }

        ProcessAffinityRule rule = sourceRule;
        normalizeLogicalProcessorCoordinates(&rule.processors);
        if (rule.selectAllAvailable)
        {
            // “全部可用”由标志完整表达，持久化时不携带无效坐标，保证字节表示唯一。
            rule.processors.clear();
        }
        if (rule.schemaVersion != kProcessAffinityRuleVersion ||
            (!rule.selectAllAvailable && rule.processors.empty()) ||
            rule.processors.size() > kProcessAffinityRuleMaximumProcessorCount)
        {
            bytesOut->clear();
            return false;
        }
        for (const LogicalProcessorCoordinate& coordinate : rule.processors)
        {
            if (coordinate.logicalIndex >= 64U)
            {
                bytesOut->clear();
                return false;
            }
        }

        bytesOut->clear();
        bytesOut->reserve(
            kProcessAffinityRuleHeaderSize +
            rule.processors.size() * kProcessAffinityRuleCoordinateSize);
        appendAffinityUnsigned(bytesOut, kProcessAffinityRuleMagic, sizeof(std::uint32_t));
        appendAffinityUnsigned(bytesOut, rule.schemaVersion, sizeof(std::uint16_t));
        appendAffinityUnsigned(
            bytesOut,
            rule.selectAllAvailable ? kProcessAffinityRuleSelectAllFlag : 0U,
            sizeof(std::uint16_t));
        appendAffinityUnsigned(
            bytesOut,
            static_cast<std::uint32_t>(rule.processors.size()),
            sizeof(std::uint32_t));
        for (const LogicalProcessorCoordinate& coordinate : rule.processors)
        {
            appendAffinityUnsigned(bytesOut, coordinate.group, sizeof(std::uint16_t));
            appendAffinityUnsigned(bytesOut, coordinate.logicalIndex, sizeof(std::uint16_t));
        }
        return true;
    }

    // deserializeProcessAffinityRule 作用：
    // - 严格解析当前版本 REG_BINARY 数据；
    // - 拒绝未知标志、重复之外的非法坐标、截断或尾随字节，避免静默误应用。
    inline bool deserializeProcessAffinityRule(
        const std::vector<std::uint8_t>& bytes,
        ProcessAffinityRule* const ruleOut)
    {
        if (ruleOut == nullptr || bytes.size() < kProcessAffinityRuleHeaderSize)
        {
            return false;
        }

        std::size_t offset = 0U;
        std::uint64_t magic = 0U;
        std::uint64_t version = 0U;
        std::uint64_t flags = 0U;
        std::uint64_t processorCount = 0U;
        if (!readAffinityUnsigned(bytes, &offset, sizeof(std::uint32_t), &magic) ||
            !readAffinityUnsigned(bytes, &offset, sizeof(std::uint16_t), &version) ||
            !readAffinityUnsigned(bytes, &offset, sizeof(std::uint16_t), &flags) ||
            !readAffinityUnsigned(bytes, &offset, sizeof(std::uint32_t), &processorCount))
        {
            return false;
        }

        const bool selectAllAvailable =
            (flags & kProcessAffinityRuleSelectAllFlag) != 0U;
        const std::size_t expectedSize =
            kProcessAffinityRuleHeaderSize +
            static_cast<std::size_t>(processorCount) *
                kProcessAffinityRuleCoordinateSize;
        if (magic != kProcessAffinityRuleMagic ||
            version != kProcessAffinityRuleVersion ||
            (flags & ~static_cast<std::uint64_t>(kProcessAffinityRuleSelectAllFlag)) != 0U ||
            processorCount > kProcessAffinityRuleMaximumProcessorCount ||
            expectedSize != bytes.size() ||
            (selectAllAvailable && processorCount != 0U) ||
            (!selectAllAvailable && processorCount == 0U))
        {
            return false;
        }

        ProcessAffinityRule rule;
        rule.schemaVersion = static_cast<std::uint16_t>(version);
        rule.selectAllAvailable = selectAllAvailable;
        rule.processors.reserve(static_cast<std::size_t>(processorCount));
        for (std::size_t processorIndex = 0U;
             processorIndex < static_cast<std::size_t>(processorCount);
             ++processorIndex)
        {
            std::uint64_t group = 0U;
            std::uint64_t logicalIndex = 0U;
            if (!readAffinityUnsigned(bytes, &offset, sizeof(std::uint16_t), &group) ||
                !readAffinityUnsigned(bytes, &offset, sizeof(std::uint16_t), &logicalIndex) ||
                logicalIndex >= 64U)
            {
                return false;
            }
            rule.processors.push_back(LogicalProcessorCoordinate{
                static_cast<std::uint16_t>(group),
                static_cast<std::uint16_t>(logicalIndex)
            });
        }
        normalizeLogicalProcessorCoordinates(&rule.processors);
        *ruleOut = std::move(rule);
        return true;
    }

    // remapAffinityRuleToCpuSetIds 作用：
    // - 用稳定 group/index 坐标在当前拓扑中查找本次启动的 CPU Set ID；
    // - 允许返回部分可映射结果，同时通过 missingCoordinatesOut 明确报告缺失坐标。
    inline bool remapAffinityRuleToCpuSetIds(
        const ProcessAffinityRule& rule,
        const std::vector<LogicalProcessorState>& currentTopology,
        std::vector<std::uint32_t>* const cpuSetIdsOut,
        std::vector<LogicalProcessorCoordinate>* const missingCoordinatesOut)
    {
        if (cpuSetIdsOut == nullptr)
        {
            return false;
        }

        cpuSetIdsOut->clear();
        if (missingCoordinatesOut != nullptr)
        {
            missingCoordinatesOut->clear();
        }
        if (rule.selectAllAvailable)
        {
            return true;
        }

        std::vector<LogicalProcessorCoordinate> requestedCoordinates = rule.processors;
        normalizeLogicalProcessorCoordinates(&requestedCoordinates);
        for (const LogicalProcessorCoordinate& coordinate : requestedCoordinates)
        {
            const auto processorIt = std::find_if(
                currentTopology.begin(),
                currentTopology.end(),
                [&coordinate](const LogicalProcessorState& processor)
                {
                    return processor.coordinate == coordinate && processor.available;
                });
            if (processorIt == currentTopology.end())
            {
                if (missingCoordinatesOut != nullptr)
                {
                    missingCoordinatesOut->push_back(coordinate);
                }
                continue;
            }
            cpuSetIdsOut->push_back(processorIt->cpuSetId);
        }

        std::sort(cpuSetIdsOut->begin(), cpuSetIdsOut->end());
        cpuSetIdsOut->erase(
            std::unique(cpuSetIdsOut->begin(), cpuSetIdsOut->end()),
            cpuSetIdsOut->end());
        return !cpuSetIdsOut->empty();
    }
}
