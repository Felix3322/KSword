#pragma once

// ============================================================
// ProcessAffinityUtils.h
// 作用：
// - 为进程列表右键菜单与进程详细信息窗口提供一致的 CPU 亲和性读写入口；
// - 只封装当前 Windows processor group 的 Get/SetProcessAffinityMask 语义；
// - 调用方负责把掩码映射为具体 UI 与用户可见状态。
// ============================================================

#include <cstddef>
#include <cstdint>
#include <string>
#include <utility>
#include <vector>

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>

namespace ks::process
{
    struct ProcessAffinityMasks
    {
        ULONG_PTR processMask = 0; // processMask：当前进程已启用的逻辑核心位图。
        ULONG_PTR systemMask = 0;  // systemMask：当前 processor group 中可分配的逻辑核心位图。
    };

    // QueryProcessAffinityCoreLabels：依据 RelationProcessorCore 的 EfficiencyClass 生成 UI 标签。
    // 只有同一 processor group 同时出现 0 和非 0 EfficiencyClass 时才判定为混合架构；
    // 无法可靠判定时保持 Cx，避免把统一架构误标为大小核。
    inline bool QueryProcessAffinityCoreLabels(
        const DWORD processId,
        std::vector<std::string>* const labelsOut)
    {
        if (labelsOut == nullptr || processId == 0U)
        {
            return false;
        }

        const std::size_t logicalProcessorCount = sizeof(ULONG_PTR) * 8U;
        labelsOut->clear();
        labelsOut->reserve(logicalProcessorCount);
        for (std::size_t index = 0U; index < logicalProcessorCount; ++index)
        {
            labelsOut->push_back("C" + std::to_string(index));
        }

        HANDLE processHandle = ::OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, processId);
        if (processHandle == nullptr)
        {
            return false;
        }

        USHORT groupCount = 1U;
        USHORT processGroup = 0U;
        const BOOL groupOk = ::GetProcessGroupAffinity(processHandle, &groupCount, &processGroup);
        ::CloseHandle(processHandle);
        if (groupOk == FALSE || groupCount != 1U)
        {
            return false;
        }

        DWORD bufferSize = 0U;
        ::GetLogicalProcessorInformationEx(RelationProcessorCore, nullptr, &bufferSize);
        if (::GetLastError() != ERROR_INSUFFICIENT_BUFFER || bufferSize == 0U)
        {
            return false;
        }
        std::vector<BYTE> topologyBuffer(bufferSize);
        if (::GetLogicalProcessorInformationEx(
                RelationProcessorCore,
                reinterpret_cast<PSYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX>(topologyBuffer.data()),
                &bufferSize) == FALSE)
        {
            return false;
        }

        constexpr std::size_t recordHeaderSize =
            offsetof(SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX, Processor) +
            offsetof(PROCESSOR_RELATIONSHIP, GroupMask);
        struct PhysicalCoreTopology
        {
            int efficiencyClass = -1;
            bool supportsSimultaneousMultithreading = false;
            std::vector<std::size_t> logicalProcessorIndexes;
        };
        std::vector<PhysicalCoreTopology> physicalCores;
        const BYTE* cursor = topologyBuffer.data();
        const BYTE* const end = topologyBuffer.data() + bufferSize;
        while (cursor < end)
        {
            if (static_cast<std::size_t>(end - cursor) < recordHeaderSize)
            {
                return false;
            }
            const auto* const topology = reinterpret_cast<const SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX*>(cursor);
            if (topology->Size < recordHeaderSize || cursor + topology->Size > end)
            {
                return false;
            }

            const PROCESSOR_RELATIONSHIP& processor = topology->Processor;
            const std::size_t requiredSize = recordHeaderSize +
                static_cast<std::size_t>(processor.GroupCount) * sizeof(GROUP_AFFINITY);
            if (topology->Size < requiredSize)
            {
                return false;
            }
            for (WORD groupIndex = 0U; groupIndex < processor.GroupCount; ++groupIndex)
            {
                const GROUP_AFFINITY& groupAffinity = processor.GroupMask[groupIndex];
                if (groupAffinity.Group != processGroup)
                {
                    continue;
                }
                PhysicalCoreTopology physicalCore;
                physicalCore.efficiencyClass = processor.EfficiencyClass;
                physicalCore.supportsSimultaneousMultithreading =
                    (processor.Flags & LTP_PC_SMT) != 0U;
                for (std::size_t logicalIndex = 0U; logicalIndex < logicalProcessorCount; ++logicalIndex)
                {
                    const KAFFINITY logicalBit = static_cast<KAFFINITY>(1ULL) << logicalIndex;
                    if ((groupAffinity.Mask & logicalBit) != 0U)
                    {
                        physicalCore.logicalProcessorIndexes.push_back(logicalIndex);
                    }
                }
                if (!physicalCore.logicalProcessorIndexes.empty())
                {
                    physicalCores.push_back(std::move(physicalCore));
                }
            }
            cursor += topology->Size;
        }

        bool hasPerformanceClass = false;
        bool hasEfficiencyClass = false;
        for (const PhysicalCoreTopology& physicalCore : physicalCores)
        {
            // Windows EfficiencyClass 数值越高，表示该核心的性能等级越高。
            hasPerformanceClass = hasPerformanceClass || physicalCore.efficiencyClass > 0;
            hasEfficiencyClass = hasEfficiencyClass || physicalCore.efficiencyClass == 0;
        }

        const bool isHybridArchitecture = hasPerformanceClass && hasEfficiencyClass;
        std::size_t unifiedCoreIndex = 0U;
        std::size_t performanceIndex = 0U;
        std::size_t efficiencyIndex = 0U;
        for (const PhysicalCoreTopology& physicalCore : physicalCores)
        {
            const bool isPerformanceCore =
                isHybridArchitecture && physicalCore.efficiencyClass > 0;
            const bool isEfficiencyCore =
                isHybridArchitecture && physicalCore.efficiencyClass == 0;
            // LTP_PC_SMT 是 Windows 对“同一物理核心含多个逻辑处理器”的权威标志。
            // 混合架构的 E 核即使拓扑位图异常包含多个位，也必须拆开显示为独立 E 核，不能标为超线程。
            const bool hasHyperThreads = physicalCore.supportsSimultaneousMultithreading &&
                !isEfficiencyCore && physicalCore.logicalProcessorIndexes.size() > 1U;
            for (std::size_t threadIndex = 0U;
                 threadIndex < physicalCore.logicalProcessorIndexes.size();
                 ++threadIndex)
            {
                const std::size_t logicalIndex = physicalCore.logicalProcessorIndexes[threadIndex];
                std::string coreLabel;
                if (isPerformanceCore)
                {
                    coreLabel = "P" + std::to_string(performanceIndex + (hasHyperThreads ? 0U : threadIndex));
                }
                else if (isEfficiencyCore)
                {
                    coreLabel = "E" + std::to_string(efficiencyIndex + threadIndex);
                }
                else
                {
                    coreLabel = "C" + std::to_string(unifiedCoreIndex + (hasHyperThreads ? 0U : threadIndex));
                }
                (*labelsOut)[logicalIndex] = hasHyperThreads
                    ? coreLabel + "T" + std::to_string(threadIndex)
                    : coreLabel;
            }
            if (isPerformanceCore)
            {
                performanceIndex += hasHyperThreads ? 1U : physicalCore.logicalProcessorIndexes.size();
            }
            else if (isEfficiencyCore)
            {
                efficiencyIndex += physicalCore.logicalProcessorIndexes.size();
            }
            else
            {
                unifiedCoreIndex += hasHyperThreads ? 1U : physicalCore.logicalProcessorIndexes.size();
            }
        }
        return true;
    }

    inline bool QueryProcessAffinityMasks(
        const DWORD processId,
        ProcessAffinityMasks* const masksOut,
        std::string* const detailTextOut)
    {
        if (masksOut == nullptr || processId == 0U)
        {
            if (detailTextOut != nullptr)
            {
                *detailTextOut = "invalid process affinity query input";
            }
            return false;
        }

        *masksOut = ProcessAffinityMasks{};
        HANDLE processHandle = ::OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, processId);
        if (processHandle == nullptr)
        {
            if (detailTextOut != nullptr)
            {
                *detailTextOut = "OpenProcess(PROCESS_QUERY_INFORMATION) failed(" +
                    std::to_string(::GetLastError()) + ")";
            }
            return false;
        }

        const BOOL queryOk = ::GetProcessAffinityMask(
            processHandle,
            &masksOut->processMask,
            &masksOut->systemMask);
        const DWORD errorCode = queryOk != FALSE ? ERROR_SUCCESS : ::GetLastError();
        ::CloseHandle(processHandle);

        if (queryOk == FALSE || masksOut->systemMask == 0U)
        {
            if (detailTextOut != nullptr)
            {
                *detailTextOut = queryOk == FALSE
                    ? "GetProcessAffinityMask failed(" + std::to_string(errorCode) + ")"
                    : "GetProcessAffinityMask returned an empty system mask";
            }
            return false;
        }

        if (detailTextOut != nullptr)
        {
            detailTextOut->clear();
        }
        return true;
    }

    inline bool SetProcessAffinityMaskByPid(
        const DWORD processId,
        const ULONG_PTR requestedMask,
        std::string* const detailTextOut)
    {
        if (processId == 0U || requestedMask == 0U)
        {
            if (detailTextOut != nullptr)
            {
                *detailTextOut = "invalid process affinity update input";
            }
            return false;
        }

        HANDLE processHandle = ::OpenProcess(
            PROCESS_QUERY_INFORMATION | PROCESS_SET_INFORMATION,
            FALSE,
            processId);
        if (processHandle == nullptr)
        {
            if (detailTextOut != nullptr)
            {
                *detailTextOut = "OpenProcess(PROCESS_QUERY_INFORMATION|PROCESS_SET_INFORMATION) failed(" +
                    std::to_string(::GetLastError()) + ")";
            }
            return false;
        }

        ULONG_PTR currentMask = 0;
        ULONG_PTR systemMask = 0;
        if (::GetProcessAffinityMask(processHandle, &currentMask, &systemMask) == FALSE)
        {
            const DWORD errorCode = ::GetLastError();
            ::CloseHandle(processHandle);
            if (detailTextOut != nullptr)
            {
                *detailTextOut = "GetProcessAffinityMask failed(" + std::to_string(errorCode) + ")";
            }
            return false;
        }

        if ((requestedMask & ~systemMask) != 0U)
        {
            ::CloseHandle(processHandle);
            if (detailTextOut != nullptr)
            {
                *detailTextOut = "requested affinity mask contains unavailable logical processors";
            }
            return false;
        }

        if (currentMask == requestedMask)
        {
            ::CloseHandle(processHandle);
            if (detailTextOut != nullptr)
            {
                *detailTextOut = "unchanged";
            }
            return true;
        }

        const BOOL setOk = ::SetProcessAffinityMask(processHandle, requestedMask);
        const DWORD errorCode = setOk != FALSE ? ERROR_SUCCESS : ::GetLastError();
        ::CloseHandle(processHandle);
        if (setOk == FALSE)
        {
            if (detailTextOut != nullptr)
            {
                *detailTextOut = "SetProcessAffinityMask failed(" + std::to_string(errorCode) + ")";
            }
            return false;
        }

        if (detailTextOut != nullptr)
        {
            detailTextOut->clear();
        }
        return true;
    }
}
