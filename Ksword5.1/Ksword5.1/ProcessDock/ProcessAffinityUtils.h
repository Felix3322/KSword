#pragma once

// ============================================================
// ProcessAffinityUtils.h
// 作用：
// - 为进程列表与详情窗口提供 processor-group-aware CPU 亲和性查询和设置入口；
// - 优先动态解析 Windows 10 CPU Sets API，以稳定 group/index 坐标跨组选择；
// - 旧系统或 API 缺失时保留单 processor group 的 Get/SetProcessAffinityMask 回退。
// ============================================================

#include "ProcessAffinityModel.h"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <map>
#include <set>
#include <string>
#include <utility>
#include <vector>

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>

namespace ks::process
{
    namespace affinity_detail
    {
        using GetSystemCpuSetInformationFunction = BOOL(WINAPI*)(
            PSYSTEM_CPU_SET_INFORMATION,
            ULONG,
            PULONG,
            HANDLE,
            ULONG);
        using GetProcessDefaultCpuSetsFunction = BOOL(WINAPI*)(
            HANDLE,
            PULONG,
            ULONG,
            PULONG);
        using SetProcessDefaultCpuSetsFunction = BOOL(WINAPI*)(
            HANDLE,
            const ULONG*,
            ULONG);

        // CpuSetApiFunctions 作用：缓存 Kernel32 动态入口，避免旧系统装载阶段绑定失败。
        struct CpuSetApiFunctions
        {
            GetSystemCpuSetInformationFunction getSystemCpuSetInformation = nullptr;
            GetProcessDefaultCpuSetsFunction getProcessDefaultCpuSets = nullptr;
            SetProcessDefaultCpuSetsFunction setProcessDefaultCpuSets = nullptr;
        };

        // cpuSetApiFunctions 作用：只解析一次 Windows 10 CPU Sets API；调用方检查所需入口是否存在。
        inline const CpuSetApiFunctions& cpuSetApiFunctions()
        {
            static const CpuSetApiFunctions functions = []()
            {
                CpuSetApiFunctions resolvedFunctions;
                const HMODULE kernel32Module = ::GetModuleHandleW(L"kernel32.dll");
                if (kernel32Module == nullptr)
                {
                    return resolvedFunctions;
                }
                resolvedFunctions.getSystemCpuSetInformation =
                    reinterpret_cast<GetSystemCpuSetInformationFunction>(
                        ::GetProcAddress(kernel32Module, "GetSystemCpuSetInformation"));
                resolvedFunctions.getProcessDefaultCpuSets =
                    reinterpret_cast<GetProcessDefaultCpuSetsFunction>(
                        ::GetProcAddress(kernel32Module, "GetProcessDefaultCpuSets"));
                resolvedFunctions.setProcessDefaultCpuSets =
                    reinterpret_cast<SetProcessDefaultCpuSetsFunction>(
                        ::GetProcAddress(kernel32Module, "SetProcessDefaultCpuSets"));
                return resolvedFunctions;
            }();
            return functions;
        }

        // closeProcessHandle 作用：统一关闭本文件打开的真实进程句柄。
        inline void closeProcessHandle(HANDLE* const processHandle)
        {
            if (processHandle != nullptr && *processHandle != nullptr)
            {
                ::CloseHandle(*processHandle);
                *processHandle = nullptr;
            }
        }

        // querySingleProcessGroup 作用：
        // - 仅在目标明确属于单一 processor group 时返回该 group；
        // - 多组进程返回 false，防止把 ULONG_PTR 误解释为全系统掩码。
        inline bool querySingleProcessGroup(
            const HANDLE processHandle,
            USHORT* const processorGroupOut)
        {
            if (processHandle == nullptr || processorGroupOut == nullptr)
            {
                return false;
            }

            USHORT groupCount = 1U;
            USHORT processorGroup = 0U;
            if (::GetProcessGroupAffinity(
                    processHandle,
                    &groupCount,
                    &processorGroup) == FALSE ||
                groupCount != 1U)
            {
                return false;
            }
            *processorGroupOut = processorGroup;
            return true;
        }

        // querySystemCpuSetStates 作用：
        // - 枚举系统 CPU Set，并把临时 ID 映射为稳定 group/index；
        // - processHandle 用于区分“分配给其它进程”和“分配给当前目标”的 CPU Set。
        inline bool querySystemCpuSetStates(
            const HANDLE processHandle,
            const CpuSetApiFunctions& functions,
            std::vector<LogicalProcessorState>* const processorsOut,
            std::string* const detailTextOut)
        {
            if (processHandle == nullptr || processorsOut == nullptr ||
                functions.getSystemCpuSetInformation == nullptr)
            {
                return false;
            }

            ULONG requiredBytes = 0U;
            const BOOL sizeQueryOk = functions.getSystemCpuSetInformation(
                nullptr,
                0U,
                &requiredBytes,
                processHandle,
                0U);
            const DWORD sizeQueryError =
                sizeQueryOk != FALSE ? ERROR_SUCCESS : ::GetLastError();
            if (requiredBytes == 0U ||
                (sizeQueryOk == FALSE && sizeQueryError != ERROR_INSUFFICIENT_BUFFER))
            {
                if (detailTextOut != nullptr)
                {
                    *detailTextOut =
                        "GetSystemCpuSetInformation size query failed(" +
                        std::to_string(sizeQueryError) + ")";
                }
                return false;
            }

            std::vector<BYTE> cpuSetBuffer(requiredBytes);
            ULONG returnedBytes = requiredBytes;
            if (functions.getSystemCpuSetInformation(
                    reinterpret_cast<PSYSTEM_CPU_SET_INFORMATION>(cpuSetBuffer.data()),
                    static_cast<ULONG>(cpuSetBuffer.size()),
                    &returnedBytes,
                    processHandle,
                    0U) == FALSE)
            {
                if (detailTextOut != nullptr)
                {
                    *detailTextOut =
                        "GetSystemCpuSetInformation failed(" +
                        std::to_string(::GetLastError()) + ")";
                }
                return false;
            }

            processorsOut->clear();
            const BYTE* cpuSetCursor = cpuSetBuffer.data();
            const BYTE* const cpuSetEnd =
                cpuSetBuffer.data() +
                std::min<std::size_t>(returnedBytes, cpuSetBuffer.size());
            while (cpuSetCursor < cpuSetEnd)
            {
                if (static_cast<std::size_t>(cpuSetEnd - cpuSetCursor) <
                    sizeof(SYSTEM_CPU_SET_INFORMATION))
                {
                    if (detailTextOut != nullptr)
                    {
                        *detailTextOut = "CPU Set information record is truncated";
                    }
                    return false;
                }

                const auto* const cpuSetRecord =
                    reinterpret_cast<const SYSTEM_CPU_SET_INFORMATION*>(cpuSetCursor);
                if (cpuSetRecord->Size < sizeof(SYSTEM_CPU_SET_INFORMATION) ||
                    cpuSetRecord->Size >
                        static_cast<DWORD>(cpuSetEnd - cpuSetCursor))
                {
                    if (detailTextOut != nullptr)
                    {
                        *detailTextOut = "CPU Set information record size is invalid";
                    }
                    return false;
                }
                if (cpuSetRecord->Type == CpuSetInformation)
                {
                    const BYTE cpuSetFlags = cpuSetRecord->CpuSet.AllFlags;
                    LogicalProcessorState processor;
                    processor.coordinate.group = cpuSetRecord->CpuSet.Group;
                    processor.coordinate.logicalIndex =
                        cpuSetRecord->CpuSet.LogicalProcessorIndex;
                    processor.cpuSetId = cpuSetRecord->CpuSet.Id;
                    processor.coreIndex = cpuSetRecord->CpuSet.CoreIndex;
                    processor.efficiencyClass =
                        cpuSetRecord->CpuSet.EfficiencyClass;
                    processor.parked =
                        (cpuSetFlags & SYSTEM_CPU_SET_INFORMATION_PARKED) != 0U;
                    processor.allocated =
                        (cpuSetFlags & SYSTEM_CPU_SET_INFORMATION_ALLOCATED) != 0U;
                    processor.allocatedToTargetProcess =
                        (cpuSetFlags &
                            SYSTEM_CPU_SET_INFORMATION_ALLOCATED_TO_TARGET_PROCESS) != 0U;
                    processor.available =
                        !processor.allocated || processor.allocatedToTargetProcess;
                    processorsOut->push_back(std::move(processor));
                }
                cpuSetCursor += cpuSetRecord->Size;
            }

            std::sort(
                processorsOut->begin(),
                processorsOut->end(),
                [](const LogicalProcessorState& left, const LogicalProcessorState& right)
                {
                    return left.coordinate < right.coordinate;
                });
            if (processorsOut->empty())
            {
                if (detailTextOut != nullptr)
                {
                    *detailTextOut = "GetSystemCpuSetInformation returned no CPU Sets";
                }
                return false;
            }
            return true;
        }

        // queryProcessDefaultCpuSetIds 作用：读取进程默认 CPU Set ID 列表；空列表表示未设置 CPU Set 限制。
        inline bool queryProcessDefaultCpuSetIds(
            const HANDLE processHandle,
            const CpuSetApiFunctions& functions,
            std::vector<std::uint32_t>* const cpuSetIdsOut,
            std::string* const detailTextOut)
        {
            if (processHandle == nullptr || cpuSetIdsOut == nullptr ||
                functions.getProcessDefaultCpuSets == nullptr)
            {
                return false;
            }

            ULONG requiredIdCount = 0U;
            const BOOL sizeQueryOk = functions.getProcessDefaultCpuSets(
                processHandle,
                nullptr,
                0U,
                &requiredIdCount);
            const DWORD sizeQueryError =
                sizeQueryOk != FALSE ? ERROR_SUCCESS : ::GetLastError();
            if (sizeQueryOk == FALSE &&
                sizeQueryError != ERROR_INSUFFICIENT_BUFFER)
            {
                if (detailTextOut != nullptr)
                {
                    *detailTextOut =
                        "GetProcessDefaultCpuSets size query failed(" +
                        std::to_string(sizeQueryError) + ")";
                }
                return false;
            }

            cpuSetIdsOut->clear();
            if (requiredIdCount == 0U)
            {
                return true;
            }

            std::vector<ULONG> nativeCpuSetIds(requiredIdCount, 0U);
            ULONG returnedIdCount = requiredIdCount;
            if (functions.getProcessDefaultCpuSets(
                    processHandle,
                    nativeCpuSetIds.data(),
                    static_cast<ULONG>(nativeCpuSetIds.size()),
                    &returnedIdCount) == FALSE)
            {
                if (detailTextOut != nullptr)
                {
                    *detailTextOut =
                        "GetProcessDefaultCpuSets failed(" +
                        std::to_string(::GetLastError()) + ")";
                }
                cpuSetIdsOut->clear();
                return false;
            }

            nativeCpuSetIds.resize(
                std::min<std::size_t>(
                    returnedIdCount,
                    nativeCpuSetIds.size()));
            cpuSetIdsOut->assign(
                nativeCpuSetIds.begin(),
                nativeCpuSetIds.end());
            std::sort(cpuSetIdsOut->begin(), cpuSetIdsOut->end());
            cpuSetIdsOut->erase(
                std::unique(cpuSetIdsOut->begin(), cpuSetIdsOut->end()),
                cpuSetIdsOut->end());
            return true;
        }

        // populateProcessorTopologyLabels 作用：
        // - 按 group 分别判断混合架构并生成 P/E/C 标签；
        // - 最终身份仍由 UI 追加 Gx:Ly，避免跨组逻辑索引混淆。
        inline void populateProcessorTopologyLabels(
            std::vector<LogicalProcessorState>* const processors)
        {
            if (processors == nullptr)
            {
                return;
            }

            std::map<std::uint16_t, bool> groupHasPerformanceClass;
            std::map<std::uint16_t, bool> groupHasEfficiencyClass;
            for (const LogicalProcessorState& processor : *processors)
            {
                const std::uint16_t group = processor.coordinate.group;
                groupHasPerformanceClass[group] =
                    groupHasPerformanceClass[group] ||
                    processor.efficiencyClass > 0U;
                groupHasEfficiencyClass[group] =
                    groupHasEfficiencyClass[group] ||
                    processor.efficiencyClass == 0U;
            }

            using CoreKey = std::pair<std::uint16_t, std::uint16_t>;
            std::map<CoreKey, std::vector<std::size_t>> processorIndexesByCore;
            for (std::size_t processorIndex = 0U;
                 processorIndex < processors->size();
                 ++processorIndex)
            {
                const LogicalProcessorState& processor =
                    (*processors)[processorIndex];
                processorIndexesByCore[
                    CoreKey{ processor.coordinate.group, processor.coreIndex }]
                    .push_back(processorIndex);
            }

            std::map<std::uint16_t, std::size_t> performanceCoreIndexByGroup;
            std::map<std::uint16_t, std::size_t> efficiencyCoreIndexByGroup;
            std::map<std::uint16_t, std::size_t> unifiedCoreIndexByGroup;
            for (const auto& corePair : processorIndexesByCore)
            {
                const std::uint16_t group = corePair.first.first;
                const std::vector<std::size_t>& logicalProcessorIndexes =
                    corePair.second;
                if (logicalProcessorIndexes.empty())
                {
                    continue;
                }

                const LogicalProcessorState& firstProcessor =
                    (*processors)[logicalProcessorIndexes.front()];
                const bool hybridArchitecture =
                    groupHasPerformanceClass[group] &&
                    groupHasEfficiencyClass[group];
                const bool performanceCore =
                    hybridArchitecture && firstProcessor.efficiencyClass > 0U;
                const bool efficiencyCore =
                    hybridArchitecture && firstProcessor.efficiencyClass == 0U;

                std::string corePrefix;
                std::size_t coreIndex = 0U;
                if (performanceCore)
                {
                    corePrefix = "P";
                    coreIndex = performanceCoreIndexByGroup[group]++;
                }
                else if (efficiencyCore)
                {
                    corePrefix = "E";
                    coreIndex = efficiencyCoreIndexByGroup[group];
                    efficiencyCoreIndexByGroup[group] +=
                        logicalProcessorIndexes.size();
                }
                else
                {
                    corePrefix = "C";
                    coreIndex = unifiedCoreIndexByGroup[group]++;
                }

                for (std::size_t threadIndex = 0U;
                     threadIndex < logicalProcessorIndexes.size();
                     ++threadIndex)
                {
                    LogicalProcessorState& processor =
                        (*processors)[logicalProcessorIndexes[threadIndex]];
                    const std::size_t displayedCoreIndex =
                        efficiencyCore ? coreIndex + threadIndex : coreIndex;
                    processor.topologyLabel =
                        corePrefix + std::to_string(displayedCoreIndex);
                    if (!efficiencyCore && logicalProcessorIndexes.size() > 1U)
                    {
                        processor.topologyLabel +=
                            "T" + std::to_string(threadIndex);
                    }
                }
            }
        }

        // queryCpuSetProcessAffinity 作用：用 Windows 10 CPU Sets 查询跨组拓扑和进程当前默认选择。
        inline bool queryCpuSetProcessAffinity(
            const HANDLE processHandle,
            const CpuSetApiFunctions& functions,
            ProcessAffinitySnapshot* const snapshotOut,
            std::string* const detailTextOut)
        {
            std::vector<LogicalProcessorState> processors;
            if (!querySystemCpuSetStates(
                    processHandle,
                    functions,
                    &processors,
                    detailTextOut))
            {
                return false;
            }

            std::vector<std::uint32_t> defaultCpuSetIds;
            if (!queryProcessDefaultCpuSetIds(
                    processHandle,
                    functions,
                    &defaultCpuSetIds,
                    detailTextOut))
            {
                return false;
            }
            const std::set<std::uint32_t> selectedCpuSetIds(
                defaultCpuSetIds.begin(),
                defaultCpuSetIds.end());

            // legacyConstraintAvailable：单组旧亲和性仍会与 CPU Set 选择求交，UI 必须反映实际约束。
            USHORT legacyProcessorGroup = 0U;
            ULONG_PTR legacyProcessMask = 0U;
            ULONG_PTR legacySystemMask = 0U;
            const bool singleProcessGroup = querySingleProcessGroup(
                processHandle,
                &legacyProcessorGroup);
            const bool legacyMaskReadable = singleProcessGroup &&
                ::GetProcessAffinityMask(
                    processHandle,
                    &legacyProcessMask,
                    &legacySystemMask) != FALSE;
            const bool legacyConstraintAvailable =
                legacyMaskReadable &&
                (::GetActiveProcessorGroupCount() > 1U ||
                    legacyProcessMask != legacySystemMask);

            for (LogicalProcessorState& processor : processors)
            {
                const bool selectedByCpuSet =
                    defaultCpuSetIds.empty() ||
                    selectedCpuSetIds.find(processor.cpuSetId) !=
                        selectedCpuSetIds.end();
                const bool selectedByLegacyConstraint =
                    processorCoordinateAllowedByLegacyAffinity(
                        processor.coordinate,
                        legacyConstraintAvailable,
                        legacyProcessorGroup,
                        static_cast<std::uint64_t>(
                            legacyProcessMask));
                processor.constrainedByHardAffinity =
                    !selectedByLegacyConstraint;
                processor.available =
                    processor.available &&
                    selectedByLegacyConstraint;
                processor.selected =
                    processor.available &&
                    selectedByCpuSet;
            }
            populateProcessorTopologyLabels(&processors);

            snapshotOut->processors = std::move(processors);
            snapshotOut->usesCpuSets = true;
            snapshotOut->unrestricted =
                defaultCpuSetIds.empty() && !legacyConstraintAvailable;
            return true;
        }

        // queryLegacyProcessAffinity 作用：CPU Sets API 缺失时提供单组兼容路径。
        inline bool queryLegacyProcessAffinity(
            const DWORD processId,
            ProcessAffinitySnapshot* const snapshotOut,
            std::string* const detailTextOut)
        {
            HANDLE processHandle = ::OpenProcess(
                PROCESS_QUERY_INFORMATION,
                FALSE,
                processId);
            if (processHandle == nullptr)
            {
                if (detailTextOut != nullptr)
                {
                    *detailTextOut =
                        "OpenProcess(PROCESS_QUERY_INFORMATION) failed(" +
                        std::to_string(::GetLastError()) + ")";
                }
                return false;
            }

            USHORT processorGroup = 0U;
            ULONG_PTR processMask = 0U;
            ULONG_PTR systemMask = 0U;
            const bool groupOk =
                querySingleProcessGroup(processHandle, &processorGroup);
            const BOOL maskOk = groupOk
                ? ::GetProcessAffinityMask(
                    processHandle,
                    &processMask,
                    &systemMask)
                : FALSE;
            const DWORD errorCode =
                maskOk != FALSE ? ERROR_SUCCESS : ::GetLastError();
            closeProcessHandle(&processHandle);
            if (!groupOk || maskOk == FALSE || systemMask == 0U)
            {
                if (detailTextOut != nullptr)
                {
                    *detailTextOut = !groupOk
                        ? "CPU Set APIs are unavailable and the process spans multiple processor groups"
                        : "GetProcessAffinityMask failed(" +
                            std::to_string(errorCode) + ")";
                }
                return false;
            }

            ProcessAffinitySnapshot snapshot;
            snapshot.usesCpuSets = false;
            snapshot.unrestricted = processMask == systemMask;
            for (std::uint16_t logicalIndex = 0U;
                 logicalIndex < static_cast<std::uint16_t>(sizeof(ULONG_PTR) * 8U);
                 ++logicalIndex)
            {
                const ULONG_PTR processorBit =
                    static_cast<ULONG_PTR>(1ULL) << logicalIndex;
                if ((systemMask & processorBit) == 0U)
                {
                    continue;
                }

                LogicalProcessorState processor;
                processor.coordinate = LogicalProcessorCoordinate{
                    processorGroup,
                    logicalIndex
                };
                processor.cpuSetId = logicalIndex;
                processor.coreIndex = logicalIndex;
                processor.available = true;
                processor.selected = (processMask & processorBit) != 0U;
                processor.topologyLabel = "C" + std::to_string(logicalIndex);
                snapshot.processors.push_back(std::move(processor));
            }
            *snapshotOut = std::move(snapshot);
            return true;
        }

        // setLegacyProcessAffinity 作用：旧系统中把单组稳定坐标转换回 ULONG_PTR 后应用。
        inline bool setLegacyProcessAffinity(
            const DWORD processId,
            const ProcessAffinityRule& rule,
            std::string* const detailTextOut)
        {
            HANDLE processHandle = ::OpenProcess(
                PROCESS_QUERY_INFORMATION | PROCESS_SET_INFORMATION,
                FALSE,
                processId);
            if (processHandle == nullptr)
            {
                if (detailTextOut != nullptr)
                {
                    *detailTextOut =
                        "OpenProcess(PROCESS_QUERY_INFORMATION|PROCESS_SET_INFORMATION) failed(" +
                        std::to_string(::GetLastError()) + ")";
                }
                return false;
            }

            USHORT processorGroup = 0U;
            ULONG_PTR currentMask = 0U;
            ULONG_PTR systemMask = 0U;
            if (!querySingleProcessGroup(processHandle, &processorGroup) ||
                ::GetProcessAffinityMask(
                    processHandle,
                    &currentMask,
                    &systemMask) == FALSE)
            {
                const DWORD errorCode = ::GetLastError();
                closeProcessHandle(&processHandle);
                if (detailTextOut != nullptr)
                {
                    *detailTextOut =
                        "legacy process affinity query failed(" +
                        std::to_string(errorCode) + ")";
                }
                return false;
            }

            ULONG_PTR requestedMask = rule.selectAllAvailable
                ? systemMask
                : 0U;
            if (!rule.selectAllAvailable)
            {
                for (const LogicalProcessorCoordinate& coordinate :
                     rule.processors)
                {
                    if (coordinate.group != processorGroup ||
                        coordinate.logicalIndex >=
                            static_cast<std::uint16_t>(sizeof(ULONG_PTR) * 8U))
                    {
                        closeProcessHandle(&processHandle);
                        if (detailTextOut != nullptr)
                        {
                            *detailTextOut =
                                "CPU Set APIs are unavailable for the requested processor group";
                        }
                        return false;
                    }
                    requestedMask |=
                        static_cast<ULONG_PTR>(1ULL) <<
                        coordinate.logicalIndex;
                }
                requestedMask &= systemMask;
            }
            if (requestedMask == 0U)
            {
                closeProcessHandle(&processHandle);
                if (detailTextOut != nullptr)
                {
                    *detailTextOut =
                        "requested affinity has no available logical processor";
                }
                return false;
            }

            const BOOL setOk = currentMask == requestedMask
                ? TRUE
                : ::SetProcessAffinityMask(processHandle, requestedMask);
            const DWORD errorCode =
                setOk != FALSE ? ERROR_SUCCESS : ::GetLastError();
            closeProcessHandle(&processHandle);
            if (setOk == FALSE)
            {
                if (detailTextOut != nullptr)
                {
                    *detailTextOut =
                        "SetProcessAffinityMask failed(" +
                        std::to_string(errorCode) + ")";
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

    // QueryProcessAffinityState 作用：
    // - 优先返回所有 processor group 的 CPU Set 拓扑与当前选择；
    // - CPU Sets 不可用时只在单组目标上回退旧掩码 API。
    inline bool QueryProcessAffinityState(
        const DWORD processId,
        ProcessAffinitySnapshot* const snapshotOut,
        std::string* const detailTextOut)
    {
        if (processId == 0U || snapshotOut == nullptr)
        {
            if (detailTextOut != nullptr)
            {
                *detailTextOut = "invalid process affinity query input";
            }
            return false;
        }
        *snapshotOut = ProcessAffinitySnapshot{};

        const affinity_detail::CpuSetApiFunctions& functions =
            affinity_detail::cpuSetApiFunctions();
        if (functions.getSystemCpuSetInformation != nullptr &&
            functions.getProcessDefaultCpuSets != nullptr)
        {
            HANDLE processHandle = ::OpenProcess(
                PROCESS_QUERY_LIMITED_INFORMATION,
                FALSE,
                processId);
            if (processHandle != nullptr)
            {
                const bool queryOk =
                    affinity_detail::queryCpuSetProcessAffinity(
                        processHandle,
                        functions,
                        snapshotOut,
                        detailTextOut);
                affinity_detail::closeProcessHandle(&processHandle);
                if (queryOk)
                {
                    if (detailTextOut != nullptr)
                    {
                        detailTextOut->clear();
                    }
                    return true;
                }
            }
        }
        return affinity_detail::queryLegacyProcessAffinity(
            processId,
            snapshotOut,
            detailTextOut);
    }

    // SetProcessAffinityRuleByPid 作用：
    // - 将稳定 group/index 规则映射为本次启动的 CPU Set ID 后应用；
    // - selectAllAvailable 会清除默认 CPU Set 分配；旧系统回退单组掩码。
    inline bool SetProcessAffinityRuleByPid(
        const DWORD processId,
        const ProcessAffinityRule& rule,
        std::string* const detailTextOut)
    {
        if (processId == 0U ||
            (!rule.selectAllAvailable && rule.processors.empty()))
        {
            if (detailTextOut != nullptr)
            {
                *detailTextOut = "invalid process affinity update input";
            }
            return false;
        }

        const affinity_detail::CpuSetApiFunctions& functions =
            affinity_detail::cpuSetApiFunctions();
        if (functions.getSystemCpuSetInformation == nullptr ||
            functions.getProcessDefaultCpuSets == nullptr ||
            functions.setProcessDefaultCpuSets == nullptr)
        {
            return affinity_detail::setLegacyProcessAffinity(
                processId,
                rule,
                detailTextOut);
        }

        HANDLE processHandle = ::OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION |
                PROCESS_SET_LIMITED_INFORMATION,
            FALSE,
            processId);
        if (processHandle == nullptr)
        {
            if (detailTextOut != nullptr)
            {
                *detailTextOut =
                    "OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION|PROCESS_SET_LIMITED_INFORMATION) failed(" +
                    std::to_string(::GetLastError()) + ")";
            }
            return false;
        }

        std::vector<LogicalProcessorState> currentTopology;
        if (!affinity_detail::querySystemCpuSetStates(
                processHandle,
                functions,
                &currentTopology,
                detailTextOut))
        {
            affinity_detail::closeProcessHandle(&processHandle);
            return false;
        }

        std::vector<std::uint32_t> cpuSetIds;
        std::vector<LogicalProcessorCoordinate> missingCoordinates;
        if (!remapAffinityRuleToCpuSetIds(
                rule,
                currentTopology,
                &cpuSetIds,
                &missingCoordinates))
        {
            affinity_detail::closeProcessHandle(&processHandle);
            if (detailTextOut != nullptr)
            {
                *detailTextOut =
                    "saved affinity has no logical processor in the current topology";
            }
            return false;
        }
        if (!missingCoordinates.empty())
        {
            affinity_detail::closeProcessHandle(&processHandle);
            if (detailTextOut != nullptr)
            {
                *detailTextOut =
                    "requested affinity topology changed; refusing partial apply because " +
                    std::to_string(missingCoordinates.size()) +
                    " processor coordinate(s) are unavailable";
            }
            return false;
        }

        // previousCpuSetIds 用于写后验证失败时恢复调用前的默认 CPU Set 选择。
        std::vector<std::uint32_t> previousCpuSetIds;
        if (!affinity_detail::queryProcessDefaultCpuSetIds(
                processHandle,
                functions,
                &previousCpuSetIds,
                detailTextOut))
        {
            affinity_detail::closeProcessHandle(&processHandle);
            return false;
        }

        const std::vector<ULONG> nativeCpuSetIds(
            cpuSetIds.begin(),
            cpuSetIds.end());
        const ULONG* cpuSetIdData = rule.selectAllAvailable
            ? nullptr
            : nativeCpuSetIds.data();
        const ULONG cpuSetIdCount = rule.selectAllAvailable
            ? 0U
            : static_cast<ULONG>(cpuSetIds.size());
        const BOOL setOk = functions.setProcessDefaultCpuSets(
            processHandle,
            cpuSetIdData,
            cpuSetIdCount);
        const DWORD errorCode =
            setOk != FALSE ? ERROR_SUCCESS : ::GetLastError();
        if (setOk == FALSE)
        {
            affinity_detail::closeProcessHandle(&processHandle);
            if (detailTextOut != nullptr)
            {
                *detailTextOut =
                    "SetProcessDefaultCpuSets failed(" +
                    std::to_string(errorCode) + ")";
            }
            return false;
        }

        // CPU Set 与既有线程/进程 group 亲和性及 Job 约束取交集；必须读回验证，
        // 不能把“API 返回成功但请求坐标不可调度”报告为完整成功。
        std::string verificationDetailText;
        bool verificationQueryOk = false;
        bool verificationMatches = false;
        if (rule.selectAllAvailable)
        {
            std::vector<std::uint32_t> verifiedDefaultCpuSetIds;
            verificationQueryOk =
                affinity_detail::queryProcessDefaultCpuSetIds(
                    processHandle,
                    functions,
                    &verifiedDefaultCpuSetIds,
                    &verificationDetailText);
            verificationMatches =
                verificationQueryOk &&
                selectAllCpuSetSelectionMatches(
                    rule,
                    verifiedDefaultCpuSetIds);
        }
        else
        {
            ProcessAffinitySnapshot verifiedSnapshot;
            verificationQueryOk =
                affinity_detail::queryCpuSetProcessAffinity(
                    processHandle,
                    functions,
                    &verifiedSnapshot,
                    &verificationDetailText);
            verificationMatches = verificationQueryOk;
            std::vector<LogicalProcessorCoordinate> requestedCoordinates =
                rule.processors;
            std::vector<LogicalProcessorCoordinate> selectedCoordinates;
            normalizeLogicalProcessorCoordinates(&requestedCoordinates);
            for (const LogicalProcessorState& processor :
                 verifiedSnapshot.processors)
            {
                if (processor.available && processor.selected)
                {
                    selectedCoordinates.push_back(processor.coordinate);
                }
            }
            normalizeLogicalProcessorCoordinates(&selectedCoordinates);
            verificationMatches = verificationMatches &&
                requestedCoordinates == selectedCoordinates;
        }
        if (!verificationMatches)
        {
            const std::vector<ULONG> nativePreviousCpuSetIds(
                previousCpuSetIds.begin(),
                previousCpuSetIds.end());
            const BOOL rollbackOk = functions.setProcessDefaultCpuSets(
                processHandle,
                nativePreviousCpuSetIds.empty()
                    ? nullptr
                    : nativePreviousCpuSetIds.data(),
                static_cast<ULONG>(nativePreviousCpuSetIds.size()));
            const DWORD rollbackError =
                rollbackOk != FALSE ? ERROR_SUCCESS : ::GetLastError();
            affinity_detail::closeProcessHandle(&processHandle);
            if (detailTextOut != nullptr)
            {
                const std::string rollbackText = rollbackOk != FALSE
                    ? "succeeded"
                    : "failed(" +
                        std::to_string(rollbackError) + ")";
                *detailTextOut =
                    verificationQueryOk
                        ? (rule.selectAllAvailable
                            ? "CPU Set verification did not confirm an empty process default CPU Set list; rollback " +
                                rollbackText
                            : "CPU Set verification did not match the requested group/index coordinates; existing thread/process group or Job constraints may intersect; rollback " +
                                rollbackText)
                        : "CPU Set verification query failed(" +
                            verificationDetailText +
                            "); rollback " +
                            rollbackText;
            }
            return false;
        }
        affinity_detail::closeProcessHandle(&processHandle);

        if (detailTextOut != nullptr)
        {
            detailTextOut->clear();
        }
        return true;
    }

    // processorIdentityText 作用：生成日志与 UI 可复用的稳定“Gx:Ly”处理器身份。
    inline std::string processorIdentityText(
        const LogicalProcessorCoordinate& coordinate)
    {
        return "G" + std::to_string(coordinate.group) +
            ":L" + std::to_string(coordinate.logicalIndex);
    }
}
