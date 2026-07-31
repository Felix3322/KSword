#include "KernelThreadAuditTab.h"

#include "../ArkDriverClient/ArkDriverClient.h"

#include <Windows.h>

#include <QByteArray>

#include <algorithm>
#include <cstddef>
#include <limits>
#include <unordered_map>
#include <utility>
#include <vector>

namespace
{
    using NtQuerySystemInformationFunction = LONG(NTAPI*)(
        unsigned long,
        void*,
        unsigned long,
        unsigned long*);

    struct RawModuleEntry
    {
        HANDLE section;
        void* mappedBase;
        void* imageBase;
        unsigned long imageSize;
        unsigned long flags;
        unsigned short loadOrderIndex;
        unsigned short initOrderIndex;
        unsigned short loadCount;
        unsigned short fileNameOffset;
        unsigned char fullPathName[256];
    };

    struct RawModuleInformation
    {
        unsigned long moduleCount;
        RawModuleEntry modules[1];
    };

    constexpr unsigned long kSystemModuleInformationClass = 11UL;
    constexpr LONG kStatusInfoLengthMismatch = static_cast<LONG>(0xC0000004UL);
    constexpr std::size_t kMaximumModuleSnapshotBytes = 16U * 1024U * 1024U;
    constexpr std::uint32_t kSystemProcessId = 4U;

    std::size_t boundedAnsiLength(
        const unsigned char* const text,
        const std::size_t capacity)
    {
        if (text == nullptr)
        {
            return 0U;
        }
        for (std::size_t index = 0U; index < capacity; ++index)
        {
            if (text[index] == 0U)
            {
                return index;
            }
        }
        return capacity;
    }

    std::uint64_t checkedAddressEnd(
        const std::uint64_t baseAddress,
        const std::uint32_t imageSize)
    {
        const std::uint64_t sizeValue = static_cast<std::uint64_t>(imageSize);
        if (baseAddress > (std::numeric_limits<std::uint64_t>::max)() - sizeValue)
        {
            return (std::numeric_limits<std::uint64_t>::max)();
        }
        return baseAddress + sizeValue;
    }
}

KernelThreadAuditTab::Snapshot KernelThreadAuditTab::collectSnapshot(const Mode mode)
{
    Snapshot snapshot;
    const ksword::ark::DriverClient driverClient;

    if (mode == Mode::WorkQueueThreads)
    {
        const ksword::ark::WorkQueueEnumResult result =
            driverClient.enumerateWorkQueues();
        snapshot.r0Available = result.io.ok;
        snapshot.r0Win32Error = result.io.win32Error;
        snapshot.workQueueQueryStatus = result.queryStatus;
        snapshot.workQueueStatusFlags = result.statusFlags;
        snapshot.workQueueTotalCount = result.totalCount;
        snapshot.workQueueNodeCount = result.nodeCount;
        snapshot.workQueueQueuesVisited = result.queuesVisited;
        snapshot.workQueueCorruptCount = result.corruptListCount;
        snapshot.workQueueReadFailureCount = result.readFailureCount;
        snapshot.workQueueReferenceFailureCount = result.referenceFailureCount;
        snapshot.workQueueLastStatus = result.lastStatus;

        if (!result.io.ok)
        {
            snapshot.diagnosticFlags |= DiagnosticWorkQueueTransportFailed;
            if (result.unsupported)
            {
                snapshot.diagnosticFlags |= DiagnosticWorkQueueUnsupported;
            }
            return snapshot;
        }
        if (result.unsupported ||
            result.queryStatus == KSWORD_ARK_WORK_QUEUE_QUERY_STATUS_UNSUPPORTED ||
            result.queryStatus == KSWORD_ARK_WORK_QUEUE_QUERY_STATUS_INVALID_LAYOUT ||
            result.queryStatus == KSWORD_ARK_WORK_QUEUE_QUERY_STATUS_IDENTITY_MISMATCH)
        {
            snapshot.diagnosticFlags |= DiagnosticWorkQueueUnsupported;
        }
        if (result.queryStatus == KSWORD_ARK_WORK_QUEUE_QUERY_STATUS_PARTIAL)
        {
            snapshot.diagnosticFlags |= DiagnosticWorkQueuePartial;
        }

        snapshot.rows.reserve(result.entries.size());
        for (const ksword::ark::WorkQueueEntry& source : result.entries)
        {
            ThreadRow row;
            row.threadId = source.threadId;
            row.createTime100ns = source.threadCreateTime100ns;
            row.startAddress = source.routineAddress;
            row.queueAddress = source.queueAddress;
            row.workItemAddress = source.workItemAddress;
            row.parameterAddress = source.parameterAddress;
            row.threadObject = source.threadObject;
            row.workQueueRowKind = source.rowKind;
            row.queueType = source.queueType;
            row.queuePriorityIndex = source.priorityIndex;
            row.nodeIndex = source.nodeIndex;
            row.workQueueFlags = source.flags;
            row.workQueueStatus = source.status;
            row.module.name = QString::fromLocal8Bit(
                source.moduleName.data(),
                static_cast<int>(source.moduleName.size()));
            row.module.path = QString::fromLocal8Bit(
                source.modulePath.data(),
                static_cast<int>(source.modulePath.size()));
            row.module.baseAddress = source.moduleBase;
            row.module.imageSize = source.moduleSize;
            row.moduleResolved =
                (source.flags & KSWORD_ARK_WORK_QUEUE_ENTRY_MODULE_RESOLVED) != 0U;
            row.protectedTarget = true;
            row.protectionKind = ProtectionKind::ReadOnlyWorkQueueEvidence;
            snapshot.rows.push_back(std::move(row));
        }

        std::sort(
            snapshot.rows.begin(),
            snapshot.rows.end(),
            [](const ThreadRow& left, const ThreadRow& right) {
                if (left.nodeIndex != right.nodeIndex)
                {
                    return left.nodeIndex < right.nodeIndex;
                }
                if (left.queueType != right.queueType)
                {
                    return left.queueType < right.queueType;
                }
                if (left.workQueueRowKind != right.workQueueRowKind)
                {
                    return left.workQueueRowKind < right.workQueueRowKind;
                }
                const std::uint64_t leftIdentity =
                    left.workItemAddress != 0U ? left.workItemAddress : left.threadObject;
                const std::uint64_t rightIdentity =
                    right.workItemAddress != 0U ? right.workItemAddress : right.threadObject;
                return leftIdentity < rightIdentity;
            });
        return snapshot;
    }

    bool usedNtQuery = false;
    std::string ignoredR3Diagnostic;
    const std::vector<ks::process::SystemThreadRecord> systemThreads =
        ks::process::EnumerateSystemThreads(&usedNtQuery, &ignoredR3Diagnostic);
    snapshot.usedNtQuery = usedNtQuery;
    if (systemThreads.empty())
    {
        snapshot.diagnosticFlags |= DiagnosticR3EnumerationEmpty;
    }

    const ksword::ark::ThreadEnumResult r0Result = driverClient.enumerateThreads(
        KSWORD_ARK_ENUM_THREAD_FLAG_INCLUDE_WORKER_STATE,
        kSystemProcessId);
    snapshot.r0Available = r0Result.io.ok;
    snapshot.r0Win32Error = r0Result.io.win32Error;
    if (!r0Result.io.ok)
    {
        snapshot.diagnosticFlags |= DiagnosticR0ThreadUnavailable;
    }

    std::unordered_map<std::uint32_t, const ksword::ark::ThreadEntry*> r0ByTid;
    for (const ksword::ark::ThreadEntry& r0Entry : r0Result.entries)
    {
        if (r0Entry.processId == kSystemProcessId && r0Entry.threadId != 0U)
        {
            r0ByTid.insert_or_assign(r0Entry.threadId, &r0Entry);
        }
    }

    const std::vector<ModuleRecord> modules = queryKernelModules(
        &snapshot.moduleQueryStatus,
        &snapshot.moduleNativeStatus,
        &snapshot.moduleRequiredBytes);
    if (snapshot.moduleQueryStatus != ModuleQueryStatus::Ok)
    {
        snapshot.diagnosticFlags |= DiagnosticModuleUnavailable;
    }

    for (const ks::process::SystemThreadRecord& sourceThread : systemThreads)
    {
        if (sourceThread.ownerPid != kSystemProcessId || sourceThread.threadId == 0U)
        {
            continue;
        }

        ThreadRow row;
        row.threadId = sourceThread.threadId;
        row.createTime100ns = sourceThread.createTime100ns;
        row.startAddress = sourceThread.startAddress != 0U
            ? sourceThread.startAddress
            : sourceThread.win32StartAddress;
        row.priority = sourceThread.priority;
        row.basePriority = sourceThread.basePriority;
        row.state = sourceThread.threadState;
        row.waitReason = sourceThread.waitReason;

        const auto r0Iterator = r0ByTid.find(row.threadId);
        if (r0Iterator != r0ByTid.end() && r0Iterator->second != nullptr)
        {
            const ksword::ark::ThreadEntry& r0Entry = *(r0Iterator->second);
            row.r0Flags = r0Entry.flags;
            row.r0FieldFlags = r0Entry.fieldFlags;
            row.r0Status = r0Entry.r0Status;
            row.workerKnown =
                (r0Entry.fieldFlags & KSWORD_ARK_THREAD_FIELD_ACTIVE_EX_WORKER_PRESENT) != 0U;
            row.activeWorker =
                (r0Entry.flags & KSWORD_ARK_THREAD_FLAG_ACTIVE_EX_WORKER) != 0U;
        }

        row.module = findOwnerModule(
            modules,
            row.startAddress,
            &row.moduleResolved);
        // 系统线程页不再按内核归属、未知模块、启动地址或创建时间缺失禁用操作；
        // R0 仅复核请求中实际可用的身份字段，TID 始终是动作入口的必要标识。
        row.protectedTarget = false;
        row.protectionKind = ProtectionKind::BestEffortR0Recheck;
        snapshot.rows.push_back(std::move(row));
    }

    std::sort(
        snapshot.rows.begin(),
        snapshot.rows.end(),
        [](const ThreadRow& left, const ThreadRow& right) {
            return left.threadId < right.threadId;
        });
    return snapshot;
}

std::vector<KernelThreadAuditTab::ModuleRecord>
KernelThreadAuditTab::queryKernelModules(
    ModuleQueryStatus* const queryStatusOut,
    long* const nativeStatusOut,
    unsigned long* const requiredBytesOut)
{
    if (queryStatusOut != nullptr)
    {
        *queryStatusOut = ModuleQueryStatus::Ok;
    }
    if (nativeStatusOut != nullptr)
    {
        *nativeStatusOut = 0L;
    }
    if (requiredBytesOut != nullptr)
    {
        *requiredBytesOut = 0UL;
    }

    HMODULE ntdllModule = ::GetModuleHandleW(L"ntdll.dll");
    const auto querySystemInformation = ntdllModule != nullptr
        ? reinterpret_cast<NtQuerySystemInformationFunction>(
            ::GetProcAddress(ntdllModule, "NtQuerySystemInformation"))
        : nullptr;
    if (querySystemInformation == nullptr)
    {
        if (queryStatusOut != nullptr)
        {
            *queryStatusOut = ModuleQueryStatus::ApiUnavailable;
        }
        return {};
    }

    unsigned long requiredBytes = 0UL;
    LONG status = querySystemInformation(
        kSystemModuleInformationClass,
        nullptr,
        0UL,
        &requiredBytes);
    if (requiredBytesOut != nullptr)
    {
        *requiredBytesOut = requiredBytes;
    }
    if (nativeStatusOut != nullptr)
    {
        *nativeStatusOut = status;
    }
    if (status != kStatusInfoLengthMismatch ||
        requiredBytes < sizeof(RawModuleInformation) ||
        requiredBytes > kMaximumModuleSnapshotBytes)
    {
        if (queryStatusOut != nullptr)
        {
            *queryStatusOut = ModuleQueryStatus::LengthQueryFailed;
        }
        return {};
    }

    std::vector<unsigned char> buffer(
        static_cast<std::size_t>(requiredBytes) + 4096U);
    unsigned long returnedBytes = 0UL;
    status = querySystemInformation(
        kSystemModuleInformationClass,
        buffer.data(),
        static_cast<unsigned long>(buffer.size()),
        &returnedBytes);
    if (nativeStatusOut != nullptr)
    {
        *nativeStatusOut = status;
    }
    if (status != 0L ||
        returnedBytes < offsetof(RawModuleInformation, modules))
    {
        if (queryStatusOut != nullptr)
        {
            *queryStatusOut = ModuleQueryStatus::SnapshotFailed;
        }
        return {};
    }

    const auto* const rawInformation =
        reinterpret_cast<const RawModuleInformation*>(buffer.data());
    const std::size_t headerBytes = offsetof(RawModuleInformation, modules);
    const std::size_t availableEntries =
        (static_cast<std::size_t>(returnedBytes) - headerBytes) /
        sizeof(RawModuleEntry);
    const std::size_t safeEntryCount = (std::min)(
        static_cast<std::size_t>(rawInformation->moduleCount),
        availableEntries);

    std::vector<ModuleRecord> modules;
    modules.reserve(safeEntryCount);
    for (std::size_t moduleIndex = 0U;
         moduleIndex < safeEntryCount;
         ++moduleIndex)
    {
        const RawModuleEntry& rawModule = rawInformation->modules[moduleIndex];
        const std::size_t pathLength = boundedAnsiLength(
            rawModule.fullPathName,
            sizeof(rawModule.fullPathName));
        const QByteArray pathBytes(
            reinterpret_cast<const char*>(rawModule.fullPathName),
            static_cast<int>(pathLength));

        ModuleRecord module;
        module.path = QString::fromLocal8Bit(pathBytes);
        module.baseAddress = static_cast<std::uint64_t>(
            reinterpret_cast<std::uintptr_t>(rawModule.imageBase));
        module.imageSize = rawModule.imageSize;
        module.kernelImage = moduleIndex == 0U;
        if (rawModule.fileNameOffset < pathLength)
        {
            module.name = QString::fromLocal8Bit(
                pathBytes.constData() + rawModule.fileNameOffset,
                static_cast<int>(pathLength - rawModule.fileNameOffset));
        }
        if (module.name.isEmpty())
        {
            module.name = module.path.section(QLatin1Char('\\'), -1);
        }
        modules.push_back(std::move(module));
    }
    return modules;
}

KernelThreadAuditTab::ModuleRecord KernelThreadAuditTab::findOwnerModule(
    const std::vector<ModuleRecord>& modules,
    const std::uint64_t address,
    bool* const matchedOut)
{
    if (matchedOut != nullptr)
    {
        *matchedOut = false;
    }
    if (address == 0U)
    {
        return {};
    }

    for (const ModuleRecord& module : modules)
    {
        const std::uint64_t moduleEnd =
            checkedAddressEnd(module.baseAddress, module.imageSize);
        if (module.baseAddress != 0U &&
            address >= module.baseAddress &&
            address < moduleEnd)
        {
            if (matchedOut != nullptr)
            {
                *matchedOut = true;
            }
            return module;
        }
    }
    return {};
}
