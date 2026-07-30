#include "KernelThreadAuditTab.h"

#include "../ArkDriverClient/ArkDriverClient.h"
#include "../Internationalization/LanguageManager.h"

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
    // threadAuditSnapshotText：
    // - 输入语言键和中文回退文本；
    // - 返回后台快照中需要持久化的本地化保护原因。
    QString threadAuditSnapshotText(const char* key, const QString& fallbackText)
    {
        return ks::i18n::contextText(QString::fromLatin1(key), fallbackText);
    }

    // NtQuerySystemInformationFunction：查询安全模块范围所需的 ntdll 入口。
    using NtQuerySystemInformationFunction = LONG(NTAPI*)(
        unsigned long,
        void*,
        unsigned long,
        unsigned long*);

    // RawModuleEntry：SystemModuleInformation 固定模块行布局。
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

    // RawModuleInformation：模块数量和首行。
    struct RawModuleInformation
    {
        unsigned long moduleCount;
        RawModuleEntry modules[1];
    };

    constexpr unsigned long kSystemModuleInformationClass = 11UL; // SystemModuleInformation。
    constexpr LONG kStatusInfoLengthMismatch = static_cast<LONG>(0xC0000004UL); // 缓冲长度状态。
    constexpr std::size_t kMaximumModuleSnapshotBytes = 16U * 1024U * 1024U; // 最大安全分配。
    constexpr std::uint32_t kSystemProcessId = 4U; // Windows System PID。
    constexpr std::uint32_t kWaitReasonQueue = 15U; // KWAIT_REASON::WrQueue。

    // boundedAnsiLength：
    // - 输入固定 ANSI 缓冲和上限；
    // - 返回首个 NUL 前长度，避免依赖非标准 strnlen；
    // - 缓冲无 NUL 时返回上限。
    std::size_t boundedAnsiLength(const unsigned char* text, const std::size_t capacity)
    {
        if (text == nullptr)
        {
            return 0U;
        }
        for (std::size_t index = 0; index < capacity; ++index)
        {
            if (text[index] == 0U)
            {
                return index;
            }
        }
        return capacity;
    }

    // checkedAddressEnd：
    // - 输入模块基址和大小；
    // - 返回饱和计算后的末地址，防止范围加法回绕。
    std::uint64_t checkedAddressEnd(const std::uint64_t baseAddress, const std::uint32_t imageSize)
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
    bool usedNtQuery = false;
    std::string r3Diagnostic;
    std::vector<ks::process::SystemThreadRecord> systemThreads =
        ks::process::EnumerateSystemThreads(&usedNtQuery, &r3Diagnostic);
    snapshot.usedNtQuery = usedNtQuery;
    snapshot.diagnosticText = QString::fromStdString(r3Diagnostic);

    // R0 扩展只查询 PID 4，并只请求 worker 标志，避免无关 KTHREAD 字段读取。
    const ksword::ark::DriverClient driverClient;
    const ksword::ark::ThreadEnumResult r0Result = driverClient.enumerateThreads(
        KSWORD_ARK_ENUM_THREAD_FLAG_INCLUDE_WORKER_STATE,
        kSystemProcessId);
    snapshot.r0Available = r0Result.io.ok;
    if (!r0Result.io.ok)
    {
        const QString r0Diagnostic = QString::fromStdString(r0Result.io.message);
        if (!r0Diagnostic.trimmed().isEmpty())
        {
            snapshot.diagnosticText += QStringLiteral(" | R0: %1").arg(r0Diagnostic);
        }
    }

    std::unordered_map<std::uint32_t, const ksword::ark::ThreadEntry*> r0ByTid;
    for (const ksword::ark::ThreadEntry& r0Entry : r0Result.entries)
    {
        if (r0Entry.processId == kSystemProcessId && r0Entry.threadId != 0U)
        {
            r0ByTid.insert_or_assign(r0Entry.threadId, &r0Entry);
        }
    }

    QString moduleErrorText;
    const std::vector<ModuleRecord> modules = queryKernelModules(&moduleErrorText);
    if (!moduleErrorText.isEmpty())
    {
        snapshot.diagnosticText += QStringLiteral(" | Modules: %1").arg(moduleErrorText);
    }

    // 只合并 System(PID 4)；工作队列模式再按可靠候选标志过滤。
    for (const ks::process::SystemThreadRecord& sourceThread : systemThreads)
    {
        if (sourceThread.ownerPid != kSystemProcessId || sourceThread.threadId == 0U)
        {
            continue;
        }

        ThreadRow row;
        row.threadId = sourceThread.threadId;
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

        row.workerCandidate = row.activeWorker || row.waitReason == kWaitReasonQueue;
        row.module = findOwnerModule(modules, row.startAddress, &row.moduleResolved);

        // R3 前置保护：未知归属、内核映像和 KswordARK 自身一律禁用操作。
        if (!row.moduleResolved)
        {
            row.protectedTarget = true;
            row.protectionReason = threadAuditSnapshotText(
                "thread_audit.protection.unknown",
                QStringLiteral("启动入口归属未知"));
        }
        else if (row.module.kernelImage)
        {
            row.protectedTarget = true;
            row.protectionReason = threadAuditSnapshotText(
                "thread_audit.protection.kernel",
                QStringLiteral("Windows 内核线程"));
        }
        else if (row.module.name.contains(QStringLiteral("KswordARK"), Qt::CaseInsensitive))
        {
            row.protectedTarget = true;
            row.protectionReason = threadAuditSnapshotText(
                "thread_audit.protection.self",
                QStringLiteral("KswordARK 自身线程"));
        }
        else
        {
            row.protectedTarget = false;
            row.protectionReason = threadAuditSnapshotText(
                "thread_audit.protection.r0_recheck",
                QStringLiteral("第三方模块；操作时由 R0 再校验"));
        }

        if (mode == Mode::SystemThreads || row.workerCandidate)
        {
            snapshot.rows.push_back(std::move(row));
        }
    }

    std::sort(
        snapshot.rows.begin(),
        snapshot.rows.end(),
        [](const ThreadRow& left, const ThreadRow& right) {
            return left.threadId < right.threadId;
        });
    return snapshot;
}

std::vector<KernelThreadAuditTab::ModuleRecord> KernelThreadAuditTab::queryKernelModules(QString* errorTextOut)
{
    if (errorTextOut != nullptr)
    {
        errorTextOut->clear();
    }

    HMODULE ntdllModule = ::GetModuleHandleW(L"ntdll.dll");
    const auto querySystemInformation = ntdllModule != nullptr
        ? reinterpret_cast<NtQuerySystemInformationFunction>(
            ::GetProcAddress(ntdllModule, "NtQuerySystemInformation"))
        : nullptr;
    if (querySystemInformation == nullptr)
    {
        if (errorTextOut != nullptr)
        {
            *errorTextOut = QStringLiteral("NtQuerySystemInformation unavailable");
        }
        return {};
    }

    unsigned long requiredBytes = 0UL;
    LONG status = querySystemInformation(
        kSystemModuleInformationClass,
        nullptr,
        0UL,
        &requiredBytes);
    if (status != kStatusInfoLengthMismatch || requiredBytes < sizeof(RawModuleInformation) ||
        requiredBytes > kMaximumModuleSnapshotBytes)
    {
        if (errorTextOut != nullptr)
        {
            *errorTextOut = QStringLiteral("module length query failed, status=0x%1, bytes=%2")
                .arg(static_cast<unsigned long>(status), 8, 16, QLatin1Char('0'))
                .arg(requiredBytes);
        }
        return {};
    }

    std::vector<unsigned char> buffer(static_cast<std::size_t>(requiredBytes) + 4096U);
    unsigned long returnedBytes = 0UL;
    status = querySystemInformation(
        kSystemModuleInformationClass,
        buffer.data(),
        static_cast<unsigned long>(buffer.size()),
        &returnedBytes);
    if (status != 0L || returnedBytes < offsetof(RawModuleInformation, modules))
    {
        if (errorTextOut != nullptr)
        {
            *errorTextOut = QStringLiteral("module query failed, status=0x%1")
                .arg(static_cast<unsigned long>(status), 8, 16, QLatin1Char('0'));
        }
        return {};
    }

    const auto* rawInformation = reinterpret_cast<const RawModuleInformation*>(buffer.data());
    const std::size_t headerBytes = offsetof(RawModuleInformation, modules);
    const std::size_t availableEntries =
        (static_cast<std::size_t>(returnedBytes) - headerBytes) / sizeof(RawModuleEntry);
    const std::size_t safeEntryCount = (std::min)(
        static_cast<std::size_t>(rawInformation->moduleCount),
        availableEntries);

    std::vector<ModuleRecord> modules;
    modules.reserve(safeEntryCount);
    for (std::size_t moduleIndex = 0; moduleIndex < safeEntryCount; ++moduleIndex)
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
    bool* matchedOut)
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
        const std::uint64_t moduleEnd = checkedAddressEnd(module.baseAddress, module.imageSize);
        if (module.baseAddress != 0U && address >= module.baseAddress && address < moduleEnd)
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
