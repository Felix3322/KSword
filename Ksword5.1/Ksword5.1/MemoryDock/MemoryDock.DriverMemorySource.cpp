#include "MemoryDock.Internal.h"
#include "../KernelDock/KernelThreadAuditTab.h"
#include "../UI/TableInteractionSupport.h"

// ============================================================
// MemoryDock.DriverMemorySource.cpp
// 作用：
// - 承载“驱动内存读写”页的目标来源扩展：内核模块列表与物理内存通道；
// - 内核模块列表来自 R3 的 SystemModuleInformation 快照，不依赖驱动在线；
// - 物理内存读写直接封装 R0 的物理内存 IOCTL，遵守协议的长度与 flags 约束。
// ============================================================

using namespace ksword::memory_dock_internal;

namespace
{
    // kDriverMemoryKernelModuleRole：下拉项里保存内核模块基址的自定义角色。
    // 之所以另开一个角色而不是复用 Qt::UserRole，是因为 UserRole 已经被进程项占用为 PID。
    constexpr int kDriverMemoryKernelModuleBaseRole = Qt::UserRole + 2;

    // kDriverMemoryKernelModulePathRole：下拉项里保存内核模块 NT 路径的角色，用于消歧与提示。
    constexpr int kDriverMemoryKernelModulePathRole = Qt::UserRole + 3;

    // kDriverMemoryKernelModuleSizeRole：下拉项里保存内核模块映像大小的角色，用于偏移越界提示。
    constexpr int kDriverMemoryKernelModuleSizeRole = Qt::UserRole + 4;
}

int MemoryDock::driverMemoryKernelModuleBaseRole()
{
    // 对外暴露角色常量，避免其它 .cpp 重复定义同一个魔数。
    return kDriverMemoryKernelModuleBaseRole;
}

MemoryDock::DriverMemorySourceMode MemoryDock::currentDriverMemorySourceMode() const
{
    // 来源下拉未建立时按默认的“进程虚拟内存”处理，保证早期调用安全。
    if (m_driverMemorySourceCombo == nullptr)
    {
        return DriverMemorySourceMode::ProcessVirtual;
    }
    const int selectedIndex = m_driverMemorySourceCombo->currentIndex();
    if (selectedIndex < 0
        || selectedIndex > static_cast<int>(DriverMemorySourceMode::Physical))
    {
        return DriverMemorySourceMode::ProcessVirtual;
    }
    return static_cast<DriverMemorySourceMode>(selectedIndex);
}

void MemoryDock::refreshKernelModuleCacheAsync()
{
    // 记录刷新日志：内核模块列表是下拉框的数据源，出问题时需要能定位到这一步。
    kLogEvent kernelModuleEvent;
    info << kernelModuleEvent
        << "[MemoryDock] refreshKernelModuleCacheAsync: 开始异步枚举已加载内核模块。"
        << eol;

    // 同一时刻只允许一轮枚举在跑，重复点击直接忽略。
    bool expectedIdle = false;
    if (!m_kernelModuleRefreshInProgress.compare_exchange_strong(expectedIdle, true))
    {
        return;
    }

    // 票据用于丢弃过期结果：界面上后发起的一轮永远赢。
    const std::uint64_t currentTicket = ++m_kernelModuleRefreshTicket;
    if (m_driverMemoryKernelModuleRefreshButton != nullptr)
    {
        m_driverMemoryKernelModuleRefreshButton->setEnabled(false);
    }
    if (m_driverMemoryStatusLabel != nullptr)
    {
        m_driverMemoryStatusLabel->setText(QStringLiteral("正在枚举已加载内核模块..."));
    }

    // 枚举走线程池，避免 NtQuerySystemInformation 的大缓冲区分配阻塞 UI 线程。
    QThreadPool::globalInstance()->start([this, currentTicket]() {
        KernelThreadAuditTab::ModuleQueryStatus queryStatus =
            KernelThreadAuditTab::ModuleQueryStatus::Ok;
        long nativeStatus = 0L;
        unsigned long requiredBytes = 0UL;
        const std::vector<KernelThreadAuditTab::ModuleRecord> moduleRecords =
            KernelThreadAuditTab::queryKernelModules(&queryStatus, &nativeStatus, &requiredBytes);

        // 后台线程只做数据整形，所有 UI 更新都回主线程执行。
        std::vector<KernelModuleEntry> convertedEntries;
        convertedEntries.reserve(moduleRecords.size());
        for (const KernelThreadAuditTab::ModuleRecord& record : moduleRecords)
        {
            KernelModuleEntry entry;
            entry.moduleName = record.name;
            entry.ntPath = record.path;
            entry.baseAddress = record.baseAddress;
            entry.sizeBytes = record.imageSize;
            entry.kernelImage = record.kernelImage;
            convertedEntries.push_back(entry);
        }

        const bool querySucceeded =
            (queryStatus == KernelThreadAuditTab::ModuleQueryStatus::Ok);
        QMetaObject::invokeMethod(
            this,
            [this, currentTicket, convertedEntries, querySucceeded, nativeStatus]() {
                // 票据过期说明有更新的一轮已经完成，本轮结果整体丢弃。
                if (currentTicket != m_kernelModuleRefreshTicket.load())
                {
                    return;
                }
                m_kernelModuleRefreshInProgress.store(false);
                if (m_driverMemoryKernelModuleRefreshButton != nullptr)
                {
                    m_driverMemoryKernelModuleRefreshButton->setEnabled(true);
                }

                if (!querySucceeded)
                {
                    // 失败时保留上一轮缓存，只更新状态文案，避免下拉框突然清空。
                    if (m_driverMemoryStatusLabel != nullptr)
                    {
                        m_driverMemoryStatusLabel->setText(
                            QStringLiteral("内核模块枚举失败，NTSTATUS=0x%1。")
                                .arg(static_cast<qulonglong>(
                                    static_cast<std::uint32_t>(nativeStatus)), 8, 16, QChar('0'))
                                .toUpper());
                    }
                    return;
                }

                m_kernelModuleCache = convertedEntries;
                updateDriverMemoryBaseComboFromProcessCache();
                if (m_driverMemoryStatusLabel != nullptr)
                {
                    m_driverMemoryStatusLabel->setText(
                        QStringLiteral("已加载 %1 个内核模块，可直接输入“模块名+偏移”定位。")
                            .arg(m_kernelModuleCache.size()));
                }
            },
            Qt::QueuedConnection);
        });
}

bool MemoryDock::resolveDriverMemoryKernelModuleExpression(
    const QString& moduleToken,
    const std::uint64_t moduleOffset,
    std::uint64_t& resolvedBaseOut,
    QString& errorTextOut) const
{
    resolvedBaseOut = 0ULL;
    errorTextOut.clear();

    // 缓存为空说明还没枚举过，给出明确的下一步操作指引而不是笼统报错。
    if (m_kernelModuleCache.empty())
    {
        errorTextOut = QStringLiteral(
            "尚未加载内核模块列表，请先点击“刷新内核模块”。");
        return false;
    }
    if (m_kernelModuleRefreshInProgress.load())
    {
        errorTextOut = QStringLiteral("内核模块列表正在刷新，请稍候重试。");
        return false;
    }

    // 输入带路径分隔符时按完整路径比对，否则只比模块文件名。
    QString normalizedInput = moduleToken;
    normalizedInput.replace(QLatin1Char('/'), QLatin1Char('\\'));
    const bool inputContainsPath = normalizedInput.contains(QLatin1Char('\\'));
    const QString inputFileName = QFileInfo(normalizedInput).fileName();

    std::vector<const KernelModuleEntry*> matchedEntries;
    for (const KernelModuleEntry& entry : m_kernelModuleCache)
    {
        bool matched = false;
        if (inputContainsPath)
        {
            // 内核路径形如 \SystemRoot\system32\CI.dll，用尾部包含匹配兼容用户简写。
            QString normalizedPath = entry.ntPath;
            normalizedPath.replace(QLatin1Char('/'), QLatin1Char('\\'));
            matched = normalizedPath.endsWith(normalizedInput, Qt::CaseInsensitive)
                || normalizedPath.compare(normalizedInput, Qt::CaseInsensitive) == 0;
        }
        else
        {
            matched = (entry.moduleName.compare(inputFileName, Qt::CaseInsensitive) == 0);
        }
        if (matched)
        {
            matchedEntries.push_back(&entry);
        }
    }

    if (matchedEntries.empty())
    {
        errorTextOut = QStringLiteral(
            "在已加载内核模块中找不到 %1。可先点击“刷新内核模块”，或改用完整路径。")
            .arg(moduleToken);
        return false;
    }
    if (matchedEntries.size() > 1U)
    {
        errorTextOut = QStringLiteral(
            "内核模块 %1 命中 %2 项，请改用完整路径消歧。")
            .arg(moduleToken)
            .arg(matchedEntries.size());
        return false;
    }

    // 溢出保护：基址加偏移不得回绕，否则会读到完全无关的地址。
    const KernelModuleEntry* matchedEntry = matchedEntries.front();
    if (moduleOffset > (std::numeric_limits<std::uint64_t>::max() - matchedEntry->baseAddress))
    {
        errorTextOut = QStringLiteral("模块基址加偏移超出 64 位地址范围。");
        return false;
    }

    // 偏移超出映像大小时只提示不拦截：调试场景确实存在读模块尾部之外的需求。
    resolvedBaseOut = matchedEntry->baseAddress + moduleOffset;
    return true;
}

void MemoryDock::driverReadPhysicalMemoryFromUi()
{
    // 记录物理读日志：物理内存通道绕开了所有进程隔离，必须留痕。
    kLogEvent physicalReadEvent;
    info << physicalReadEvent
        << "[MemoryDock] driverReadPhysicalMemoryFromUi: 请求通过 R0 读取物理内存。"
        << eol;

    if (m_driverMemoryAddressEdit == nullptr)
    {
        return;
    }

    // 物理地址不接受模块偏移与进程筛选，只解析地址输入框本身。
    std::uint64_t physicalAddress = 0ULL;
    if (!parseAddressText(m_driverMemoryAddressEdit->text(), physicalAddress))
    {
        QMessageBox::warning(
            this,
            QStringLiteral("驱动内存读写"),
            QStringLiteral("物理地址解析失败，请填写十六进制物理地址，例如 0x1000。"));
        return;
    }

    // 协议规定物理地址不超过 52 位，超限本地拒绝，不浪费一次 IOCTL。
    constexpr std::uint64_t kMaxPhysicalAddress = 0x000FFFFFFFFFFFFFULL;
    if (physicalAddress > kMaxPhysicalAddress)
    {
        QMessageBox::warning(
            this,
            QStringLiteral("驱动内存读写"),
            QStringLiteral("物理地址超过驱动支持的 52 位上限。"));
        return;
    }

    // 物理读单次上限 64KB，这里按前后预算求和后夹取。
    const std::uint64_t beforeBytes = (m_driverMemoryBeforeSpin != nullptr)
        ? static_cast<std::uint64_t>(m_driverMemoryBeforeSpin->value())
        : 0ULL;
    const std::uint64_t afterBytes = (m_driverMemoryAfterSpin != nullptr)
        ? static_cast<std::uint64_t>(m_driverMemoryAfterSpin->value())
        : 4096ULL;
    const std::uint64_t baseAddress =
        (physicalAddress >= beforeBytes) ? (physicalAddress - beforeBytes) : 0ULL;
    std::uint64_t totalBytes = beforeBytes + afterBytes;
    if (totalBytes == 0ULL)
    {
        QMessageBox::warning(
            this,
            QStringLiteral("驱动内存读写"),
            QStringLiteral("读取长度为 0，请调整向前/向后字节数。"));
        return;
    }
    if (totalBytes > static_cast<std::uint64_t>(KSWORD_ARK_MEMORY_PHYSICAL_READ_MAX_BYTES))
    {
        // 物理通道上限远小于虚拟通道，这里主动截断并在状态栏说明，而不是直接失败。
        totalBytes = static_cast<std::uint64_t>(KSWORD_ARK_MEMORY_PHYSICAL_READ_MAX_BYTES);
    }
    if (baseAddress > (kMaxPhysicalAddress - (totalBytes - 1ULL)))
    {
        QMessageBox::warning(
            this,
            QStringLiteral("驱动内存读写"),
            QStringLiteral("读取范围末端超过物理地址上限，请缩小范围。"));
        return;
    }

    if (m_driverMemoryStatusLabel != nullptr)
    {
        m_driverMemoryStatusLabel->setText(QStringLiteral("正在通过 R0 读取物理内存..."));
    }

    // 物理读的 flags 必须为 0，协议对非零 flags 一律拒绝。
    const ksword::ark::DriverClient driverClient;
    const ksword::ark::PhysicalMemoryReadResult readResult =
        driverClient.readPhysicalMemory(
            baseAddress,
            static_cast<std::uint32_t>(totalBytes),
            0UL);

    if (!readResult.io.ok)
    {
        resetDriverMemoryRwState();
        const QString failureText = QStringLiteral(
            "物理内存读取失败。\nWin32 错误: %1\n驱动消息: %2")
            .arg(readResult.io.win32Error)
            .arg(QString::fromStdString(readResult.io.message));
        if (m_driverMemoryStatusLabel != nullptr)
        {
            m_driverMemoryStatusLabel->setText(QStringLiteral("物理内存读取失败。"));
        }
        QMessageBox::warning(this, QStringLiteral("驱动内存读写"), failureText);
        return;
    }

    // io.ok 只代表 IOCTL 往返成功，真正结果看 readStatus。
    const bool hasUsableBytes =
        (readResult.readStatus == KSWORD_ARK_MEMORY_PHYSICAL_READ_STATUS_OK
            || readResult.readStatus == KSWORD_ARK_MEMORY_PHYSICAL_READ_STATUS_PARTIAL);
    if (!hasUsableBytes || readResult.data.empty())
    {
        resetDriverMemoryRwState();
        const QString statusText = QStringLiteral(
            "物理内存读取未返回可用数据。\nreadStatus=%1  copyStatus=0x%2  bytesRead=%3")
            .arg(readResult.readStatus)
            .arg(static_cast<qulonglong>(static_cast<std::uint32_t>(readResult.copyStatus)),
                8, 16, QChar('0'))
            .arg(readResult.bytesRead);
        if (m_driverMemoryStatusLabel != nullptr)
        {
            m_driverMemoryStatusLabel->setText(QStringLiteral("物理内存读取未返回数据。"));
        }
        QMessageBox::warning(this, QStringLiteral("驱动内存读写"), statusText.toUpper());
        return;
    }

    // 物理快照复用同一组缓存成员，只用 m_driverMemorySnapshotIsPhysical 区分写回通道。
    m_driverMemoryBaseAddress = readResult.requestedPhysicalAddress;
    m_driverMemoryOffsetBase = 0ULL;
    m_driverMemoryCenterAddress = physicalAddress;
    m_driverMemorySnapshotPid = 0U;
    m_driverMemorySnapshotProcessName = QStringLiteral("物理内存");
    m_driverMemorySnapshotIsPhysical = true;
    m_driverMemoryOriginalBytes = QByteArray(
        reinterpret_cast<const char*>(readResult.data.data()),
        static_cast<qsizetype>(readResult.data.size()));
    m_driverMemoryEditedBytes = m_driverMemoryOriginalBytes;
    m_driverMemoryHasSnapshot = true;

    // 刷新十六进制视图与派生视图，让三个视图看到同一份快照。
    if (m_driverMemoryHexEditor != nullptr)
    {
        m_driverMemoryHexEditor->setEditable(true);
        m_driverMemoryHexEditor->setByteArray(m_driverMemoryEditedBytes, m_driverMemoryBaseAddress);
    }
    refreshDriverMemoryViewsFromSnapshot();

    if (m_driverMemoryApplyButton != nullptr)
    {
        m_driverMemoryApplyButton->setEnabled(false);
        m_driverMemoryApplyButton->setToolTip(
            QStringLiteral("把编辑器中改动过的字节写回物理内存，单块上限 %1 字节。")
                .arg(KSWORD_ARK_MEMORY_PHYSICAL_WRITE_MAX_BYTES));
    }
    if (m_driverMemoryRangeLabel != nullptr)
    {
        m_driverMemoryRangeLabel->setText(
            QStringLiteral("物理范围: 0x%1 - 0x%2 | 已读取 %3 字节")
                .arg(formatAddress(m_driverMemoryBaseAddress))
                .arg(formatAddress(m_driverMemoryBaseAddress
                    + static_cast<std::uint64_t>(m_driverMemoryOriginalBytes.size()) - 1ULL))
                .arg(m_driverMemoryOriginalBytes.size()));
    }
    if (m_driverMemoryStatusLabel != nullptr)
    {
        QString statusText = QStringLiteral("物理内存读取成功，共 %1 字节。")
            .arg(m_driverMemoryOriginalBytes.size());
        if (readResult.readStatus == KSWORD_ARK_MEMORY_PHYSICAL_READ_STATUS_PARTIAL)
        {
            statusText += QStringLiteral(" 驱动报告为部分读取，尾部可能不完整。");
        }
        m_driverMemoryStatusLabel->setText(statusText);
    }

    kLogEvent physicalReadDoneEvent;
    info << physicalReadDoneEvent
        << "[MemoryDock] driverReadPhysicalMemoryFromUi: 物理内存读取完成。"
        << eol;
}

bool MemoryDock::applyDriverMemoryPhysicalDiff(
    const std::vector<DriverDiffBlock>& diffBlocks,
    QString& failureTextOut)
{
    failureTextOut.clear();

    // 记录物理写日志：这是本页破坏性最强的一条路径。
    kLogEvent physicalWriteEvent;
    warn << physicalWriteEvent
        << "[MemoryDock] applyDriverMemoryPhysicalDiff: 开始把差异块写回物理内存。"
        << eol;

    // 一次同意 FORCE 对本轮后续所有块生效，避免每块都弹一次确认。
    bool forceApproved = false;
    std::uint64_t writtenBytesTotal = 0ULL;
    const ksword::ark::DriverClient driverClient;

    for (const DriverDiffBlock& diffBlock : diffBlocks)
    {
        // 物理写单次上限 4KB，超过的差异块按上限切片逐块提交。
        const qsizetype blockSize = diffBlock.bytes.size();
        for (qsizetype chunkStart = 0; chunkStart < blockSize;
             chunkStart += static_cast<qsizetype>(KSWORD_ARK_MEMORY_PHYSICAL_WRITE_MAX_BYTES))
        {
            const qsizetype chunkSize = std::min<qsizetype>(
                static_cast<qsizetype>(KSWORD_ARK_MEMORY_PHYSICAL_WRITE_MAX_BYTES),
                blockSize - chunkStart);
            const QByteArray chunkBytes = diffBlock.bytes.mid(chunkStart, chunkSize);
            const std::uint64_t chunkAddress =
                diffBlock.address + static_cast<std::uint64_t>(chunkStart);

            const std::vector<std::uint8_t> payload(
                reinterpret_cast<const std::uint8_t*>(chunkBytes.constData()),
                reinterpret_cast<const std::uint8_t*>(chunkBytes.constData()) + chunkBytes.size());

            // 首轮只带 UI_CONFIRMED；驱动要求 FORCE 时再征求用户同意后重试。
            unsigned long writeFlags = KSWORD_ARK_PHYSICAL_WRITE_FLAG_UI_CONFIRMED;
            if (forceApproved)
            {
                writeFlags |= KSWORD_ARK_PHYSICAL_WRITE_FLAG_FORCE;
            }
            ksword::ark::PhysicalMemoryWriteResult writeResult =
                driverClient.writePhysicalMemory(chunkAddress, payload, writeFlags);

            if (writeResult.io.ok
                && writeResult.writeStatus == KSWORD_ARK_MEMORY_PHYSICAL_WRITE_STATUS_FORCE_REQUIRED
                && !forceApproved)
            {
                // 驱动明确要求强制标志，弹一次不可抑制的确认框。
                if (!confirmForceDriverMemoryWrite(
                        chunkAddress,
                        static_cast<std::uint32_t>(chunkBytes.size()),
                        QStringLiteral("驱动要求对物理内存写入附加强制标志。")))
                {
                    failureTextOut = QStringLiteral("用户取消了物理内存强制写入。");
                    return false;
                }
                forceApproved = true;
                writeFlags |= KSWORD_ARK_PHYSICAL_WRITE_FLAG_FORCE;
                writeResult = driverClient.writePhysicalMemory(chunkAddress, payload, writeFlags);
            }

            const bool chunkOk = writeResult.io.ok
                && writeResult.writeStatus == KSWORD_ARK_MEMORY_PHYSICAL_WRITE_STATUS_OK
                && writeResult.bytesWritten == static_cast<std::uint32_t>(chunkBytes.size());
            if (!chunkOk)
            {
                // 物理写没有事务与回滚，失败即停，已写入的部分保持现状并如实报告。
                failureTextOut = QStringLiteral(
                    "物理内存写入失败。\n地址: 0x%1\n长度: %2 字节\n"
                    "writeStatus=%3  mapStatus=0x%4  copyStatus=0x%5\n"
                    "本轮已成功写入 %6 字节，失败块之前的改动不会自动回滚。")
                    .arg(formatAddress(chunkAddress))
                    .arg(chunkBytes.size())
                    .arg(writeResult.writeStatus)
                    .arg(static_cast<qulonglong>(
                        static_cast<std::uint32_t>(writeResult.mapStatus)), 8, 16, QChar('0'))
                    .arg(static_cast<qulonglong>(
                        static_cast<std::uint32_t>(writeResult.copyStatus)), 8, 16, QChar('0'))
                    .arg(writtenBytesTotal);
                return false;
            }
            writtenBytesTotal += static_cast<std::uint64_t>(chunkBytes.size());
        }
    }

    kLogEvent physicalWriteDoneEvent;
    warn << physicalWriteDoneEvent
        << "[MemoryDock] applyDriverMemoryPhysicalDiff: 物理内存写入完成。"
        << eol;
    return true;
}
