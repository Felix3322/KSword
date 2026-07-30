#include "DiskMonitorStoragePanel.h"

#include "../UI/VisibleTableWidget.h"
#include "../theme.h"

#include <QAbstractItemView>
#include <QBrush>
#include <QColor>
#include <QHeaderView>
#include <QSet>
#include <QSignalBlocker>
#include <QTableWidget>
#include <QTableWidgetItem>
#include <QVBoxLayout>

#include <algorithm>
#include <cmath>
#include <cwchar>
#include <iterator>
#include <limits>
#include <utility>

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#include <winioctl.h>

struct DiskMonitorStoragePerformanceState
{
    struct Lease
    {
        QString volumeGuidName;
        QString storageManagerName;
        std::array<std::uint16_t, 8> storageManagerIdentity{};
        std::uint32_t volumeSerialNumber = 0U;
        std::uint32_t storageDeviceNumber = 0U;
        HANDLE volumeHandle = INVALID_HANDLE_VALUE;
        std::uint32_t ownedEnableReferenceCount = 0U;
        bool lifecycleHealthy = true;
    };

    QHash<QString, Lease> leaseByVolumeGuid;
};

namespace
{
    constexpr int kStorageColumnDrive = 0;          // kStorageColumnDrive：卷根目录列。
    constexpr int kStorageColumnLabel = 1;          // kStorageColumnLabel：卷标列。
    constexpr int kStorageColumnFileSystem = 2;     // kStorageColumnFileSystem：文件系统列。
    constexpr int kStorageColumnActiveTime = 3;     // kStorageColumnActiveTime：活动时间百分比列。
    constexpr int kStorageColumnAvailable = 4;      // kStorageColumnAvailable：可用空间列。
    constexpr int kStorageColumnTotal = 5;          // kStorageColumnTotal：总空间列。
    constexpr int kStorageColumnReadRate = 6;       // kStorageColumnReadRate：读取速率列。
    constexpr int kStorageColumnWriteRate = 7;      // kStorageColumnWriteRate：写入速率列。
    constexpr int kStorageColumnResponse = 8;       // kStorageColumnResponse：平均响应时间列。
    constexpr int kStorageColumnQueueDepth = 9;     // kStorageColumnQueueDepth：队列深度列。
    constexpr int kStorageColumnCount = 10;         // kStorageColumnCount：存储表总列数。

    std::uint64_t nonNegativeLargeInteger(const LARGE_INTEGER value)
    {
        // nonNegativeLargeInteger：
        // - 输入：Windows 磁盘性能 LARGE_INTEGER；
        // - 返回：负值按 0 处理，避免转换为极大的无符号数。
        return value.QuadPart > 0
            ? static_cast<std::uint64_t>(value.QuadPart)
            : 0U;
    }

    bool samplingShouldStop(const std::atomic_bool* stopRequested)
    {
        return stopRequested != nullptr &&
            stopRequested->load(std::memory_order_acquire);
    }

    QString storageManagerName(const DISK_PERFORMANCE& performance)
    {
        int characterCount = 0;
        while (characterCount < static_cast<int>(std::size(performance.StorageManagerName)) &&
               performance.StorageManagerName[characterCount] != L'\0')
        {
            ++characterCount;
        }
        return QString::fromWCharArray(
            performance.StorageManagerName,
            characterCount).trimmed();
    }

    QString normalizedVolumeGuidName(const QString& volumeGuidName)
    {
        QString normalizedName = volumeGuidName.trimmed();
        normalizedName.replace(QLatin1Char('/'), QLatin1Char('\\'));
        return normalizedName.toUpper();
    }

    bool hasStorageManagerIdentity(
        const std::array<std::uint16_t, 8>& managerIdentity)
    {
        return std::any_of(
            managerIdentity.cbegin(),
            managerIdentity.cend(),
            [](const std::uint16_t character)
            {
                return character != 0U;
            });
    }

    QString storageManagerIdentityKey(
        const std::array<std::uint16_t, 8>& managerIdentity)
    {
        QString key;
        key.reserve(static_cast<int>(managerIdentity.size() * 4U));
        for (const std::uint16_t character : managerIdentity)
        {
            key.append(
                QString::number(character, 16)
                    .rightJustified(4, QLatin1Char('0')));
        }
        return key;
    }

    QString storageIdentityKey(const DiskMonitorStorageSample& sample)
    {
        if (sample.volumeGuidName.isEmpty() ||
            !sample.volumeSerialAvailable ||
            !hasStorageManagerIdentity(sample.storageManagerIdentity) ||
            !sample.performanceAvailable)
        {
            return {};
        }

        return QStringLiteral("%1|%2|%3|%4")
            .arg(normalizedVolumeGuidName(sample.volumeGuidName))
            .arg(
                QString::number(sample.volumeSerialNumber, 16)
                    .rightJustified(8, QLatin1Char('0')))
            .arg(storageManagerIdentityKey(
                sample.storageManagerIdentity))
            .arg(sample.storageDeviceNumber);
    }

    bool counter32Delta(
        const std::uint32_t currentValue,
        const std::uint32_t previousValue,
        std::uint64_t* deltaOut)
    {
        if (deltaOut == nullptr)
        {
            return false;
        }
        if (currentValue >= previousValue)
        {
            *deltaOut =
                static_cast<std::uint64_t>(currentValue) -
                static_cast<std::uint64_t>(previousValue);
            return true;
        }

        // 只有落在 32 位计数器边界两侧才视为自然回绕；其它下降属于 epoch 重置。
        constexpr std::uint32_t kWrapHighWatermark = 0xf0000000U;
        constexpr std::uint32_t kWrapLowWatermark = 0x0fffffffU;
        if (previousValue >= kWrapHighWatermark &&
            currentValue <= kWrapLowWatermark)
        {
            *deltaOut =
                (static_cast<std::uint64_t>(
                    std::numeric_limits<std::uint32_t>::max()) + 1U) -
                static_cast<std::uint64_t>(previousValue) +
                static_cast<std::uint64_t>(currentValue);
            return true;
        }
        return false;
    }

    bool turnOffOnePerformanceReference(
        DiskMonitorStoragePerformanceState::Lease* lease)
    {
        if (lease == nullptr ||
            lease->volumeHandle == INVALID_HANDLE_VALUE ||
            lease->ownedEnableReferenceCount == 0U)
        {
            return true;
        }

        DWORD returnedBytes = 0U;
        const BOOL releaseOk = DeviceIoControl(
            lease->volumeHandle,
            IOCTL_DISK_PERFORMANCE_OFF,
            nullptr,
            0U,
            nullptr,
            0U,
            &returnedBytes,
            nullptr);
        if (!releaseOk)
        {
            lease->lifecycleHealthy = false;
            return false;
        }
        --lease->ownedEnableReferenceCount;
        return true;
    }

    bool drainOwnedPerformanceReferences(
        DiskMonitorStoragePerformanceState::Lease* lease)
    {
        if (lease == nullptr)
        {
            return true;
        }

        // 只释放本会话记录的引用；失败即停止，避免误减其它监控程序的全局引用。
        while (lease->ownedEnableReferenceCount > 0U)
        {
            if (!turnOffOnePerformanceReference(lease))
            {
                break;
            }
        }
        return lease->ownedEnableReferenceCount == 0U;
    }

    void closePerformanceLeaseHandle(
        DiskMonitorStoragePerformanceState::Lease* lease)
    {
        if (lease == nullptr)
        {
            return;
        }
        if (lease->volumeHandle != INVALID_HANDLE_VALUE)
        {
            CloseHandle(lease->volumeHandle);
            lease->volumeHandle = INVALID_HANDLE_VALUE;
        }
    }

    bool releasePerformanceLease(
        DiskMonitorStoragePerformanceState::Lease* lease)
    {
        if (!drainOwnedPerformanceReferences(lease))
        {
            return false;
        }
        closePerformanceLeaseHandle(lease);
        return true;
    }

    void populatePerformanceSample(
        const DISK_PERFORMANCE& performance,
        const std::uint64_t sampleTickMs,
        DiskMonitorStorageSample* sample)
    {
        if (sample == nullptr)
        {
            return;
        }

        sample->sampleTickMs = sampleTickMs;
        sample->bytesRead = nonNegativeLargeInteger(performance.BytesRead);
        sample->bytesWritten = nonNegativeLargeInteger(performance.BytesWritten);
        sample->readCount = performance.ReadCount;
        sample->writeCount = performance.WriteCount;
        sample->readTime100ns = nonNegativeLargeInteger(performance.ReadTime);
        sample->writeTime100ns = nonNegativeLargeInteger(performance.WriteTime);
        sample->idleTime100ns = nonNegativeLargeInteger(performance.IdleTime);
        sample->queryTime100ns = nonNegativeLargeInteger(performance.QueryTime);
        sample->storageDeviceNumber = performance.StorageDeviceNumber;
        sample->storageManagerName = storageManagerName(performance);
        for (std::size_t managerIndex = 0U;
             managerIndex < sample->storageManagerIdentity.size();
             ++managerIndex)
        {
            sample->storageManagerIdentity[managerIndex] =
                static_cast<std::uint16_t>(
                    performance.StorageManagerName[managerIndex]);
        }
        sample->queueDepth = performance.QueueDepth;
    }

    bool performanceIdentityMatches(
        const DiskMonitorStoragePerformanceState::Lease& lease,
        const DiskMonitorStorageSample& sample)
    {
        return sample.volumeSerialAvailable &&
            lease.volumeSerialNumber == sample.volumeSerialNumber &&
            lease.storageDeviceNumber == sample.storageDeviceNumber &&
            lease.storageManagerIdentity ==
                sample.storageManagerIdentity;
    }

    QTableWidgetItem* createStorageItem(
        const QString& text,
        const double numericValue = std::numeric_limits<double>::quiet_NaN())
    {
        // createStorageItem：
        // - 输入：显示文本和可选数值；
        // - 返回：只读表格单元格；数值写入 UserRole 以支持正确排序。
        auto* item = new QTableWidgetItem(text);
        item->setFlags(item->flags() & ~Qt::ItemIsEditable);
        if (std::isfinite(numericValue))
        {
            item->setData(Qt::UserRole, numericValue);
            item->setTextAlignment(Qt::AlignRight | Qt::AlignVCenter);
        }
        return item;
    }
}

DiskMonitorStoragePanel::DiskMonitorStoragePanel(QWidget* parent)
    : QWidget(parent),
      m_performanceState(
          std::make_unique<DiskMonitorStoragePerformanceState>())
{
    // 存储区仅负责表格展示；采样由 DiskMonitorPage 的既有后台线程统一调度，
    // 避免硬件页增加另一组定时器并与页面销毁发生竞争。
    auto* rootLayout = new QVBoxLayout(this);
    rootLayout->setContentsMargins(0, 0, 0, 0);
    rootLayout->setSpacing(0);

    m_table = new ks::ui::VisibleTableWidget(this);
    m_table->setColumnCount(kStorageColumnCount);
    m_table->setHorizontalHeaderLabels({
        QStringLiteral("驱动器"),
        QStringLiteral("卷标"),
        QStringLiteral("文件系统"),
        QStringLiteral("活动时间"),
        QStringLiteral("可用空间"),
        QStringLiteral("总空间"),
        QStringLiteral("读(字节/秒)"),
        QStringLiteral("写(字节/秒)"),
        QStringLiteral("响应时间(ms)"),
        QStringLiteral("队列长度")
        });
    m_table->setAlternatingRowColors(true);
    m_table->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_table->setSelectionMode(QAbstractItemView::SingleSelection);
    m_table->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_table->setSortingEnabled(true);
    m_table->verticalHeader()->setVisible(false);
    m_table->verticalHeader()->setDefaultSectionSize(24);
    m_table->horizontalHeader()->setSectionResizeMode(QHeaderView::ResizeToContents);
    m_table->horizontalHeader()->setSectionResizeMode(kStorageColumnLabel, QHeaderView::Stretch);
    m_table->setStyleSheet(QStringLiteral(
        "QTableWidget{background:transparent;border:1px solid %1;}"
        "QHeaderView::section{background:%2;color:%3;border:0;border-right:1px solid %1;"
        "border-bottom:1px solid %1;padding:5px 7px;font-weight:600;}"))
        .arg(
            KswordTheme::BorderHex(),
            KswordTheme::PanelHex(),
            KswordTheme::TextPrimaryHex()));
    rootLayout->addWidget(m_table, 1);

    m_summaryText = QStringLiteral("存储：等待首轮采样");
}

DiskMonitorStoragePanel::~DiskMonitorStoragePanel()
{
    releasePerformanceCounters();
}

void DiskMonitorStoragePanel::releasePerformanceCounters()
{
    if (m_performanceState == nullptr)
    {
        return;
    }

    for (auto leaseIterator = m_performanceState->leaseByVolumeGuid.begin();
         leaseIterator != m_performanceState->leaseByVolumeGuid.end();
         ++leaseIterator)
    {
        DiskMonitorStoragePerformanceState::Lease& lease =
            leaseIterator.value();
        if (!releasePerformanceLease(&lease))
        {
            // 页面最终退出前只再做一次有界重试；随后必须关闭句柄，
            // 避免析构因故障存储栈无限循环。
            drainOwnedPerformanceReferences(&lease);
            closePerformanceLeaseHandle(&lease);
        }
    }
    m_performanceState->leaseByVolumeGuid.clear();
}

std::vector<DiskMonitorStorageSample> DiskMonitorStoragePanel::collectSamples(
    const std::atomic_bool* stopRequested)
{
    std::vector<DiskMonitorStorageSample> sampleList;
    if (m_performanceState == nullptr || samplingShouldStop(stopRequested))
    {
        return sampleList;
    }

    // 先让 Windows 返回多字符串缓冲区长度，再一次性读取所有逻辑卷根目录。
    const DWORD requiredCharacterCount = GetLogicalDriveStringsW(0U, nullptr);
    if (requiredCharacterCount == 0U)
    {
        return sampleList;
    }
    std::vector<wchar_t> driveBuffer(
        static_cast<std::size_t>(requiredCharacterCount) + 1U,
        L'\0');
    const DWORD copiedCharacterCount = GetLogicalDriveStringsW(
        static_cast<DWORD>(driveBuffer.size()),
        driveBuffer.data());
    if (copiedCharacterCount == 0U ||
        static_cast<std::size_t>(copiedCharacterCount) >= driveBuffer.size())
    {
        return sampleList;
    }

    QSet<QString> seenVolumeGuidSet;

    // 仅枚举固定卷；网络盘和可移动介质可能在后台查询时长时间阻塞，
    // 与资源监视器的本机磁盘审计目标也不一致。
    const wchar_t* driveRootPointer = driveBuffer.data();
    while (driveRootPointer != nullptr && *driveRootPointer != L'\0')
    {
        const std::size_t driveRootLength = std::wcslen(driveRootPointer);
        if (driveRootLength == 0U)
        {
            break;
        }
        if (samplingShouldStop(stopRequested))
        {
            break;
        }

        if (GetDriveTypeW(driveRootPointer) == DRIVE_FIXED)
        {
            DiskMonitorStorageSample sample;
            sample.driveRoot = QString::fromWCharArray(driveRootPointer);

            wchar_t volumeGuidBuffer[MAX_PATH + 1]{};
            if (GetVolumeNameForVolumeMountPointW(
                driveRootPointer,
                volumeGuidBuffer,
                static_cast<DWORD>(std::size(volumeGuidBuffer))))
            {
                sample.volumeGuidName =
                    normalizedVolumeGuidName(
                        QString::fromWCharArray(volumeGuidBuffer));
            }
            if (samplingShouldStop(stopRequested))
            {
                break;
            }

            // 同一个卷可能有多个盘符/挂载点。按卷 GUID 只查询和汇总一次，
            // 避免重复增加性能引用及双重计算吞吐。
            if (!sample.volumeGuidName.isEmpty() &&
                seenVolumeGuidSet.contains(sample.volumeGuidName))
            {
                driveRootPointer += driveRootLength + 1U;
                continue;
            }
            if (!sample.volumeGuidName.isEmpty())
            {
                seenVolumeGuidSet.insert(sample.volumeGuidName);
            }

            ULARGE_INTEGER availableBytes{};
            ULARGE_INTEGER totalBytes{};
            ULARGE_INTEGER totalFreeBytes{};
            if (GetDiskFreeSpaceExW(
                driveRootPointer,
                &availableBytes,
                &totalBytes,
                &totalFreeBytes))
            {
                sample.availableBytes = availableBytes.QuadPart;
                sample.totalBytes = totalBytes.QuadPart;
                sample.capacityAvailable = true;
            }
            if (samplingShouldStop(stopRequested))
            {
                break;
            }

            // 卷标和文件系统只用于展示；卷序列号参与稳定身份，
            // 因此本调用失败时本轮不建立性能基线。
            wchar_t volumeLabelBuffer[MAX_PATH + 1]{};
            wchar_t fileSystemBuffer[MAX_PATH + 1]{};
            DWORD volumeSerialNumber = 0U;
            if (GetVolumeInformationW(
                driveRootPointer,
                volumeLabelBuffer,
                static_cast<DWORD>(std::size(volumeLabelBuffer)),
                &volumeSerialNumber,
                nullptr,
                nullptr,
                fileSystemBuffer,
                static_cast<DWORD>(std::size(fileSystemBuffer))))
            {
                sample.volumeLabel = QString::fromWCharArray(volumeLabelBuffer);
                sample.fileSystemName = QString::fromWCharArray(fileSystemBuffer);
                sample.volumeSerialNumber = volumeSerialNumber;
                sample.volumeSerialAvailable = true;
            }
            if (samplingShouldStop(stopRequested))
            {
                break;
            }

            // IOCTL_DISK_PERFORMANCE 每次成功调用都会增加一个启用引用。
            // 会话为每个卷保留一个 anchor；后续查询完成后立即 OFF 一次，
            // 使采样间隔内始终只有本页面持有的一个引用。
            const QString volumeGuidKey =
                normalizedVolumeGuidName(sample.volumeGuidName);
            bool mayOpenNewLease =
                !volumeGuidKey.isEmpty() &&
                sample.volumeSerialAvailable;
            auto leaseIterator =
                m_performanceState->leaseByVolumeGuid.find(volumeGuidKey);
            if (leaseIterator !=
                m_performanceState->leaseByVolumeGuid.end())
            {
                mayOpenNewLease = false;
                DiskMonitorStoragePerformanceState::Lease& lease =
                    leaseIterator.value();
                if (lease.volumeHandle == INVALID_HANDLE_VALUE)
                {
                    m_performanceState->leaseByVolumeGuid.erase(leaseIterator);
                    mayOpenNewLease = true;
                }
                else if (!lease.lifecycleHealthy)
                {
                    // OFF 曾失败时停止继续查询，先尝试清空已知自有引用；
                    // 本轮仍保持 N/A，下一轮才重新建立 anchor。
                    if (drainOwnedPerformanceReferences(&lease))
                    {
                        CloseHandle(lease.volumeHandle);
                        lease.volumeHandle = INVALID_HANDLE_VALUE;
                        m_performanceState->leaseByVolumeGuid.erase(
                            leaseIterator);
                    }
                }
                else
                {
                    DISK_PERFORMANCE performance{};
                    DWORD returnedBytes = 0U;
                    const BOOL queryOk = DeviceIoControl(
                        lease.volumeHandle,
                        IOCTL_DISK_PERFORMANCE,
                        nullptr,
                        0U,
                        &performance,
                        static_cast<DWORD>(sizeof(performance)),
                        &returnedBytes,
                        nullptr);
                    const std::uint64_t sampleTickMs = GetTickCount64();
                    if (queryOk)
                    {
                        ++lease.ownedEnableReferenceCount;
                        const bool completeResult =
                            returnedBytes >=
                            static_cast<DWORD>(sizeof(performance));
                        if (completeResult)
                        {
                            populatePerformanceSample(
                                performance,
                                sampleTickMs,
                                &sample);
                        }

                        // 无论返回长度是否有效，成功 IOCTL 都已增加引用。
                        const bool balancedQueryReference =
                            turnOffOnePerformanceReference(&lease);
                        if (completeResult &&
                            balancedQueryReference &&
                            performanceIdentityMatches(lease, sample))
                        {
                            sample.performanceAvailable = true;
                        }
                        else if (completeResult &&
                                 balancedQueryReference &&
                                 !performanceIdentityMatches(lease, sample))
                        {
                            // GUID 相同但设备/管理器/卷序列已变化：整组 epoch
                            // 作废并释放旧 anchor，避免跨设备相减。
                            if (releasePerformanceLease(&lease))
                            {
                                m_performanceState->leaseByVolumeGuid.erase(
                                    leaseIterator);
                            }
                        }
                    }
                }
            }

            if (mayOpenNewLease &&
                !samplingShouldStop(stopRequested))
            {
                QString volumeDevicePath = sample.volumeGuidName;
                while (volumeDevicePath.endsWith(QLatin1Char('\\')))
                {
                    volumeDevicePath.chop(1);
                }
                const HANDLE volumeHandle = CreateFileW(
                    reinterpret_cast<LPCWSTR>(volumeDevicePath.utf16()),
                    0U,
                    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                    nullptr,
                    OPEN_EXISTING,
                    FILE_ATTRIBUTE_NORMAL,
                    nullptr);
                if (volumeHandle != INVALID_HANDLE_VALUE)
                {
                    DiskMonitorStoragePerformanceState::Lease newLease;
                    newLease.volumeGuidName = volumeGuidKey;
                    newLease.volumeSerialNumber =
                        sample.volumeSerialNumber;
                    newLease.volumeHandle = volumeHandle;

                    DISK_PERFORMANCE performance{};
                    DWORD returnedBytes = 0U;
                    const BOOL queryOk = DeviceIoControl(
                        volumeHandle,
                        IOCTL_DISK_PERFORMANCE,
                        nullptr,
                        0U,
                        &performance,
                        static_cast<DWORD>(sizeof(performance)),
                        &returnedBytes,
                        nullptr);
                    const std::uint64_t sampleTickMs = GetTickCount64();
                    if (queryOk)
                    {
                        newLease.ownedEnableReferenceCount = 1U;
                        if (returnedBytes >=
                            static_cast<DWORD>(sizeof(performance)))
                        {
                            populatePerformanceSample(
                                performance,
                                sampleTickMs,
                                &sample);
                            newLease.storageDeviceNumber =
                                sample.storageDeviceNumber;
                            newLease.storageManagerName =
                                sample.storageManagerName;
                            newLease.storageManagerIdentity =
                                sample.storageManagerIdentity;
                            sample.performanceAvailable = true;
                            m_performanceState->leaseByVolumeGuid.insert(
                                volumeGuidKey,
                                std::move(newLease));
                        }
                        else
                        {
                            if (!releasePerformanceLease(&newLease))
                            {
                                newLease.lifecycleHealthy = false;
                                m_performanceState->leaseByVolumeGuid.insert(
                                    volumeGuidKey,
                                    std::move(newLease));
                            }
                        }
                    }
                    else
                    {
                        CloseHandle(volumeHandle);
                    }
                }
            }

            if (samplingShouldStop(stopRequested))
            {
                break;
            }

            if (sample.performanceAvailable)
            {
                // 性能身份必须完整；无法确认身份时仅保留容量信息。
                sample.performanceAvailable =
                    !storageIdentityKey(sample).isEmpty();
            }

            if (!sample.performanceAvailable)
            {
                sample.sampleTickMs = 0U;
            }
            sampleList.push_back(std::move(sample));
        }
        driveRootPointer += driveRootLength + 1U;
    }

    if (!samplingShouldStop(stopRequested))
    {
        // 本轮未出现的卷已卸载/移除；释放成功才删除 lease。
        // 临时 OFF 失败时保留句柄和准确自有引用数，供后续轮次重试。
        for (auto leaseIterator =
                 m_performanceState->leaseByVolumeGuid.begin();
             leaseIterator !=
                 m_performanceState->leaseByVolumeGuid.end();)
        {
            if (!seenVolumeGuidSet.contains(leaseIterator.key()))
            {
                if (releasePerformanceLease(&leaseIterator.value()))
                {
                    leaseIterator =
                        m_performanceState->leaseByVolumeGuid.erase(
                            leaseIterator);
                }
                else
                {
                    ++leaseIterator;
                }
            }
            else
            {
                ++leaseIterator;
            }
        }
    }

    std::sort(
        sampleList.begin(),
        sampleList.end(),
        [](const DiskMonitorStorageSample& left, const DiskMonitorStorageSample& right)
        {
            return left.driveRoot.compare(right.driveRoot, Qt::CaseInsensitive) < 0;
        });
    return sampleList;
}

void DiskMonitorStoragePanel::applySamples(
    std::vector<DiskMonitorStorageSample> sampleList)
{
    if (m_table == nullptr)
    {
        return;
    }

    const QSignalBlocker tableSignalBlocker(m_table);
    const bool sortingWasEnabled = m_table->isSortingEnabled();
    m_table->setSortingEnabled(false);
    m_table->clearSpans();
    m_table->setRowCount(static_cast<int>(sampleList.size()));

    double highestActivePercent = 0.0;
    double totalReadRate = 0.0;
    double totalWriteRate = 0.0;
    int validRateSampleCount = 0;
    QHash<QString, StorageBaseline> nextBaselineByIdentity;

    for (std::size_t sampleIndex = 0U;
         sampleIndex < sampleList.size();
         ++sampleIndex)
    {
        const DiskMonitorStorageSample& sample = sampleList[sampleIndex];
        const QString baselineKey = storageIdentityKey(sample);
        const auto baselineIterator =
            m_baselineByIdentity.constFind(baselineKey);

        double readRate = 0.0;
        double writeRate = 0.0;
        double activePercent = 0.0;
        double responseTimeMs = 0.0;
        bool rateAvailable = false;
        bool responseTimeAvailable = false;
        if (!baselineKey.isEmpty() &&
            baselineIterator != m_baselineByIdentity.constEnd() &&
            baselineIterator->performanceAvailable &&
            sample.performanceAvailable &&
            sample.sampleTickMs > baselineIterator->sampleTickMs)
        {
            std::uint64_t readOperationDelta = 0U;
            std::uint64_t writeOperationDelta = 0U;
            const bool cumulativeEpochContinues =
                sample.bytesRead >= baselineIterator->bytesRead &&
                sample.bytesWritten >= baselineIterator->bytesWritten &&
                sample.readTime100ns >=
                    baselineIterator->readTime100ns &&
                sample.writeTime100ns >=
                    baselineIterator->writeTime100ns &&
                sample.idleTime100ns >=
                    baselineIterator->idleTime100ns &&
                sample.queryTime100ns >
                    baselineIterator->queryTime100ns &&
                counter32Delta(
                    sample.readCount,
                    baselineIterator->readCount,
                    &readOperationDelta) &&
                counter32Delta(
                    sample.writeCount,
                    baselineIterator->writeCount,
                    &writeOperationDelta);

            if (cumulativeEpochContinues)
            {
                const std::uint64_t elapsedMs =
                    sample.sampleTickMs -
                    baselineIterator->sampleTickMs;
                const std::uint64_t queryDelta =
                    sample.queryTime100ns -
                    baselineIterator->queryTime100ns;
                const std::uint64_t monotonicDelta100ns =
                    elapsedMs <=
                        std::numeric_limits<std::uint64_t>::max() / 10000U
                    ? elapsedMs * 10000U
                    : std::numeric_limits<std::uint64_t>::max();

                // QueryTime 是系统时间戳。与 IOCTL 附近的单调间隔明显
                // 不一致时，视为系统调时/计数器 epoch 变化并重建基线。
                const bool queryIntervalConsistent =
                    queryDelta > 0U &&
                    monotonicDelta100ns > 0U &&
                    queryDelta >= monotonicDelta100ns / 4U &&
                    queryDelta <=
                        (monotonicDelta100ns <=
                             std::numeric_limits<std::uint64_t>::max() / 4U
                             ? monotonicDelta100ns * 4U
                             : std::numeric_limits<std::uint64_t>::max());
                if (queryIntervalConsistent)
                {
                    const double elapsedSeconds =
                        static_cast<double>(elapsedMs) / 1000.0;
                    readRate =
                        static_cast<double>(
                            sample.bytesRead -
                            baselineIterator->bytesRead) /
                        elapsedSeconds;
                    writeRate =
                        static_cast<double>(
                            sample.bytesWritten -
                            baselineIterator->bytesWritten) /
                        elapsedSeconds;

                    const std::uint64_t idleDelta =
                        sample.idleTime100ns -
                        baselineIterator->idleTime100ns;
                    const std::uint64_t busyDelta =
                        queryDelta > idleDelta
                        ? queryDelta - idleDelta
                        : 0U;
                    activePercent = std::clamp(
                        static_cast<double>(busyDelta) * 100.0 /
                        static_cast<double>(queryDelta),
                        0.0,
                        100.0);

                    const std::uint64_t operationDelta =
                        readOperationDelta + writeOperationDelta;
                    const std::uint64_t operationTimeDelta =
                        (sample.readTime100ns -
                         baselineIterator->readTime100ns) +
                        (sample.writeTime100ns -
                         baselineIterator->writeTime100ns);
                    if (operationDelta > 0U)
                    {
                        responseTimeMs =
                            static_cast<double>(operationTimeDelta) /
                            static_cast<double>(operationDelta) /
                            10000.0;
                        responseTimeAvailable = true;
                    }
                    rateAvailable = true;
                    ++validRateSampleCount;
                }
            }
        }

        // 身份完整且本轮性能值有效时才刷新整组基线。
        if (!baselineKey.isEmpty() && sample.performanceAvailable)
        {
            StorageBaseline nextBaseline;
            nextBaseline.sampleTickMs = sample.sampleTickMs;
            nextBaseline.bytesRead = sample.bytesRead;
            nextBaseline.bytesWritten = sample.bytesWritten;
            nextBaseline.readCount = sample.readCount;
            nextBaseline.writeCount = sample.writeCount;
            nextBaseline.readTime100ns = sample.readTime100ns;
            nextBaseline.writeTime100ns = sample.writeTime100ns;
            nextBaseline.idleTime100ns = sample.idleTime100ns;
            nextBaseline.queryTime100ns = sample.queryTime100ns;
            nextBaseline.performanceAvailable = true;
            nextBaselineByIdentity.insert(baselineKey, nextBaseline);
        }

        const int rowIndex = static_cast<int>(sampleIndex);
        m_table->setItem(
            rowIndex,
            kStorageColumnDrive,
            createStorageItem(sample.driveRoot));
        m_table->setItem(
            rowIndex,
            kStorageColumnLabel,
            createStorageItem(
                sample.volumeLabel.isEmpty()
                    ? QStringLiteral("-")
                    : sample.volumeLabel));
        m_table->setItem(
            rowIndex,
            kStorageColumnFileSystem,
            createStorageItem(
                sample.fileSystemName.isEmpty()
                    ? QStringLiteral("-")
                    : sample.fileSystemName));
        m_table->setItem(
            rowIndex,
            kStorageColumnActiveTime,
            createStorageItem(
                rateAvailable
                    ? QStringLiteral("%1%").arg(activePercent, 0, 'f', 1)
                    : QStringLiteral("N/A"),
                rateAvailable
                    ? activePercent
                    : std::numeric_limits<double>::quiet_NaN()));
        m_table->setItem(
            rowIndex,
            kStorageColumnAvailable,
            createStorageItem(
                sample.capacityAvailable
                    ? formatBytes(static_cast<double>(sample.availableBytes))
                    : QStringLiteral("N/A"),
                sample.capacityAvailable
                    ? static_cast<double>(sample.availableBytes)
                    : std::numeric_limits<double>::quiet_NaN()));
        m_table->setItem(
            rowIndex,
            kStorageColumnTotal,
            createStorageItem(
                sample.capacityAvailable
                    ? formatBytes(static_cast<double>(sample.totalBytes))
                    : QStringLiteral("N/A"),
                sample.capacityAvailable
                    ? static_cast<double>(sample.totalBytes)
                    : std::numeric_limits<double>::quiet_NaN()));
        m_table->setItem(
            rowIndex,
            kStorageColumnReadRate,
            createStorageItem(
                rateAvailable ? formatRate(readRate) : QStringLiteral("N/A"),
                rateAvailable
                    ? readRate
                    : std::numeric_limits<double>::quiet_NaN()));
        m_table->setItem(
            rowIndex,
            kStorageColumnWriteRate,
            createStorageItem(
                rateAvailable ? formatRate(writeRate) : QStringLiteral("N/A"),
                rateAvailable
                    ? writeRate
                    : std::numeric_limits<double>::quiet_NaN()));
        m_table->setItem(
            rowIndex,
            kStorageColumnResponse,
            createStorageItem(
                responseTimeAvailable
                    ? QStringLiteral("%1").arg(responseTimeMs, 0, 'f', 2)
                    : QStringLiteral("N/A"),
                responseTimeAvailable
                    ? responseTimeMs
                    : std::numeric_limits<double>::quiet_NaN()));
        m_table->setItem(
            rowIndex,
            kStorageColumnQueueDepth,
            createStorageItem(
                sample.performanceAvailable
                    ? QString::number(sample.queueDepth)
                    : QStringLiteral("N/A"),
                sample.performanceAvailable
                    ? static_cast<double>(sample.queueDepth)
                    : std::numeric_limits<double>::quiet_NaN()));

        if (rateAvailable)
        {
            highestActivePercent =
                std::max(highestActivePercent, activePercent);
            totalReadRate += readRate;
            totalWriteRate += writeRate;
        }
    }

    m_baselineByIdentity = std::move(nextBaselineByIdentity);
    if (sampleList.empty())
    {
        m_table->setRowCount(1);
        m_table->setItem(
            0,
            kStorageColumnDrive,
            createStorageItem(QStringLiteral("未发现可用的本机固定卷")));
        m_table->setSpan(0, kStorageColumnDrive, 1, kStorageColumnCount);
        m_summaryText = QStringLiteral("存储：未发现可用固定卷");
    }
    else if (validRateSampleCount == 0)
    {
        m_summaryText = QStringLiteral(
            "存储：%1 个卷    最高活动时间：N/A    总吞吐：N/A")
            .arg(static_cast<int>(sampleList.size()));
    }
    else
    {
        m_summaryText = QStringLiteral("存储：%1 个卷    最高活动时间：%2%    总吞吐：%3")
            .arg(static_cast<int>(sampleList.size()))
            .arg(highestActivePercent, 0, 'f', 1)
            .arg(formatRate(totalReadRate + totalWriteRate));
    }
    m_table->setSortingEnabled(sortingWasEnabled);
}

QString DiskMonitorStoragePanel::summaryText() const
{
    return m_summaryText;
}

QString DiskMonitorStoragePanel::formatBytes(const double byteCount)
{
    static const QStringList unitList = {
        QStringLiteral("B"),
        QStringLiteral("KB"),
        QStringLiteral("MB"),
        QStringLiteral("GB"),
        QStringLiteral("TB")
    };
    double displayValue = std::max(0.0, byteCount);
    int unitIndex = 0;
    while (displayValue >= 1024.0 && unitIndex + 1 < unitList.size())
    {
        displayValue /= 1024.0;
        ++unitIndex;
    }
    const int precision = unitIndex == 0 ? 0 : (displayValue >= 100.0 ? 0 : 1);
    return QStringLiteral("%1 %2")
        .arg(displayValue, 0, 'f', precision)
        .arg(unitList[unitIndex]);
}

QString DiskMonitorStoragePanel::formatRate(const double bytesPerSecond)
{
    return QStringLiteral("%1/s").arg(formatBytes(bytesPerSecond));
}
