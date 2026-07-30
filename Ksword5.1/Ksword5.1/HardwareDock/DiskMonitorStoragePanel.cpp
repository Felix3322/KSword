#include "DiskMonitorStoragePanel.h"

#include "../UI/VisibleTableWidget.h"
#include "../theme.h"

#include <QAbstractItemView>
#include <QBrush>
#include <QColor>
#include <QHeaderView>
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

    std::uint64_t safeCounterDelta(
        const std::uint64_t currentValue,
        const std::uint64_t previousValue)
    {
        // safeCounterDelta：
        // - 输入：本轮和上一轮累计计数；
        // - 返回：计数器回绕、设备重置或基线较新时返回 0。
        return currentValue >= previousValue
            ? currentValue - previousValue
            : 0U;
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
    : QWidget(parent)
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

std::vector<DiskMonitorStorageSample> DiskMonitorStoragePanel::collectSamples()
{
    std::vector<DiskMonitorStorageSample> sampleList;

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

        if (GetDriveTypeW(driveRootPointer) == DRIVE_FIXED)
        {
            DiskMonitorStorageSample sample;
            sample.driveRoot = QString::fromWCharArray(driveRootPointer);

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

            // 卷标和文件系统只用于展示；查询失败不会阻断性能计数器读取。
            wchar_t volumeLabelBuffer[MAX_PATH + 1]{};
            wchar_t fileSystemBuffer[MAX_PATH + 1]{};
            if (GetVolumeInformationW(
                driveRootPointer,
                volumeLabelBuffer,
                static_cast<DWORD>(std::size(volumeLabelBuffer)),
                nullptr,
                nullptr,
                nullptr,
                fileSystemBuffer,
                static_cast<DWORD>(std::size(fileSystemBuffer))))
            {
                sample.volumeLabel = QString::fromWCharArray(volumeLabelBuffer);
                sample.fileSystemName = QString::fromWCharArray(fileSystemBuffer);
            }

            // IOCTL_DISK_PERFORMANCE 是只读累计计数器。句柄路径仅含盘符，
            // 未请求写权限，也不会修改磁盘性能状态或目标卷内容。
            const QString volumeDevicePath = QStringLiteral("\\\\.\\%1")
                .arg(sample.driveRoot.left(2));
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
                if (queryOk &&
                    returnedBytes >= static_cast<DWORD>(sizeof(performance)))
                {
                    sample.bytesRead = nonNegativeLargeInteger(performance.BytesRead);
                    sample.bytesWritten = nonNegativeLargeInteger(performance.BytesWritten);
                    sample.readCount = performance.ReadCount;
                    sample.writeCount = performance.WriteCount;
                    sample.readTime100ns = nonNegativeLargeInteger(performance.ReadTime);
                    sample.writeTime100ns = nonNegativeLargeInteger(performance.WriteTime);
                    sample.idleTime100ns = nonNegativeLargeInteger(performance.IdleTime);
                    sample.queryTime100ns = nonNegativeLargeInteger(performance.QueryTime);
                    sample.queueDepth = performance.QueueDepth;
                    sample.performanceAvailable = true;
                }
                CloseHandle(volumeHandle);
            }
            sampleList.push_back(std::move(sample));
        }
        driveRootPointer += driveRootLength + 1U;
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
    const std::uint64_t sampleTickMs = GetTickCount64();
    QHash<QString, StorageBaseline> nextBaselineByDrive;

    for (std::size_t sampleIndex = 0U;
         sampleIndex < sampleList.size();
         ++sampleIndex)
    {
        const DiskMonitorStorageSample& sample = sampleList[sampleIndex];
        const QString baselineKey = sample.driveRoot.toUpper();
        const auto baselineIterator = m_baselineByDrive.constFind(baselineKey);

        double readRate = 0.0;
        double writeRate = 0.0;
        double activePercent = 0.0;
        double responseTimeMs = 0.0;
        bool rateAvailable = false;
        if (baselineIterator != m_baselineByDrive.constEnd() &&
            baselineIterator->performanceAvailable &&
            sample.performanceAvailable &&
            sampleTickMs > baselineIterator->sampleTickMs)
        {
            const double elapsedSeconds =
                static_cast<double>(sampleTickMs - baselineIterator->sampleTickMs) / 1000.0;
            readRate = static_cast<double>(
                safeCounterDelta(sample.bytesRead, baselineIterator->bytesRead)) /
                elapsedSeconds;
            writeRate = static_cast<double>(
                safeCounterDelta(sample.bytesWritten, baselineIterator->bytesWritten)) /
                elapsedSeconds;

            const std::uint64_t queryDelta = safeCounterDelta(
                sample.queryTime100ns,
                baselineIterator->queryTime100ns);
            const std::uint64_t idleDelta = safeCounterDelta(
                sample.idleTime100ns,
                baselineIterator->idleTime100ns);
            if (queryDelta > 0U)
            {
                const std::uint64_t busyDelta =
                    queryDelta > idleDelta ? queryDelta - idleDelta : 0U;
                activePercent = std::clamp(
                    static_cast<double>(busyDelta) * 100.0 /
                    static_cast<double>(queryDelta),
                    0.0,
                    100.0);
            }

            const std::uint64_t operationDelta =
                safeCounterDelta(sample.readCount, baselineIterator->readCount) +
                safeCounterDelta(sample.writeCount, baselineIterator->writeCount);
            const std::uint64_t operationTimeDelta =
                safeCounterDelta(sample.readTime100ns, baselineIterator->readTime100ns) +
                safeCounterDelta(sample.writeTime100ns, baselineIterator->writeTime100ns);
            if (operationDelta > 0U)
            {
                responseTimeMs =
                    static_cast<double>(operationTimeDelta) /
                    static_cast<double>(operationDelta) /
                    10000.0;
            }
            rateAvailable = true;
        }

        // 无论本轮是否已有速率，都刷新基线；设备重置或首次出现时下一轮即可计算。
        StorageBaseline nextBaseline;
        nextBaseline.sampleTickMs = sampleTickMs;
        nextBaseline.bytesRead = sample.bytesRead;
        nextBaseline.bytesWritten = sample.bytesWritten;
        nextBaseline.readCount = sample.readCount;
        nextBaseline.writeCount = sample.writeCount;
        nextBaseline.readTime100ns = sample.readTime100ns;
        nextBaseline.writeTime100ns = sample.writeTime100ns;
        nextBaseline.idleTime100ns = sample.idleTime100ns;
        nextBaseline.queryTime100ns = sample.queryTime100ns;
        nextBaseline.performanceAvailable = sample.performanceAvailable;
        nextBaselineByDrive.insert(baselineKey, nextBaseline);

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
                rateAvailable
                    ? QStringLiteral("%1").arg(responseTimeMs, 0, 'f', 2)
                    : QStringLiteral("N/A"),
                rateAvailable
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

        highestActivePercent = std::max(highestActivePercent, activePercent);
        totalReadRate += readRate;
        totalWriteRate += writeRate;
    }

    m_baselineByDrive = std::move(nextBaselineByDrive);
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
