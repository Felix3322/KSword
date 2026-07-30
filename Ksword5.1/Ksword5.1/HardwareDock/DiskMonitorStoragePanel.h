#pragma once

// ============================================================
// DiskMonitorStoragePanel.h
// 作用：
// 1) 为硬盘监控页提供资源监视器风格的“存储”区域；
// 2) 在后台采集固定卷容量与 IOCTL_DISK_PERFORMANCE 原始计数器；
// 3) 在 UI 线程计算活动时间、吞吐、响应时间和队列长度。
// ============================================================

#include <QHash>
#include <QString>
#include <QWidget>

#include <cstdint>
#include <vector>

class QTableWidget;

// DiskMonitorStorageSample：
// - 输入：collectSamples() 从 Windows 固定卷和磁盘性能接口读取；
// - 处理：保留累计计数器，避免后台线程访问任何 Qt 控件；
// - 输出：由 DiskMonitorStoragePanel::applySamples() 转换为每秒速率。
struct DiskMonitorStorageSample
{
    QString driveRoot;                       // driveRoot：卷根目录，例如 C:\。
    QString volumeLabel;                     // volumeLabel：卷标，系统未提供时为空。
    QString fileSystemName;                  // fileSystemName：文件系统名称，例如 NTFS。
    std::uint64_t availableBytes = 0U;       // availableBytes：当前用户可用空间。
    std::uint64_t totalBytes = 0U;           // totalBytes：卷总容量。
    std::uint64_t bytesRead = 0U;            // bytesRead：磁盘累计读取字节。
    std::uint64_t bytesWritten = 0U;         // bytesWritten：磁盘累计写入字节。
    std::uint64_t readCount = 0U;            // readCount：磁盘累计读取次数。
    std::uint64_t writeCount = 0U;           // writeCount：磁盘累计写入次数。
    std::uint64_t readTime100ns = 0U;        // readTime100ns：累计读取耗时，单位 100ns。
    std::uint64_t writeTime100ns = 0U;       // writeTime100ns：累计写入耗时，单位 100ns。
    std::uint64_t idleTime100ns = 0U;        // idleTime100ns：累计空闲时间，单位 100ns。
    std::uint64_t queryTime100ns = 0U;       // queryTime100ns：性能计数器累计观察时间。
    std::uint32_t queueDepth = 0U;           // queueDepth：采样瞬间磁盘队列深度。
    bool capacityAvailable = false;          // capacityAvailable：容量查询是否成功。
    bool performanceAvailable = false;       // performanceAvailable：磁盘性能计数器是否可用。
};

// DiskMonitorStoragePanel：
// - 构造后显示固定卷存储表；
// - collectSamples() 可在后台线程调用；
// - applySamples() 只能在 UI 线程调用，并维护跨轮计数器基线。
class DiskMonitorStoragePanel final : public QWidget
{
public:
    // 构造函数：
    // - parent：Qt 父控件；
    // - 返回：创建只读存储表，不启动独立线程或定时器。
    explicit DiskMonitorStoragePanel(QWidget* parent = nullptr);

    // collectSamples：
    // - 输入：无；
    // - 处理：枚举本机固定卷并读取容量、卷标、文件系统和磁盘性能累计值；
    // - 返回：可移动的纯数据列表，失败卷会保留可获得的字段并安全降级。
    static std::vector<DiskMonitorStorageSample> collectSamples();

    // applySamples：
    // - 输入：后台线程得到的原始样本；
    // - 处理：用上一轮基线计算速率、活动时间和响应时间，再刷新表格；
    // - 返回：无，样本为空时显示明确占位行。
    void applySamples(std::vector<DiskMonitorStorageSample> sampleList);

    // summaryText：
    // - 输入：无；
    // - 返回：最近一轮最高活动时间、总吞吐和卷数量摘要。
    QString summaryText() const;

private:
    // StorageBaseline：
    // - 作用：保存单卷上一轮累计值；
    // - key：使用大写卷根目录，避免盘符大小写造成重复基线。
    struct StorageBaseline
    {
        std::uint64_t sampleTickMs = 0U;     // sampleTickMs：GetTickCount64 采样时间。
        std::uint64_t bytesRead = 0U;        // bytesRead：上一轮累计读取字节。
        std::uint64_t bytesWritten = 0U;     // bytesWritten：上一轮累计写入字节。
        std::uint64_t readCount = 0U;        // readCount：上一轮累计读取次数。
        std::uint64_t writeCount = 0U;       // writeCount：上一轮累计写入次数。
        std::uint64_t readTime100ns = 0U;    // readTime100ns：上一轮累计读取耗时。
        std::uint64_t writeTime100ns = 0U;   // writeTime100ns：上一轮累计写入耗时。
        std::uint64_t idleTime100ns = 0U;    // idleTime100ns：上一轮累计空闲时间。
        std::uint64_t queryTime100ns = 0U;   // queryTime100ns：上一轮累计观察时间。
        bool performanceAvailable = false;   // performanceAvailable：上一轮性能值是否有效。
    };

    // formatBytes：
    // - 输入：字节数；
    // - 返回：自动选择 B/KB/MB/GB/TB 的可读容量。
    static QString formatBytes(double byteCount);

    // formatRate：
    // - 输入：每秒字节数；
    // - 返回：带 /s 后缀的可读吞吐。
    static QString formatRate(double bytesPerSecond);

    QTableWidget* m_table = nullptr;         // m_table：固定卷存储状态表。
    QHash<QString, StorageBaseline> m_baselineByDrive; // m_baselineByDrive：卷根目录到历史基线。
    QString m_summaryText;                   // m_summaryText：最近一轮资源监视器式摘要。
};
