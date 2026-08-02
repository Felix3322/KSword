#pragma once

// ============================================================
// SystemMemoryAuditPage.h
// 作用：
// 1) 从系统全局视角审计实际驻留的物理内存，而不是只罗列普通进程；
// 2) 同时展示进程私有驻留、内核池标签、Big Pool 与页面链表；
// 3) 明确展示尚不能由稳定快照接口唯一归属的物理内存余量。
// ============================================================

#include <QHash>
#include <QString>
#include <QStringList>
#include <QWidget>

#include <array>
#include <atomic>
#include <cstdint>
#include <vector>

class QCheckBox;
class QEvent;
class QLabel;
class QLineEdit;
class QPlainTextEdit;
class QPushButton;
class QSpinBox;
class QTableWidget;
class QTabWidget;
class QTimer;
class QTreeWidget;

class SystemMemoryAuditPage final : public QWidget
{
public:
    explicit SystemMemoryAuditPage(QWidget* parent = nullptr);

    // refreshSnapshot：重新采集整机内存快照并刷新全部审计视图。
    void refreshSnapshot();

protected:
    void changeEvent(QEvent* event) override;

private:
    struct ProcessRow
    {
        std::uint64_t identity = 0;
        std::uint32_t pid = 0;
        std::uint32_t sessionId = 0;
        QString name;
        std::uint64_t privateResidentBytes = 0;
        std::uint64_t workingSetBytes = 0;
        std::uint64_t sharedResidentReferenceBytes = 0;
        std::uint64_t privateCommitBytes = 0;
        std::uint64_t pagedPoolQuotaBytes = 0;
        std::uint64_t nonPagedPoolQuotaBytes = 0;
        std::uint32_t hardFaultCount = 0;
        std::int64_t privateResidentDeltaBytes = 0;
    };

    struct PoolTagRow
    {
        std::uint32_t tag = 0;
        QString tagText;
        std::uint64_t pagedBytes = 0;
        std::uint64_t nonPagedBytes = 0;
        std::uint64_t pagedOutstanding = 0;
        std::uint64_t nonPagedOutstanding = 0;
        std::int64_t totalDeltaBytes = 0;
    };

    struct BigPoolRow
    {
        std::uint64_t identity = 0;
        std::uint64_t virtualAddress = 0;
        std::uint64_t sizeBytes = 0;
        std::uint32_t tag = 0;
        QString tagText;
        bool nonPaged = false;
        std::int64_t sizeDeltaBytes = 0;
    };

    struct TagMetadata
    {
        QString source;
        QString description;
    };

    enum class UserMemoryKind : std::uint8_t
    {
        Private,
        Image,
        MappedFile,
        PagefileSection,
        Unknown
    };

    struct UserResidencyRow
    {
        std::uint32_t pid = 0;
        QString processName;
        UserMemoryKind kind = UserMemoryKind::Unknown;
        QString backingPath;
        std::uint64_t residentReferenceBytes = 0;
        std::uint64_t privateResidentBytes = 0;
        std::uint64_t shareableResidentBytes = 0;
        std::uint64_t sharedResidentReferenceBytes = 0;
        std::uint64_t proportionalResidentBytes = 0;
    };

    struct UserResidencyScan
    {
        QString sampledAt;
        QStringList errors;
        std::uint32_t processCount = 0;
        std::uint32_t accessibleProcessCount = 0;
        std::uint32_t inaccessibleProcessCount = 0;
        std::uint64_t residentReferenceBytes = 0;
        std::uint64_t privateResidentBytes = 0;
        std::uint64_t sharedResidentReferenceBytes = 0;
        std::uint64_t proportionalResidentBytes = 0;
        std::vector<UserResidencyRow> rows;
    };

    struct Snapshot
    {
        QString sampledAt;
        QStringList errors;
        std::uint64_t pageSize = 4096;

        std::uint64_t installedPhysicalBytes = 0;
        std::uint64_t hardwareReservedBytes = 0;
        std::uint64_t totalPhysicalBytes = 0;
        std::uint64_t availableBytes = 0;
        std::uint64_t residentAvailableBytes = 0;
        std::uint64_t inUseBytes = 0;
        std::uint64_t committedBytes = 0;
        std::uint64_t commitLimitBytes = 0;
        std::uint64_t peakCommitmentBytes = 0;
        std::uint64_t sharedCommittedBytes = 0;

        bool memoryListAvailable = false;
        std::uint64_t zeroBytes = 0;
        std::uint64_t freeBytes = 0;
        std::uint64_t modifiedBytes = 0;
        std::uint64_t modifiedNoWriteBytes = 0;
        std::uint64_t modifiedPageFileBytes = 0;
        std::uint64_t badBytes = 0;
        std::array<std::uint64_t, 8> standbyBytes{};
        std::array<std::uint64_t, 8> repurposedBytes{};

        bool performanceAvailable = false;
        std::uint64_t pagedPoolCommittedBytes = 0;
        std::uint64_t nonPagedPoolBytes = 0;
        std::uint64_t pagedPoolResidentBytes = 0;
        std::uint64_t systemCodeResidentBytes = 0;
        std::uint64_t systemDriverResidentBytes = 0;
        std::uint64_t systemCacheResidentBytes = 0;
        std::uint64_t mdlAllocatedBytes = 0;
        std::uint64_t pfnDatabaseCommittedBytes = 0;
        std::uint64_t systemPageTableCommittedBytes = 0;
        std::uint64_t contiguousAllocatedBytes = 0;
        std::uint64_t broadSystemCacheBytes = 0;

        std::uint64_t processPrivateResidentBytes = 0;
        std::uint64_t processWorkingSetReferenceBytes = 0;
        std::uint64_t processSharedResidentReferenceBytes = 0;
        std::uint64_t processPrivateCommitBytes = 0;
        std::uint64_t processPagedPoolQuotaBytes = 0;
        std::uint64_t processNonPagedPoolQuotaBytes = 0;
        std::vector<ProcessRow> processes;

        std::uint64_t poolTagPagedBytes = 0;
        std::uint64_t poolTagNonPagedBytes = 0;
        std::vector<PoolTagRow> poolTags;
        std::vector<BigPoolRow> bigPool;

        std::uint64_t identifiedResidentLowerBoundBytes = 0;
        std::uint64_t unattributedResidentBytes = 0;
    };

    void initializeUi();
    void initializeConnections();
    void retranslateUi();
    void applySnapshot(Snapshot snapshot);
    void startUserResidencyScan();
    void applyUserResidencyScan(UserResidencyScan scan, std::uint64_t ticket);
    void rebuildOverview();
    void rebuildUserResidencyTable();
    void rebuildProcessTable();
    void rebuildPoolTagTable();
    void rebuildBigPoolTable();
    void updateDetails();
    void updateStatus();
    void loadPoolTagMetadata();

    static Snapshot collectSnapshot();
    static UserResidencyScan collectUserResidency(const std::vector<ProcessRow>& processes, std::uint64_t pageSize);
    static QString formatBytes(std::uint64_t bytes);
    static QString formatDelta(std::int64_t bytes);
    static QString formatPercent(std::uint64_t bytes, std::uint64_t totalBytes);

private:
    QPushButton* m_refreshButton = nullptr;
    QPushButton* m_userResidencyScanButton = nullptr;
    QCheckBox* m_autoRefreshCheck = nullptr;
    QSpinBox* m_intervalSpin = nullptr;
    QLineEdit* m_filterEdit = nullptr;
    QLabel* m_totalLabel = nullptr;
    QLabel* m_installedLabel = nullptr;
    QLabel* m_inUseLabel = nullptr;
    QLabel* m_availableLabel = nullptr;
    QLabel* m_commitLabel = nullptr;
    QLabel* m_unattributedLabel = nullptr;
    QTabWidget* m_detailTabs = nullptr;
    QTreeWidget* m_overviewTree = nullptr;
    QTableWidget* m_userResidencyTable = nullptr;
    QTableWidget* m_processTable = nullptr;
    QTableWidget* m_poolTagTable = nullptr;
    QTableWidget* m_bigPoolTable = nullptr;
    QPlainTextEdit* m_detailText = nullptr;
    QLabel* m_statusLabel = nullptr;
    QTimer* m_autoRefreshTimer = nullptr;

    Snapshot m_snapshot;
    UserResidencyScan m_userResidencyScan;
    bool m_hasSnapshot = false;
    bool m_refreshing = false;
    QHash<std::uint64_t, std::uint64_t> m_previousProcessPrivateBytes;
    QHash<std::uint32_t, std::uint64_t> m_previousPoolTagBytes;
    QHash<std::uint64_t, std::uint64_t> m_previousBigPoolBytes;
    QHash<QString, std::uint64_t> m_previousSummaryBytes;
    QHash<QString, std::int64_t> m_summaryDeltaBytes;
    QHash<std::uint32_t, TagMetadata> m_poolTagMetadata;
    QString m_poolTagMetadataSource;
    std::atomic<std::uint64_t> m_userResidencyScanTicket{ 0 };
    std::atomic_bool m_userResidencyScanInProgress{ false };
};
