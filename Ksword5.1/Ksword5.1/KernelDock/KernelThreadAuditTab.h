#pragma once

// System-thread management and exact-build, read-only Ex work-queue evidence.

#include "../Framework.h"
#include "../ArkDriverClient/ArkDriverTypes.h"

#include <QWidget>

#include <cstdint>
#include <vector>

class CodeEditorWidget;
class QEvent;
class QLabel;
class QLineEdit;
class QPushButton;
class QTableWidget;

class KernelThreadAuditTab final : public QWidget
{
public:
    enum class Mode
    {
        SystemThreads,
        WorkQueueThreads
    };

    explicit KernelThreadAuditTab(Mode mode, QWidget* parent = nullptr);
    void requestRefresh();

protected:
    void changeEvent(QEvent* event) override;

private:
    enum class Column
    {
        ThreadId = 0,
        Category,
        QueueType,
        State,
        WaitReason,
        StartRoutine,
        Parameter,
        Module,
        ModuleBase,
        ModulePath,
        R0Status,
        Protection,
        Count
    };

    enum class ViewPreset
    {
        Overview,
        Evidence,
        Custom
    };

    enum class ProtectionKind : std::uint32_t
    {
        UnknownModule,
        KernelImage,
        MissingThreadIdentity,
        BestEffortR0Recheck,
        ReadOnlyWorkQueueEvidence
    };

    enum class ModuleQueryStatus : std::uint32_t
    {
        Ok,
        ApiUnavailable,
        LengthQueryFailed,
        SnapshotFailed
    };

    enum SnapshotDiagnosticFlag : std::uint32_t
    {
        DiagnosticNone = 0U,
        DiagnosticR3EnumerationEmpty = 1U << 0U,
        DiagnosticR0ThreadUnavailable = 1U << 1U,
        DiagnosticModuleUnavailable = 1U << 2U,
        DiagnosticWorkQueueTransportFailed = 1U << 3U,
        DiagnosticWorkQueueUnsupported = 1U << 4U,
        DiagnosticWorkQueuePartial = 1U << 5U
    };

    struct ModuleRecord
    {
        QString name;
        QString path;
        std::uint64_t baseAddress = 0;
        std::uint32_t imageSize = 0;
        bool kernelImage = false;
    };

    struct ThreadRow
    {
        std::uint32_t threadId = 0;
        std::uint64_t createTime100ns = 0;
        std::uint64_t startAddress = 0;
        std::uint64_t queueAddress = 0;
        std::uint64_t workItemAddress = 0;
        std::uint64_t parameterAddress = 0;
        std::uint64_t threadObject = 0;
        int priority = 0;
        int basePriority = 0;
        std::uint32_t state = 0;
        std::uint32_t waitReason = 0;
        std::uint32_t r0Flags = 0;
        std::uint32_t r0FieldFlags = 0;
        std::uint32_t r0Status = 0;
        std::uint32_t workQueueRowKind = 0;
        std::uint32_t queueType = 0;
        std::uint32_t queuePriorityIndex = 0;
        std::uint32_t nodeIndex = 0;
        std::uint32_t workQueueFlags = 0;
        std::uint32_t workQueueStatus = 0;
        ModuleRecord module;
        bool moduleResolved = false;
        bool workerKnown = false;
        bool activeWorker = false;
        bool protectedTarget = true;
        ProtectionKind protectionKind = ProtectionKind::UnknownModule;
    };

    struct Snapshot
    {
        std::vector<ThreadRow> rows;
        std::uint32_t diagnosticFlags = DiagnosticNone;
        unsigned long r0Win32Error = ERROR_SUCCESS;
        ModuleQueryStatus moduleQueryStatus = ModuleQueryStatus::Ok;
        long moduleNativeStatus = 0;
        unsigned long moduleRequiredBytes = 0;
        std::uint32_t workQueueQueryStatus = KSWORD_ARK_WORK_QUEUE_QUERY_STATUS_UNSUPPORTED;
        std::uint32_t workQueueStatusFlags = 0;
        std::uint32_t workQueueTotalCount = 0;
        std::uint32_t workQueueNodeCount = 0;
        std::uint32_t workQueueQueuesVisited = 0;
        std::uint32_t workQueueCorruptCount = 0;
        std::uint32_t workQueueReadFailureCount = 0;
        std::uint32_t workQueueReferenceFailureCount = 0;
        long workQueueLastStatus = 0;
        bool usedNtQuery = false;
        bool r0Available = false;
    };

    void initializeUi();
    void applyTranslatedText();
    void applySnapshot(const Snapshot& snapshot);
    void rebuildTable();
    void updateDetail();
    void applyColumnPreset(ViewPreset preset);
    void updatePresetButtons();
    void showHeaderMenu(const QPoint& localPosition);
    void showRowMenu(const QPoint& localPosition);
    void runControlAction(unsigned long action);
    void runControlAction(const ThreadRow& row, unsigned long action);
    const ThreadRow* selectedRow() const;
    int selectedSourceIndex() const;

    static Snapshot collectSnapshot(Mode mode);
    static std::vector<ModuleRecord> queryKernelModules(
        ModuleQueryStatus* queryStatusOut,
        long* nativeStatusOut,
        unsigned long* requiredBytesOut);
    static ModuleRecord findOwnerModule(
        const std::vector<ModuleRecord>& modules,
        std::uint64_t address,
        bool* matchedOut);
    static QString stateText(std::uint32_t stateValue);
    static QString waitReasonText(std::uint32_t waitReasonValue);
    static QString r0StatusText(std::uint32_t statusValue);
    static QString addressText(std::uint64_t addressValue);
    static QString pointerText(std::uint64_t addressValue);
    static QString protectionReasonText(ProtectionKind protectionKind);
    static QString queueTypeText(std::uint32_t queueType);
    static QString workQueueEntryStatusText(std::uint32_t status);
    static QString snapshotDiagnosticText(const Snapshot& snapshot, Mode mode);

    Mode m_mode = Mode::SystemThreads;
    ViewPreset m_viewPreset = ViewPreset::Overview;
    QLineEdit* m_filterEdit = nullptr;
    QPushButton* m_refreshButton = nullptr;
    QPushButton* m_suspendButton = nullptr;
    QPushButton* m_resumeButton = nullptr;
    QPushButton* m_terminateButton = nullptr;
    QPushButton* m_overviewButton = nullptr;
    QPushButton* m_evidenceButton = nullptr;
    QLabel* m_statusLabel = nullptr;
    QTableWidget* m_table = nullptr;
    CodeEditorWidget* m_detailEditor = nullptr;
    std::vector<ThreadRow> m_rows;
    bool m_refreshRunning = false;
    std::uint64_t m_refreshTicket = 0;
};
