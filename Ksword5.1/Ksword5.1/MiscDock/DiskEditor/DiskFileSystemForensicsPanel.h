#pragma once

#include "DiskDeletedEntryForensics.h"
#include "DiskFileSystemForensics.h"

#include <QWidget>

#include <cstdint>
#include <functional>
#include <optional>
#include <vector>

class QLabel;
class QLineEdit;
class QPushButton;
class QTableWidget;

namespace ks::misc
{
    struct DiskForensicsSelection
    {
        int diskIndex = -1;
        unsigned long backend = 1UL;
        std::uint64_t partitionOffset = 0;
        std::uint64_t partitionLength = 0;
        std::uint32_t logicalSectorSize = 512U;
        std::uint32_t backendMask = 1U;
        std::uint32_t capabilityFlags = 0U;
        QString displayText;
    };

    class DiskFileSystemForensicsPanel final : public QWidget
    {
    public:
        using SelectionProvider =
            std::function<std::optional<DiskForensicsSelection>()>;
        using JumpCallback = std::function<void(std::uint64_t)>;

        DiskFileSystemForensicsPanel(
            SelectionProvider selectionProvider,
            JumpCallback jumpCallback,
            QWidget* parent = nullptr);

    private:
        void initializeUi();
        void initializeConnections();
        void probeCurrentPartition();
        void resolveCurrentFile();
        void reverseLookupCurrentCluster();
        void scanDeletedEntries();
        void eraseSelectedDeletedEntry();
        void applyProbeResult(FileSystemProbeResult result);
        void applyExtentResult(FileExtentResult result);
        void applyReverseResult(ReverseClusterResult result);
        void applyDeletedResult(
            DiskForensicsSelection selection,
            DeletedEntryScanResult result);
        void applyEraseResult(ExtentEraseResult result);

        SelectionProvider m_selectionProvider;
        JumpCallback m_jumpCallback;
        QPushButton* m_probeButton = nullptr;
        QLabel* m_probeSummaryLabel = nullptr;
        QTableWidget* m_probeTable = nullptr;
        QLineEdit* m_filePathEdit = nullptr;
        QPushButton* m_fileBrowseButton = nullptr;
        QPushButton* m_extentButton = nullptr;
        QTableWidget* m_extentTable = nullptr;
        QLineEdit* m_volumePathEdit = nullptr;
        QLineEdit* m_clusterEdit = nullptr;
        QPushButton* m_reverseButton = nullptr;
        QTableWidget* m_reverseTable = nullptr;
        QPushButton* m_deletedScanButton = nullptr;
        QPushButton* m_deletedEraseButton = nullptr;
        QLabel* m_deletedSummaryLabel = nullptr;
        QTableWidget* m_deletedTable = nullptr;
        std::optional<DiskForensicsSelection> m_deletedSelection;
        std::vector<DeletedDirectoryEntry> m_deletedEntries;
        bool m_busy = false;
    };
}
