#pragma once

#include "DiskFileSystemForensics.h"

#include <QString>

#include <cstdint>
#include <vector>

namespace ks::misc
{
    struct DeletedFileExtent
    {
        std::uint64_t physicalOffset = 0;
        std::uint64_t lengthBytes = 0;
    };

    struct DeletedDirectoryEntry
    {
        ForensicFileSystemKind fileSystem =
            ForensicFileSystemKind::Unknown;
        QString name;
        QString directoryPath;
        QString evidenceText;
        std::uint64_t directoryEntryOffset = 0;
        std::uint64_t firstCluster = 0;
        std::uint64_t fileSizeBytes = 0;
        bool directory = false;
        bool exactExtents = false;
        bool clustersCurrentlyFree = false;
        std::vector<DeletedFileExtent> extents;
    };

    struct DeletedEntryScanResult
    {
        bool success = false;
        QString fileSystemName;
        QString errorText;
        QString summaryText;
        std::uint64_t scannedDirectoryEntries = 0;
        bool truncated = false;
        std::vector<DeletedDirectoryEntry> entries;
    };

    struct ExtentEraseResult
    {
        bool success = false;
        QString errorText;
        std::uint64_t bytesErased = 0;
        std::uint32_t extentsErased = 0;
    };

    class DiskDeletedEntryForensics final
    {
    public:
        static DeletedEntryScanResult scan(
            int diskIndex,
            unsigned long backend,
            std::uint64_t partitionOffset,
            std::uint64_t partitionLength,
            std::uint32_t logicalSectorSize);

        static ExtentEraseResult eraseExactFreeExtents(
            int diskIndex,
            unsigned long backend,
            std::uint32_t logicalSectorSize,
            unsigned long callerFlags,
            const DeletedDirectoryEntry& entry);
    };
}
