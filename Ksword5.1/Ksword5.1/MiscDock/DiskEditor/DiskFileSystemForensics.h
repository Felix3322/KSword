#pragma once

// ============================================================
// DiskFileSystemForensics.h
// 作用：
// 1) 统一探测常见 Windows/Linux/macOS 文件系统的磁盘级元数据；
// 2) 解析 Windows 已挂载文件的 VCN/LCN 区间并映射到物理磁盘；
// 3) 支持按卷簇号反查占用流，供磁盘编辑器双击定位。
// ============================================================

#include "DiskEditorModels.h"

#include <QString>

#include <cstdint>
#include <vector>

namespace ks::misc
{
    enum class ForensicFileSystemKind : int
    {
        Unknown = 0,
        Ntfs,
        Fat12,
        Fat16,
        Fat32,
        ExFat,
        ReFs,
        Ext2,
        Ext3,
        Ext4,
        Btrfs,
        Apfs,
        Hfs,
        HfsPlus
    };

    struct FileSystemProbeField
    {
        QString name;
        QString value;
        QString detail;
        std::uint64_t absoluteOffset = 0;
        std::uint32_t sizeBytes = 0;
    };

    struct FileSystemProbeResult
    {
        bool success = false;
        ForensicFileSystemKind kind = ForensicFileSystemKind::Unknown;
        QString name;
        QString volumeLabel;
        QString capabilityText;
        QString errorText;
        std::uint32_t logicalSectorSize = 0;
        std::uint32_t blockSize = 0;
        std::uint64_t totalBytes = 0;
        std::uint64_t rootObject = 0;
        std::vector<FileSystemProbeField> fields;
    };

    struct PhysicalFileExtent
    {
        int diskNumber = -1;
        std::uint64_t fileOffset = 0;
        std::uint64_t volumeOffset = 0;
        std::uint64_t physicalOffset = 0;
        std::uint64_t lengthBytes = 0;
        std::int64_t startingVcn = 0;
        std::int64_t startingLcn = -1;
        bool sparse = false;
        bool physicalMappingExact = false;
    };

    struct FileExtentResult
    {
        bool success = false;
        QString filePath;
        QString volumePath;
        QString fileSystemName;
        QString errorText;
        std::uint32_t bytesPerCluster = 0;
        std::uint64_t fileSizeBytes = 0;
        std::vector<PhysicalFileExtent> extents;
    };

    struct ReverseClusterEntry
    {
        std::uint64_t cluster = 0;
        std::uint64_t clusterCount = 0;
        QString streamPath;
    };

    struct ReverseClusterResult
    {
        bool success = false;
        QString volumePath;
        QString errorText;
        std::vector<ReverseClusterEntry> entries;
    };

    class DiskFileSystemForensics final
    {
    public:
        static FileSystemProbeResult probePartition(
            int diskIndex,
            unsigned long backend,
            std::uint64_t partitionOffset,
            std::uint64_t partitionLength,
            std::uint32_t logicalSectorSize);

        static FileExtentResult resolveFileExtents(const QString& filePath);

        static ReverseClusterResult reverseLookupCluster(
            const QString& volumePath,
            std::uint64_t cluster,
            std::uint32_t clusterCount = 1U);

        static QString fileSystemName(ForensicFileSystemKind kind);
    };
}
