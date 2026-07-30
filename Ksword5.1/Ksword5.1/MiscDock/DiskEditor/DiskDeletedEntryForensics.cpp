#include "DiskDeletedEntryForensics.h"

#include "DiskEditorBackend.h"

#include <QByteArray>
#include <QChar>
#include <QSet>

#include <algorithm>
#include <array>
#include <cstring>
#include <limits>
#include <utility>

namespace
{
    constexpr std::uint32_t kMaximumTransfer = 256U * 1024U;
    constexpr std::uint64_t kMaximumDirectoryBytes = 64ULL * 1024ULL * 1024ULL;
    constexpr std::uint64_t kMaximumBitmapBytes = 64ULL * 1024ULL * 1024ULL;
    constexpr std::uint64_t kMaximumChainClusters = 1ULL << 20U;
    constexpr std::uint64_t kMaximumScannedEntries = 2ULL * 1024ULL * 1024ULL;
    constexpr std::size_t kMaximumDeletedResults = 100000U;
    constexpr int kMaximumDirectoryDepth = 64;

    std::uint16_t le16(const QByteArray& bytes, const int offset)
    {
        if (offset < 0 || offset + 2 > bytes.size())
        {
            return 0;
        }
        const auto* value =
            reinterpret_cast<const unsigned char*>(bytes.constData() + offset);
        return static_cast<std::uint16_t>(value[0])
            | (static_cast<std::uint16_t>(value[1]) << 8U);
    }

    std::uint32_t le32(const QByteArray& bytes, const int offset)
    {
        if (offset < 0 || offset + 4 > bytes.size())
        {
            return 0;
        }
        const auto* value =
            reinterpret_cast<const unsigned char*>(bytes.constData() + offset);
        return static_cast<std::uint32_t>(value[0])
            | (static_cast<std::uint32_t>(value[1]) << 8U)
            | (static_cast<std::uint32_t>(value[2]) << 16U)
            | (static_cast<std::uint32_t>(value[3]) << 24U);
    }

    std::uint64_t le64(const QByteArray& bytes, const int offset)
    {
        return static_cast<std::uint64_t>(le32(bytes, offset))
            | (static_cast<std::uint64_t>(le32(bytes, offset + 4)) << 32U);
    }

    bool bytesEqual(
        const QByteArray& bytes,
        const int offset,
        const char* const expected,
        const int expectedLength)
    {
        return offset >= 0
            && expected != nullptr
            && expectedLength > 0
            && offset + expectedLength <= bytes.size()
            && std::memcmp(
                bytes.constData() + offset,
                expected,
                static_cast<std::size_t>(expectedLength)) == 0;
    }

    struct RawReader
    {
        int diskIndex = -1;
        unsigned long backend = 1UL;
        std::uint32_t sectorSize = 512U;

        bool read(
            const std::uint64_t offset,
            const std::uint64_t length,
            QByteArray& output,
            QString& errorText) const
        {
            output.clear();
            if (length == 0U)
            {
                return true;
            }
            if (sectorSize == 0U
                || offset > std::numeric_limits<std::uint64_t>::max() - length)
            {
                errorText = QStringLiteral("原始读取范围无效。");
                return false;
            }

            const std::uint64_t alignedStart =
                offset - (offset % sectorSize);
            const std::uint64_t requestedEnd = offset + length;
            const std::uint64_t remainder = requestedEnd % sectorSize;
            const std::uint64_t alignedEnd = remainder == 0U
                ? requestedEnd
                : requestedEnd + (sectorSize - remainder);
            if (alignedEnd < requestedEnd
                || alignedEnd - alignedStart
                    > static_cast<std::uint64_t>(std::numeric_limits<int>::max()))
            {
                errorText = QStringLiteral("原始读取范围过大。");
                return false;
            }

            QByteArray alignedBytes;
            alignedBytes.reserve(static_cast<int>(alignedEnd - alignedStart));
            std::uint64_t cursor = alignedStart;
            while (cursor < alignedEnd)
            {
                const std::uint64_t remaining = alignedEnd - cursor;
                std::uint32_t chunk = static_cast<std::uint32_t>(
                    std::min<std::uint64_t>(remaining, kMaximumTransfer));
                chunk -= chunk % sectorSize;
                if (chunk == 0U)
                {
                    chunk = sectorSize;
                }

                QByteArray chunkBytes;
                if (!ks::misc::DiskEditorBackend::readBytesWithBackend(
                    diskIndex,
                    backend,
                    cursor,
                    chunk,
                    chunkBytes,
                    errorText))
                {
                    return false;
                }
                if (chunkBytes.size() != static_cast<int>(chunk))
                {
                    errorText = QStringLiteral(
                        "原始读取返回长度不足：期望 %1，实际 %2。")
                        .arg(chunk)
                        .arg(chunkBytes.size());
                    return false;
                }
                alignedBytes.append(chunkBytes);
                cursor += chunk;
            }

            const std::uint64_t sliceOffset = offset - alignedStart;
            output = alignedBytes.mid(
                static_cast<int>(sliceOffset),
                static_cast<int>(length));
            return output.size() == static_cast<int>(length);
        }
    };

    struct DirectoryImage
    {
        QByteArray bytes;
        std::vector<std::uint64_t> entryOffsets;
    };

    struct FatContext
    {
        RawReader reader;
        ks::misc::ForensicFileSystemKind kind =
            ks::misc::ForensicFileSystemKind::Unknown;
        std::uint64_t partitionOffset = 0;
        std::uint64_t partitionLength = 0;
        std::uint32_t bytesPerSector = 0;
        std::uint32_t sectorsPerCluster = 0;
        std::uint32_t clusterSize = 0;
        std::uint32_t reservedSectors = 0;
        std::uint32_t fatCount = 0;
        std::uint32_t fatSectors = 0;
        std::uint32_t rootEntryCount = 0;
        std::uint32_t rootCluster = 0;
        std::uint64_t fatOffset = 0;
        std::uint64_t rootDirectoryOffset = 0;
        std::uint64_t rootDirectoryBytes = 0;
        std::uint64_t dataOffset = 0;
        std::uint64_t clusterCount = 0;
    };

    bool checkedClusterOffset(
        const FatContext& context,
        const std::uint32_t cluster,
        std::uint64_t& offsetOut)
    {
        if (cluster < 2U
            || cluster >= context.clusterCount + 2ULL)
        {
            return false;
        }
        const std::uint64_t relative =
            (static_cast<std::uint64_t>(cluster) - 2ULL)
            * context.clusterSize;
        if (relative > context.partitionLength
            || context.dataOffset > std::numeric_limits<std::uint64_t>::max()
                - relative
            || context.dataOffset + relative + context.clusterSize
                > context.partitionOffset + context.partitionLength)
        {
            return false;
        }
        offsetOut = context.dataOffset + relative;
        return true;
    }

    bool readFatEntry(
        const FatContext& context,
        const std::uint32_t cluster,
        std::uint32_t& valueOut,
        QString& errorText)
    {
        std::uint64_t entryOffset = 0;
        std::uint32_t entryBytes = 0;
        if (context.kind == ks::misc::ForensicFileSystemKind::Fat12)
        {
            entryOffset = cluster + (cluster / 2U);
            entryBytes = 2U;
        }
        else if (context.kind == ks::misc::ForensicFileSystemKind::Fat16)
        {
            entryOffset = static_cast<std::uint64_t>(cluster) * 2ULL;
            entryBytes = 2U;
        }
        else
        {
            entryOffset = static_cast<std::uint64_t>(cluster) * 4ULL;
            entryBytes = 4U;
        }

        QByteArray bytes;
        if (!context.reader.read(
            context.fatOffset + entryOffset,
            entryBytes,
            bytes,
            errorText))
        {
            return false;
        }

        if (context.kind == ks::misc::ForensicFileSystemKind::Fat12)
        {
            const std::uint32_t pair = le16(bytes, 0);
            valueOut = (cluster & 1U) == 0U
                ? pair & 0x0FFFU
                : (pair >> 4U) & 0x0FFFU;
        }
        else if (context.kind == ks::misc::ForensicFileSystemKind::Fat16)
        {
            valueOut = le16(bytes, 0);
        }
        else
        {
            valueOut = le32(bytes, 0) & 0x0FFFFFFFU;
        }
        return true;
    }

    bool fatEndOfChain(
        const ks::misc::ForensicFileSystemKind kind,
        const std::uint32_t value)
    {
        if (kind == ks::misc::ForensicFileSystemKind::Fat12)
        {
            return value >= 0x0FF8U;
        }
        if (kind == ks::misc::ForensicFileSystemKind::Fat16)
        {
            return value >= 0xFFF8U;
        }
        return value >= 0x0FFFFFF8U;
    }

    bool readFatDirectoryChain(
        const FatContext& context,
        const std::uint32_t firstCluster,
        DirectoryImage& imageOut,
        QString& errorText)
    {
        imageOut = {};
        QSet<std::uint32_t> visited;
        std::uint32_t cluster = firstCluster;
        while (cluster >= 2U
            && !fatEndOfChain(context.kind, cluster)
            && visited.size() < static_cast<qsizetype>(kMaximumChainClusters))
        {
            if (visited.contains(cluster))
            {
                errorText = QStringLiteral("FAT 目录簇链存在循环。");
                return false;
            }
            visited.insert(cluster);
            std::uint64_t clusterOffset = 0;
            if (!checkedClusterOffset(context, cluster, clusterOffset))
            {
                errorText = QStringLiteral("FAT 目录簇超出分区边界。");
                return false;
            }
            if (static_cast<std::uint64_t>(imageOut.bytes.size())
                + context.clusterSize > kMaximumDirectoryBytes)
            {
                errorText = QStringLiteral("FAT 目录超过单目录取证上限。");
                return false;
            }

            QByteArray clusterBytes;
            if (!context.reader.read(
                clusterOffset,
                context.clusterSize,
                clusterBytes,
                errorText))
            {
                return false;
            }
            imageOut.bytes.append(clusterBytes);
            const std::uint32_t entriesPerCluster =
                context.clusterSize / 32U;
            for (std::uint32_t index = 0; index < entriesPerCluster; ++index)
            {
                imageOut.entryOffsets.push_back(
                    clusterOffset + static_cast<std::uint64_t>(index) * 32ULL);
            }

            std::uint32_t next = 0;
            if (!readFatEntry(context, cluster, next, errorText))
            {
                return false;
            }
            if (fatEndOfChain(context.kind, next))
            {
                break;
            }
            if (next < 2U || next == 0x0FFFFFF7U)
            {
                errorText = QStringLiteral("FAT 目录簇链包含无效下一簇。");
                return false;
            }
            cluster = next;
        }
        return !imageOut.bytes.isEmpty();
    }

    QString fatLfnFragment(const QByteArray& entry)
    {
        static constexpr std::array<int, 13> offsets = {
            1, 3, 5, 7, 9,
            14, 16, 18, 20, 22, 24,
            28, 30
        };
        QString text;
        for (const int offset : offsets)
        {
            const std::uint16_t code = le16(entry, offset);
            if (code == 0U || code == 0xFFFFU)
            {
                break;
            }
            text.append(QChar(code));
        }
        return text;
    }

    QString fatShortName(const QByteArray& entry, const bool deleted)
    {
        QByteArray stem = entry.mid(0, 8);
        QByteArray extension = entry.mid(8, 3);
        if (deleted && !stem.isEmpty())
        {
            stem[0] = '?';
        }
        stem = stem.trimmed();
        extension = extension.trimmed();
        QString result = QString::fromLatin1(stem);
        if (!extension.isEmpty())
        {
            result += QLatin1Char('.');
            result += QString::fromLatin1(extension);
        }
        return result;
    }

    QString composeFatLongName(const std::vector<QString>& fragments)
    {
        QString name;
        for (auto iterator = fragments.rbegin();
             iterator != fragments.rend();
             ++iterator)
        {
            name += *iterator;
        }
        return name.trimmed();
    }

    bool appendFatDeletedEntry(
        const FatContext& context,
        const QByteArray& entry,
        const std::uint64_t entryOffset,
        const QString& directoryPath,
        const QString& longName,
        ks::misc::DeletedEntryScanResult& result,
        QString& errorText)
    {
        ks::misc::DeletedDirectoryEntry deleted;
        deleted.fileSystem = context.kind;
        deleted.name = longName.isEmpty()
            ? fatShortName(entry, true)
            : longName;
        deleted.directoryPath = directoryPath;
        deleted.directoryEntryOffset = entryOffset;
        deleted.directory = (static_cast<unsigned char>(entry.at(11)) & 0x10U) != 0U;
        deleted.firstCluster =
            (static_cast<std::uint32_t>(le16(entry, 20)) << 16U)
            | le16(entry, 26);
        deleted.fileSizeBytes = le32(entry, 28);
        deleted.evidenceText = QStringLiteral(
            "目录项首字节为 0xE5；名称与簇号来自仍保留的目录记录。");

        if (!deleted.directory
            && deleted.fileSizeBytes > 0U
            && deleted.firstCluster >= 2U
            && deleted.fileSizeBytes <= context.clusterSize)
        {
            std::uint32_t fatValue = 0;
            std::uint64_t clusterOffset = 0;
            if (!readFatEntry(
                    context,
                    static_cast<std::uint32_t>(deleted.firstCluster),
                    fatValue,
                    errorText)
                || !checkedClusterOffset(
                    context,
                    static_cast<std::uint32_t>(deleted.firstCluster),
                    clusterOffset))
            {
                return false;
            }
            if (fatValue == 0U)
            {
                deleted.exactExtents = true;
                deleted.clustersCurrentlyFree = true;
                deleted.extents.push_back({
                    clusterOffset,
                    context.clusterSize
                    });
                deleted.evidenceText += QStringLiteral(
                    " 文件不超过一个簇，首簇当前为空闲，因此物理区间可精确确认。");
            }
        }

        result.entries.push_back(std::move(deleted));
        return true;
    }

    bool scanFatDirectory(
        const FatContext& context,
        const DirectoryImage& image,
        const QString& directoryPath,
        const int depth,
        QSet<std::uint32_t>& visitedDirectories,
        ks::misc::DeletedEntryScanResult& result,
        QString& errorText)
    {
        if (depth > kMaximumDirectoryDepth)
        {
            result.truncated = true;
            return true;
        }

        std::vector<QString> pendingLongName;
        const int entryCount = image.bytes.size() / 32;
        for (int index = 0; index < entryCount; ++index)
        {
            if (result.scannedDirectoryEntries >= kMaximumScannedEntries
                || result.entries.size() >= kMaximumDeletedResults)
            {
                result.truncated = true;
                return true;
            }
            ++result.scannedDirectoryEntries;

            const QByteArray entry = image.bytes.mid(index * 32, 32);
            const unsigned char first =
                static_cast<unsigned char>(entry.at(0));
            if (first == 0x00U)
            {
                break;
            }
            const unsigned char attributes =
                static_cast<unsigned char>(entry.at(11));
            if (attributes == 0x0FU)
            {
                pendingLongName.push_back(fatLfnFragment(entry));
                continue;
            }

            const QString longName = composeFatLongName(pendingLongName);
            pendingLongName.clear();
            if ((attributes & 0x08U) != 0U)
            {
                continue;
            }

            const std::uint64_t entryOffset =
                index < static_cast<int>(image.entryOffsets.size())
                ? image.entryOffsets[static_cast<std::size_t>(index)]
                : 0U;
            if (first == 0xE5U)
            {
                if (!appendFatDeletedEntry(
                    context,
                    entry,
                    entryOffset,
                    directoryPath,
                    longName,
                    result,
                    errorText))
                {
                    return false;
                }
                continue;
            }

            if ((attributes & 0x10U) == 0U)
            {
                continue;
            }
            const QString shortName = fatShortName(entry, false);
            const QString displayName = longName.isEmpty()
                ? shortName
                : longName;
            if (displayName == QStringLiteral(".")
                || displayName == QStringLiteral(".."))
            {
                continue;
            }
            const std::uint32_t firstCluster =
                (static_cast<std::uint32_t>(le16(entry, 20)) << 16U)
                | le16(entry, 26);
            if (firstCluster < 2U || visitedDirectories.contains(firstCluster))
            {
                continue;
            }
            visitedDirectories.insert(firstCluster);
            DirectoryImage child;
            if (!readFatDirectoryChain(context, firstCluster, child, errorText))
            {
                return false;
            }
            if (!scanFatDirectory(
                context,
                child,
                directoryPath + QLatin1Char('/') + displayName,
                depth + 1,
                visitedDirectories,
                result,
                errorText))
            {
                return false;
            }
        }
        return true;
    }

    bool initializeFatContext(
        const RawReader& reader,
        const std::uint64_t partitionOffset,
        const std::uint64_t partitionLength,
        const QByteArray& boot,
        FatContext& contextOut,
        QString& errorText)
    {
        FatContext context;
        context.reader = reader;
        context.partitionOffset = partitionOffset;
        context.partitionLength = partitionLength;
        context.bytesPerSector = le16(boot, 11);
        context.sectorsPerCluster =
            static_cast<unsigned char>(boot.at(13));
        context.reservedSectors = le16(boot, 14);
        context.fatCount = static_cast<unsigned char>(boot.at(16));
        context.rootEntryCount = le16(boot, 17);
        const std::uint32_t totalSectors = le16(boot, 19) != 0U
            ? le16(boot, 19)
            : le32(boot, 32);
        context.fatSectors = le16(boot, 22) != 0U
            ? le16(boot, 22)
            : le32(boot, 36);
        context.rootCluster = le32(boot, 44);

        if (context.bytesPerSector == 0U
            || context.sectorsPerCluster == 0U
            || context.fatCount == 0U
            || context.fatSectors == 0U
            || totalSectors == 0U)
        {
            errorText = QStringLiteral("FAT BPB 几何字段无效。");
            return false;
        }
        context.clusterSize =
            context.bytesPerSector * context.sectorsPerCluster;
        const std::uint64_t rootDirectorySectors =
            ((static_cast<std::uint64_t>(context.rootEntryCount) * 32ULL)
                + context.bytesPerSector - 1ULL)
            / context.bytesPerSector;
        const std::uint64_t dataSectors =
            static_cast<std::uint64_t>(totalSectors)
            - (context.reservedSectors
                + static_cast<std::uint64_t>(context.fatCount)
                    * context.fatSectors
                + rootDirectorySectors);
        context.clusterCount =
            dataSectors / context.sectorsPerCluster;
        context.kind = context.clusterCount < 4085ULL
            ? ks::misc::ForensicFileSystemKind::Fat12
            : (context.clusterCount < 65525ULL
                ? ks::misc::ForensicFileSystemKind::Fat16
                : ks::misc::ForensicFileSystemKind::Fat32);
        context.fatOffset = partitionOffset
            + static_cast<std::uint64_t>(context.reservedSectors)
                * context.bytesPerSector;
        context.rootDirectoryOffset = context.fatOffset
            + static_cast<std::uint64_t>(context.fatCount)
                * context.fatSectors
                * context.bytesPerSector;
        context.rootDirectoryBytes =
            rootDirectorySectors * context.bytesPerSector;
        context.dataOffset =
            context.rootDirectoryOffset + context.rootDirectoryBytes;

        if (context.kind == ks::misc::ForensicFileSystemKind::Fat32)
        {
            context.rootDirectoryBytes = 0U;
            context.dataOffset = partitionOffset
                + (static_cast<std::uint64_t>(context.reservedSectors)
                    + static_cast<std::uint64_t>(context.fatCount)
                        * context.fatSectors)
                    * context.bytesPerSector;
        }
        contextOut = context;
        return true;
    }

    bool scanFat(
        const RawReader& reader,
        const std::uint64_t partitionOffset,
        const std::uint64_t partitionLength,
        const QByteArray& boot,
        ks::misc::DeletedEntryScanResult& result)
    {
        FatContext context;
        QString errorText;
        if (!initializeFatContext(
            reader,
            partitionOffset,
            partitionLength,
            boot,
            context,
            errorText))
        {
            result.errorText = errorText;
            return false;
        }

        result.fileSystemName =
            ks::misc::DiskFileSystemForensics::fileSystemName(context.kind);
        DirectoryImage root;
        if (context.kind == ks::misc::ForensicFileSystemKind::Fat32)
        {
            if (!readFatDirectoryChain(
                context,
                context.rootCluster,
                root,
                errorText))
            {
                result.errorText = errorText;
                return false;
            }
        }
        else
        {
            if (context.rootDirectoryBytes > kMaximumDirectoryBytes
                || !reader.read(
                    context.rootDirectoryOffset,
                    context.rootDirectoryBytes,
                    root.bytes,
                    errorText))
            {
                result.errorText = errorText.isEmpty()
                    ? QStringLiteral("FAT 根目录超过取证上限。")
                    : errorText;
                return false;
            }
            const std::uint64_t entryCount =
                context.rootDirectoryBytes / 32ULL;
            root.entryOffsets.reserve(static_cast<std::size_t>(entryCount));
            for (std::uint64_t index = 0; index < entryCount; ++index)
            {
                root.entryOffsets.push_back(
                    context.rootDirectoryOffset + index * 32ULL);
            }
        }

        QSet<std::uint32_t> visitedDirectories;
        if (context.kind == ks::misc::ForensicFileSystemKind::Fat32)
        {
            visitedDirectories.insert(context.rootCluster);
        }
        if (!scanFatDirectory(
            context,
            root,
            QStringLiteral("/"),
            0,
            visitedDirectories,
            result,
            errorText))
        {
            result.errorText = errorText;
            return false;
        }
        return true;
    }

    struct ExFatContext
    {
        RawReader reader;
        std::uint64_t partitionOffset = 0;
        std::uint64_t partitionLength = 0;
        std::uint32_t sectorSize = 0;
        std::uint32_t clusterSize = 0;
        std::uint32_t fatOffsetSectors = 0;
        std::uint32_t clusterHeapOffsetSectors = 0;
        std::uint32_t clusterCount = 0;
        std::uint32_t rootCluster = 0;
        std::uint64_t fatOffset = 0;
        std::uint64_t clusterHeapOffset = 0;
        QByteArray allocationBitmap;
    };

    bool exFatClusterOffset(
        const ExFatContext& context,
        const std::uint32_t cluster,
        std::uint64_t& offsetOut)
    {
        if (cluster < 2U || cluster >= context.clusterCount + 2U)
        {
            return false;
        }
        const std::uint64_t relative =
            (static_cast<std::uint64_t>(cluster) - 2ULL)
            * context.clusterSize;
        if (context.clusterHeapOffset
                > std::numeric_limits<std::uint64_t>::max() - relative
            || context.clusterHeapOffset + relative + context.clusterSize
                > context.partitionOffset + context.partitionLength)
        {
            return false;
        }
        offsetOut = context.clusterHeapOffset + relative;
        return true;
    }

    bool readExFatNextCluster(
        const ExFatContext& context,
        const std::uint32_t cluster,
        std::uint32_t& nextOut,
        QString& errorText)
    {
        QByteArray bytes;
        if (!context.reader.read(
            context.fatOffset + static_cast<std::uint64_t>(cluster) * 4ULL,
            4U,
            bytes,
            errorText))
        {
            return false;
        }
        nextOut = le32(bytes, 0);
        return true;
    }

    bool buildExFatClusterList(
        const ExFatContext& context,
        const std::uint32_t firstCluster,
        const std::uint64_t dataLength,
        const bool contiguous,
        std::vector<std::uint32_t>& clustersOut,
        QString& errorText)
    {
        clustersOut.clear();
        if (firstCluster < 2U)
        {
            errorText = QStringLiteral("exFAT 起始簇无效。");
            return false;
        }

        const std::uint64_t expectedClusters = dataLength == 0U
            ? 0U
            : (dataLength + context.clusterSize - 1ULL)
                / context.clusterSize;
        if (expectedClusters > kMaximumChainClusters)
        {
            errorText = QStringLiteral("exFAT 簇链超过取证上限。");
            return false;
        }

        if (contiguous && expectedClusters != 0U)
        {
            clustersOut.reserve(static_cast<std::size_t>(expectedClusters));
            for (std::uint64_t index = 0; index < expectedClusters; ++index)
            {
                const std::uint64_t cluster =
                    static_cast<std::uint64_t>(firstCluster) + index;
                if (cluster >= context.clusterCount + 2ULL)
                {
                    errorText = QStringLiteral("exFAT 连续簇范围越过分区边界。");
                    return false;
                }
                clustersOut.push_back(static_cast<std::uint32_t>(cluster));
            }
            return true;
        }

        QSet<std::uint32_t> visited;
        std::uint32_t cluster = firstCluster;
        while (cluster >= 2U
            && cluster < 0xFFFFFFF8U
            && visited.size() < static_cast<qsizetype>(kMaximumChainClusters))
        {
            if (visited.contains(cluster))
            {
                errorText = QStringLiteral("exFAT 簇链存在循环。");
                return false;
            }
            visited.insert(cluster);
            clustersOut.push_back(cluster);
            if (expectedClusters != 0U
                && clustersOut.size() >= expectedClusters)
            {
                return true;
            }
            std::uint32_t next = 0;
            if (!readExFatNextCluster(context, cluster, next, errorText))
            {
                return false;
            }
            if (next >= 0xFFFFFFF8U)
            {
                break;
            }
            if (next < 2U)
            {
                errorText = QStringLiteral("exFAT 簇链提前结束。");
                return false;
            }
            cluster = next;
        }
        return expectedClusters == 0U || clustersOut.size() == expectedClusters;
    }

    bool readExFatDirectory(
        const ExFatContext& context,
        const std::uint32_t firstCluster,
        const std::uint64_t dataLength,
        const bool contiguous,
        DirectoryImage& imageOut,
        QString& errorText)
    {
        imageOut = {};
        std::vector<std::uint32_t> clusters;
        if (!buildExFatClusterList(
            context,
            firstCluster,
            dataLength,
            contiguous,
            clusters,
            errorText))
        {
            return false;
        }
        const std::uint64_t maximumBytes = dataLength == 0U
            ? kMaximumDirectoryBytes
            : std::min<std::uint64_t>(dataLength, kMaximumDirectoryBytes);
        for (const std::uint32_t cluster : clusters)
        {
            if (static_cast<std::uint64_t>(imageOut.bytes.size())
                >= maximumBytes)
            {
                break;
            }
            std::uint64_t clusterOffset = 0;
            if (!exFatClusterOffset(context, cluster, clusterOffset))
            {
                errorText = QStringLiteral("exFAT 目录簇超出分区边界。");
                return false;
            }
            QByteArray clusterBytes;
            if (!context.reader.read(
                clusterOffset,
                context.clusterSize,
                clusterBytes,
                errorText))
            {
                return false;
            }
            const std::uint64_t remaining =
                maximumBytes - static_cast<std::uint64_t>(imageOut.bytes.size());
            if (remaining < context.clusterSize)
            {
                clusterBytes.truncate(static_cast<int>(remaining));
            }
            imageOut.bytes.append(clusterBytes);
            const int entries = clusterBytes.size() / 32;
            for (int index = 0; index < entries; ++index)
            {
                imageOut.entryOffsets.push_back(
                    clusterOffset + static_cast<std::uint64_t>(index) * 32ULL);
            }
        }
        return !imageOut.bytes.isEmpty();
    }

    QString exFatName(
        const QByteArray& bytes,
        const int primaryIndex,
        const int secondaryCount,
        const int nameLength)
    {
        QString name;
        name.reserve(nameLength);
        for (int secondary = 1;
             secondary <= secondaryCount && name.size() < nameLength;
             ++secondary)
        {
            const int entryOffset = (primaryIndex + secondary) * 32;
            if (entryOffset + 32 > bytes.size())
            {
                break;
            }
            const unsigned char type =
                static_cast<unsigned char>(bytes.at(entryOffset));
            if ((type & 0x7FU) != 0x41U)
            {
                continue;
            }
            for (int character = 0;
                 character < 15 && name.size() < nameLength;
                 ++character)
            {
                const std::uint16_t code =
                    le16(bytes, entryOffset + 2 + character * 2);
                if (code == 0U)
                {
                    break;
                }
                name.append(QChar(code));
            }
        }
        return name;
    }

    bool exFatClustersFree(
        const ExFatContext& context,
        const std::vector<std::uint32_t>& clusters)
    {
        if (context.allocationBitmap.isEmpty())
        {
            return false;
        }
        for (const std::uint32_t cluster : clusters)
        {
            if (cluster < 2U)
            {
                return false;
            }
            const std::uint64_t bit = cluster - 2ULL;
            const std::uint64_t byteIndex = bit / 8ULL;
            if (byteIndex >= static_cast<std::uint64_t>(
                    context.allocationBitmap.size()))
            {
                return false;
            }
            const unsigned char value = static_cast<unsigned char>(
                context.allocationBitmap.at(static_cast<int>(byteIndex)));
            if ((value & (1U << (bit % 8ULL))) != 0U)
            {
                return false;
            }
        }
        return true;
    }

    std::vector<ks::misc::DeletedFileExtent> mergeClusterExtents(
        const ExFatContext& context,
        const std::vector<std::uint32_t>& clusters)
    {
        std::vector<ks::misc::DeletedFileExtent> extents;
        for (const std::uint32_t cluster : clusters)
        {
            std::uint64_t offset = 0;
            if (!exFatClusterOffset(context, cluster, offset))
            {
                return {};
            }
            if (!extents.empty()
                && extents.back().physicalOffset
                    + extents.back().lengthBytes == offset)
            {
                extents.back().lengthBytes += context.clusterSize;
            }
            else
            {
                extents.push_back({ offset, context.clusterSize });
            }
        }
        return extents;
    }

    bool scanExFatDirectory(
        const ExFatContext& context,
        const DirectoryImage& image,
        const QString& directoryPath,
        const int depth,
        QSet<std::uint32_t>& visitedDirectories,
        ks::misc::DeletedEntryScanResult& result,
        QString& errorText)
    {
        if (depth > kMaximumDirectoryDepth)
        {
            result.truncated = true;
            return true;
        }
        const int entryCount = image.bytes.size() / 32;
        for (int index = 0; index < entryCount; ++index)
        {
            if (result.scannedDirectoryEntries >= kMaximumScannedEntries
                || result.entries.size() >= kMaximumDeletedResults)
            {
                result.truncated = true;
                return true;
            }
            ++result.scannedDirectoryEntries;
            const int entryOffset = index * 32;
            const unsigned char type =
                static_cast<unsigned char>(image.bytes.at(entryOffset));
            if (type == 0x00U)
            {
                break;
            }
            if ((type & 0x7FU) != 0x05U)
            {
                continue;
            }

            const int secondaryCount =
                static_cast<unsigned char>(image.bytes.at(entryOffset + 1));
            if (secondaryCount <= 0
                || index + secondaryCount >= entryCount)
            {
                continue;
            }
            int streamOffset = -1;
            for (int secondary = 1; secondary <= secondaryCount; ++secondary)
            {
                const int candidate = (index + secondary) * 32;
                const unsigned char secondaryType =
                    static_cast<unsigned char>(image.bytes.at(candidate));
                if ((secondaryType & 0x7FU) == 0x40U)
                {
                    streamOffset = candidate;
                    break;
                }
            }
            if (streamOffset < 0)
            {
                index += secondaryCount;
                continue;
            }

            const bool active = (type & 0x80U) != 0U;
            const std::uint16_t attributes =
                le16(image.bytes, entryOffset + 4);
            const bool directory = (attributes & 0x10U) != 0U;
            const unsigned char generalFlags =
                static_cast<unsigned char>(image.bytes.at(streamOffset + 1));
            const bool contiguous = (generalFlags & 0x02U) != 0U;
            const int nameLength =
                static_cast<unsigned char>(image.bytes.at(streamOffset + 3));
            const std::uint32_t firstCluster =
                le32(image.bytes, streamOffset + 20);
            const std::uint64_t dataLength =
                le64(image.bytes, streamOffset + 24);
            const QString name = exFatName(
                image.bytes,
                index,
                secondaryCount,
                nameLength);

            if (!active)
            {
                ks::misc::DeletedDirectoryEntry deleted;
                deleted.fileSystem =
                    ks::misc::ForensicFileSystemKind::ExFat;
                deleted.name = name.isEmpty()
                    ? QStringLiteral("deleted_%1")
                        .arg(static_cast<qulonglong>(
                            image.entryOffsets[static_cast<std::size_t>(index)]),
                            0,
                            16)
                    : name;
                deleted.directoryPath = directoryPath;
                deleted.directoryEntryOffset =
                    image.entryOffsets[static_cast<std::size_t>(index)];
                deleted.firstCluster = firstCluster;
                deleted.fileSizeBytes = dataLength;
                deleted.directory = directory;
                deleted.evidenceText = QStringLiteral(
                    "主文件目录项处于非活动状态，次级流与名称记录仍可校验。");

                if (!directory && dataLength > 0U && firstCluster >= 2U)
                {
                    std::vector<std::uint32_t> clusters;
                    if (buildExFatClusterList(
                        context,
                        firstCluster,
                        dataLength,
                        contiguous,
                        clusters,
                        errorText))
                    {
                        deleted.clustersCurrentlyFree =
                            exFatClustersFree(context, clusters);
                        if (deleted.clustersCurrentlyFree)
                        {
                            deleted.extents =
                                mergeClusterExtents(context, clusters);
                            deleted.exactExtents = !deleted.extents.empty();
                            if (deleted.exactExtents)
                            {
                                deleted.evidenceText += QStringLiteral(
                                    " 簇链/连续标志与分配位图一致，物理区间可精确确认且当前空闲。");
                            }
                        }
                    }
                    else
                    {
                        errorText.clear();
                    }
                }
                result.entries.push_back(std::move(deleted));
            }
            else if (directory
                && firstCluster >= 2U
                && !visitedDirectories.contains(firstCluster))
            {
                visitedDirectories.insert(firstCluster);
                DirectoryImage child;
                if (!readExFatDirectory(
                    context,
                    firstCluster,
                    dataLength,
                    contiguous,
                    child,
                    errorText))
                {
                    return false;
                }
                if (!scanExFatDirectory(
                    context,
                    child,
                    directoryPath + QLatin1Char('/') + name,
                    depth + 1,
                    visitedDirectories,
                    result,
                    errorText))
                {
                    return false;
                }
            }
            index += secondaryCount;
        }
        return true;
    }

    bool loadExFatAllocationBitmap(
        ExFatContext& context,
        const DirectoryImage& root,
        QString& errorText)
    {
        const int entryCount = root.bytes.size() / 32;
        for (int index = 0; index < entryCount; ++index)
        {
            const int offset = index * 32;
            const unsigned char type =
                static_cast<unsigned char>(root.bytes.at(offset));
            if (type == 0x00U)
            {
                break;
            }
            if (type != 0x81U)
            {
                continue;
            }
            const std::uint32_t firstCluster = le32(root.bytes, offset + 20);
            const std::uint64_t length = le64(root.bytes, offset + 24);
            if (length == 0U || length > kMaximumBitmapBytes)
            {
                errorText = QStringLiteral("exFAT 分配位图长度无效或超过上限。");
                return false;
            }
            std::vector<std::uint32_t> clusters;
            if (!buildExFatClusterList(
                context,
                firstCluster,
                length,
                false,
                clusters,
                errorText))
            {
                return false;
            }
            QByteArray bitmap;
            bitmap.reserve(static_cast<int>(length));
            for (const std::uint32_t cluster : clusters)
            {
                std::uint64_t clusterOffset = 0;
                if (!exFatClusterOffset(context, cluster, clusterOffset))
                {
                    errorText = QStringLiteral("exFAT 分配位图簇超出分区边界。");
                    return false;
                }
                QByteArray bytes;
                if (!context.reader.read(
                    clusterOffset,
                    context.clusterSize,
                    bytes,
                    errorText))
                {
                    return false;
                }
                bitmap.append(bytes);
                if (static_cast<std::uint64_t>(bitmap.size()) >= length)
                {
                    bitmap.truncate(static_cast<int>(length));
                    break;
                }
            }
            context.allocationBitmap = bitmap;
            return context.allocationBitmap.size()
                == static_cast<int>(length);
        }
        errorText = QStringLiteral("exFAT 根目录中未找到活动分配位图。");
        return false;
    }

    bool scanExFat(
        const RawReader& reader,
        const std::uint64_t partitionOffset,
        const std::uint64_t partitionLength,
        const QByteArray& boot,
        ks::misc::DeletedEntryScanResult& result)
    {
        ExFatContext context;
        context.reader = reader;
        context.partitionOffset = partitionOffset;
        context.partitionLength = partitionLength;
        const std::uint32_t sectorShift =
            static_cast<unsigned char>(boot.at(108));
        const std::uint32_t clusterShift =
            static_cast<unsigned char>(boot.at(109));
        if (sectorShift < 9U
            || sectorShift > 12U
            || clusterShift > 25U
            || sectorShift + clusterShift >= 32U)
        {
            result.errorText = QStringLiteral("exFAT 扇区或簇位移无效。");
            return false;
        }
        context.sectorSize = 1U << sectorShift;
        context.clusterSize = 1U << (sectorShift + clusterShift);
        context.fatOffsetSectors = le32(boot, 80);
        context.clusterHeapOffsetSectors = le32(boot, 88);
        context.clusterCount = le32(boot, 92);
        context.rootCluster = le32(boot, 96);
        context.fatOffset = partitionOffset
            + static_cast<std::uint64_t>(context.fatOffsetSectors)
                * context.sectorSize;
        context.clusterHeapOffset = partitionOffset
            + static_cast<std::uint64_t>(context.clusterHeapOffsetSectors)
                * context.sectorSize;
        if (context.clusterSize == 0U
            || context.clusterCount == 0U
            || context.rootCluster < 2U)
        {
            result.errorText = QStringLiteral("exFAT 启动区几何字段无效。");
            return false;
        }

        QString errorText;
        DirectoryImage root;
        if (!readExFatDirectory(
            context,
            context.rootCluster,
            0U,
            false,
            root,
            errorText))
        {
            result.errorText = errorText;
            return false;
        }
        if (!loadExFatAllocationBitmap(context, root, errorText))
        {
            result.errorText = errorText;
            return false;
        }

        result.fileSystemName = QStringLiteral("exFAT");
        QSet<std::uint32_t> visitedDirectories;
        visitedDirectories.insert(context.rootCluster);
        if (!scanExFatDirectory(
            context,
            root,
            QStringLiteral("/"),
            0,
            visitedDirectories,
            result,
            errorText))
        {
            result.errorText = errorText;
            return false;
        }
        return true;
    }
}

namespace ks::misc
{
    DeletedEntryScanResult DiskDeletedEntryForensics::scan(
        const int diskIndex,
        const unsigned long backend,
        const std::uint64_t partitionOffset,
        const std::uint64_t partitionLength,
        const std::uint32_t logicalSectorSize)
    {
        DeletedEntryScanResult result;
        if (diskIndex < 0
            || partitionLength < 512U
            || logicalSectorSize == 0U)
        {
            result.errorText = QStringLiteral("删除项扫描参数无效。");
            return result;
        }

        RawReader reader;
        reader.diskIndex = diskIndex;
        reader.backend = backend;
        reader.sectorSize = logicalSectorSize;
        QByteArray boot;
        if (!reader.read(
            partitionOffset,
            std::max<std::uint32_t>(logicalSectorSize, 512U),
            boot,
            result.errorText))
        {
            return result;
        }

        bool scanOk = false;
        if (bytesEqual(boot, 3, "EXFAT   ", 8))
        {
            scanOk = scanExFat(
                reader,
                partitionOffset,
                partitionLength,
                boot,
                result);
        }
        else
        {
            const std::uint16_t bytesPerSector = le16(boot, 11);
            const std::uint32_t sectorsPerCluster =
                boot.size() > 13
                ? static_cast<unsigned char>(boot.at(13))
                : 0U;
            const std::uint32_t fatCount =
                boot.size() > 16
                ? static_cast<unsigned char>(boot.at(16))
                : 0U;
            if ((bytesPerSector == 512U
                    || bytesPerSector == 1024U
                    || bytesPerSector == 2048U
                    || bytesPerSector == 4096U)
                && sectorsPerCluster != 0U
                && fatCount != 0U)
            {
                scanOk = scanFat(
                    reader,
                    partitionOffset,
                    partitionLength,
                    boot,
                    result);
            }
            else if (bytesEqual(boot, 3, "NTFS    ", 8))
            {
                result.errorText = QStringLiteral(
                    "NTFS 删除项已由“文件管理 → 文件恢复”页执行完整 MFT 扫描；"
                    "此处的原始目录项扫描用于 FAT12/16/32 与 exFAT。");
                return result;
            }
            else
            {
                result.errorText = QStringLiteral(
                    "当前分区不是可扫描删除目录项的 FAT12/16/32、exFAT 或 NTFS。");
                return result;
            }
        }

        if (!scanOk)
        {
            return result;
        }
        result.success = true;
        result.summaryText = QStringLiteral(
            "%1：扫描 %2 个目录项，发现 %3 个删除候选，其中 %4 个具备可证明的空闲精确区间%5。")
            .arg(result.fileSystemName)
            .arg(static_cast<qulonglong>(result.scannedDirectoryEntries))
            .arg(result.entries.size())
            .arg(std::count_if(
                result.entries.cbegin(),
                result.entries.cend(),
                [](const DeletedDirectoryEntry& entry)
                {
                    return entry.exactExtents
                        && entry.clustersCurrentlyFree;
                }))
            .arg(result.truncated
                ? QStringLiteral("；结果达到安全上限，已截断")
                : QString());
        return result;
    }

    ExtentEraseResult DiskDeletedEntryForensics::eraseExactFreeExtents(
        const int diskIndex,
        const unsigned long backend,
        const std::uint32_t logicalSectorSize,
        const unsigned long callerFlags,
        const DeletedDirectoryEntry& entry)
    {
        ExtentEraseResult result;
        if (diskIndex < 0
            || logicalSectorSize == 0U
            || entry.directory
            || !entry.exactExtents
            || !entry.clustersCurrentlyFree
            || entry.extents.empty())
        {
            result.errorText = QStringLiteral(
                "仅允许擦除已证明精确、当前空闲且不属于目录的物理区间。");
            return result;
        }

        for (const DeletedFileExtent& extent : entry.extents)
        {
            if (extent.lengthBytes == 0U
                || (extent.physicalOffset % logicalSectorSize) != 0U
                || (extent.lengthBytes % logicalSectorSize) != 0U)
            {
                result.errorText = QStringLiteral(
                    "待擦除区间未按逻辑扇区对齐，操作已拒绝。");
                return result;
            }

            std::uint64_t cursor = extent.physicalOffset;
            std::uint64_t remaining = extent.lengthBytes;
            while (remaining != 0U)
            {
                std::uint32_t chunk = static_cast<std::uint32_t>(
                    std::min<std::uint64_t>(remaining, kMaximumTransfer));
                chunk -= chunk % logicalSectorSize;
                if (chunk == 0U)
                {
                    result.errorText = QStringLiteral(
                        "无法生成扇区对齐的擦除块。");
                    return result;
                }

                const QByteArray zeros(static_cast<int>(chunk), '\0');
                QString writeError;
                if (!DiskEditorBackend::writeBytesWithBackend(
                    diskIndex,
                    backend,
                    cursor,
                    zeros,
                    callerFlags,
                    writeError))
                {
                    result.errorText = QStringLiteral(
                        "擦除在 %1 字节后失败：%2")
                        .arg(static_cast<qulonglong>(result.bytesErased))
                        .arg(writeError);
                    return result;
                }

                QByteArray verify;
                QString verifyError;
                if (!DiskEditorBackend::readBytesWithBackend(
                    diskIndex,
                    backend,
                    cursor,
                    chunk,
                    verify,
                    verifyError)
                    || verify != zeros)
                {
                    result.errorText = QStringLiteral(
                        "擦除写入后校验失败，已完成 %1 字节：%2")
                        .arg(static_cast<qulonglong>(result.bytesErased + chunk))
                        .arg(verifyError.isEmpty()
                            ? QStringLiteral("回读内容不全为零")
                            : verifyError);
                    return result;
                }

                cursor += chunk;
                remaining -= chunk;
                result.bytesErased += chunk;
            }
            ++result.extentsErased;
        }
        result.success = true;
        return result;
    }
}
