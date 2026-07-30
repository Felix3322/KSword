#include "DiskFileSystemForensics.h"

#include "DiskEditorBackend.h"

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#include <winioctl.h>

#include <QByteArray>
#include <QFileInfo>

#include <algorithm>
#include <array>
#include <cstring>
#include <limits>
#include <vector>

namespace
{
    std::uint16_t le16(const QByteArray& bytes, const int offset)
    {
        if (offset < 0 || offset + 2 > bytes.size())
        {
            return 0;
        }
        const auto* value = reinterpret_cast<const unsigned char*>(bytes.constData() + offset);
        return static_cast<std::uint16_t>(value[0])
            | (static_cast<std::uint16_t>(value[1]) << 8U);
    }

    std::uint32_t le32(const QByteArray& bytes, const int offset)
    {
        if (offset < 0 || offset + 4 > bytes.size())
        {
            return 0;
        }
        const auto* value = reinterpret_cast<const unsigned char*>(bytes.constData() + offset);
        return static_cast<std::uint32_t>(value[0])
            | (static_cast<std::uint32_t>(value[1]) << 8U)
            | (static_cast<std::uint32_t>(value[2]) << 16U)
            | (static_cast<std::uint32_t>(value[3]) << 24U);
    }

    std::uint64_t le64(const QByteArray& bytes, const int offset)
    {
        if (offset < 0 || offset + 8 > bytes.size())
        {
            return 0;
        }
        const std::uint64_t low = le32(bytes, offset);
        const std::uint64_t high = le32(bytes, offset + 4);
        return low | (high << 32U);
    }

    std::uint16_t be16(const QByteArray& bytes, const int offset)
    {
        if (offset < 0 || offset + 2 > bytes.size())
        {
            return 0;
        }
        const auto* value = reinterpret_cast<const unsigned char*>(bytes.constData() + offset);
        return (static_cast<std::uint16_t>(value[0]) << 8U)
            | static_cast<std::uint16_t>(value[1]);
    }

    std::uint32_t be32(const QByteArray& bytes, const int offset)
    {
        if (offset < 0 || offset + 4 > bytes.size())
        {
            return 0;
        }
        const auto* value = reinterpret_cast<const unsigned char*>(bytes.constData() + offset);
        return (static_cast<std::uint32_t>(value[0]) << 24U)
            | (static_cast<std::uint32_t>(value[1]) << 16U)
            | (static_cast<std::uint32_t>(value[2]) << 8U)
            | static_cast<std::uint32_t>(value[3]);
    }

    std::uint64_t be64(const QByteArray& bytes, const int offset)
    {
        const std::uint64_t high = be32(bytes, offset);
        const std::uint64_t low = be32(bytes, offset + 4);
        return (high << 32U) | low;
    }

    QString boundedLatin1(
        const QByteArray& bytes,
        const int offset,
        const int length)
    {
        if (offset < 0 || length <= 0 || offset + length > bytes.size())
        {
            return {};
        }
        QByteArray text = bytes.mid(offset, length);
        const int terminator = text.indexOf('\0');
        if (terminator >= 0)
        {
            text.truncate(terminator);
        }
        return QString::fromLatin1(text).trimmed();
    }

    QString boundedUtf16Le(
        const QByteArray& bytes,
        const int offset,
        const int byteLength)
    {
        if (offset < 0
            || byteLength <= 0
            || (byteLength % 2) != 0
            || offset + byteLength > bytes.size())
        {
            return {};
        }

        QString text;
        text.reserve(byteLength / 2);
        for (int index = 0; index < byteLength; index += 2)
        {
            const std::uint16_t codeUnit = le16(bytes, offset + index);
            if (codeUnit == 0)
            {
                break;
            }
            text.append(QChar(codeUnit));
        }
        return text.trimmed();
    }

    QString guidText(const QByteArray& bytes, const int offset)
    {
        if (offset < 0 || offset + 16 > bytes.size())
        {
            return {};
        }
        const auto* value = reinterpret_cast<const unsigned char*>(bytes.constData() + offset);
        return QStringLiteral(
            "%1%2%3%4-%5%6-%7%8-%9%10-%11%12%13%14%15%16")
            .arg(value[3], 2, 16, QChar('0'))
            .arg(value[2], 2, 16, QChar('0'))
            .arg(value[1], 2, 16, QChar('0'))
            .arg(value[0], 2, 16, QChar('0'))
            .arg(value[5], 2, 16, QChar('0'))
            .arg(value[4], 2, 16, QChar('0'))
            .arg(value[7], 2, 16, QChar('0'))
            .arg(value[6], 2, 16, QChar('0'))
            .arg(value[8], 2, 16, QChar('0'))
            .arg(value[9], 2, 16, QChar('0'))
            .arg(value[10], 2, 16, QChar('0'))
            .arg(value[11], 2, 16, QChar('0'))
            .arg(value[12], 2, 16, QChar('0'))
            .arg(value[13], 2, 16, QChar('0'))
            .arg(value[14], 2, 16, QChar('0'))
            .arg(value[15], 2, 16, QChar('0'))
            .toUpper();
    }

    void addField(
        ks::misc::FileSystemProbeResult& result,
        const QString& name,
        const QString& value,
        const QString& detail,
        const std::uint64_t absoluteOffset,
        const std::uint32_t sizeBytes)
    {
        ks::misc::FileSystemProbeField field;
        field.name = name;
        field.value = value;
        field.detail = detail;
        field.absoluteOffset = absoluteOffset;
        field.sizeBytes = sizeBytes;
        result.fields.push_back(std::move(field));
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
            && std::memcmp(bytes.constData() + offset, expected, expectedLength) == 0;
    }

    QString normalizeVolumeDevicePath(const QString& source)
    {
        QString value = source.trimmed();
        if (value.isEmpty())
        {
            return {};
        }
        if (value.startsWith(QStringLiteral("\\\\.\\")))
        {
            while (value.endsWith(QLatin1Char('\\')))
            {
                value.chop(1);
            }
            return value;
        }
        if (value.size() >= 2 && value.at(1) == QLatin1Char(':'))
        {
            return QStringLiteral("\\\\.\\%1").arg(value.left(2));
        }
        if (value.startsWith(QStringLiteral("\\\\?\\")))
        {
            while (value.endsWith(QLatin1Char('\\')))
            {
                value.chop(1);
            }
            value.replace(0, 4, QStringLiteral("\\\\.\\"));
            return value;
        }
        return value;
    }

    QString win32ErrorText(const QString& operation)
    {
        const DWORD error = ::GetLastError();
        wchar_t* systemText = nullptr;
        const DWORD chars = ::FormatMessageW(
            FORMAT_MESSAGE_ALLOCATE_BUFFER
                | FORMAT_MESSAGE_FROM_SYSTEM
                | FORMAT_MESSAGE_IGNORE_INSERTS,
            nullptr,
            error,
            0,
            reinterpret_cast<wchar_t*>(&systemText),
            0,
            nullptr);
        const QString detail = chars != 0 && systemText != nullptr
            ? QString::fromWCharArray(systemText, static_cast<int>(chars)).trimmed()
            : QStringLiteral("未知系统错误");
        if (systemText != nullptr)
        {
            ::LocalFree(systemText);
        }
        return QStringLiteral("%1失败，Win32=%2：%3")
            .arg(operation)
            .arg(error)
            .arg(detail);
    }
}

namespace ks::misc
{
    QString DiskFileSystemForensics::fileSystemName(
        const ForensicFileSystemKind kind)
    {
        switch (kind)
        {
        case ForensicFileSystemKind::Ntfs: return QStringLiteral("NTFS");
        case ForensicFileSystemKind::Fat12: return QStringLiteral("FAT12");
        case ForensicFileSystemKind::Fat16: return QStringLiteral("FAT16");
        case ForensicFileSystemKind::Fat32: return QStringLiteral("FAT32");
        case ForensicFileSystemKind::ExFat: return QStringLiteral("exFAT");
        case ForensicFileSystemKind::ReFs: return QStringLiteral("ReFS");
        case ForensicFileSystemKind::Ext2: return QStringLiteral("Ext2");
        case ForensicFileSystemKind::Ext3: return QStringLiteral("Ext3");
        case ForensicFileSystemKind::Ext4: return QStringLiteral("Ext4");
        case ForensicFileSystemKind::Btrfs: return QStringLiteral("BtrFS");
        case ForensicFileSystemKind::Apfs: return QStringLiteral("APFS");
        case ForensicFileSystemKind::Hfs: return QStringLiteral("HFS");
        case ForensicFileSystemKind::HfsPlus: return QStringLiteral("HFS+");
        case ForensicFileSystemKind::Unknown:
        default:
            return QStringLiteral("未知");
        }
    }

    FileSystemProbeResult DiskFileSystemForensics::probePartition(
        const int diskIndex,
        const unsigned long backend,
        const std::uint64_t partitionOffset,
        const std::uint64_t partitionLength,
        const std::uint32_t logicalSectorSize)
    {
        FileSystemProbeResult result;
        if (diskIndex < 0 || partitionLength < 2048U)
        {
            result.errorText = QStringLiteral("分区范围无效，无法执行文件系统探测。");
            return result;
        }

        const std::uint32_t sectorSize = logicalSectorSize == 0U
            ? 512U
            : logicalSectorSize;
        const std::uint32_t firstReadBytes = std::max<std::uint32_t>(
            4096U,
            sectorSize);
        QByteArray firstBytes;
        QString readError;
        if (!DiskEditorBackend::readBytesWithBackend(
            diskIndex,
            backend,
            partitionOffset,
            firstReadBytes,
            firstBytes,
            readError))
        {
            result.errorText = readError;
            return result;
        }

        result.logicalSectorSize = sectorSize;
        result.totalBytes = partitionLength;
        if (bytesEqual(firstBytes, 3, "NTFS    ", 8))
        {
            result.kind = ForensicFileSystemKind::Ntfs;
            result.name = fileSystemName(result.kind);
            result.capabilityText = QStringLiteral("原始启动扇区与 MFT 定位参数只读探测；已挂载文件支持物理区间映射");
            result.logicalSectorSize = le16(firstBytes, 11);
            const std::uint32_t sectorsPerCluster =
                static_cast<unsigned char>(firstBytes.at(13));
            result.blockSize = result.logicalSectorSize * sectorsPerCluster;
            result.totalBytes = le64(firstBytes, 40) * result.logicalSectorSize;
            result.rootObject = 5U;
            addField(result, QStringLiteral("OEM 标识"), boundedLatin1(firstBytes, 3, 8), QStringLiteral("NTFS 启动扇区签名"), partitionOffset + 3U, 8U);
            addField(result, QStringLiteral("每扇区字节"), QString::number(result.logicalSectorSize), QStringLiteral("逻辑扇区大小"), partitionOffset + 11U, 2U);
            addField(result, QStringLiteral("每簇扇区"), QString::number(sectorsPerCluster), QStringLiteral("用于计算簇大小"), partitionOffset + 13U, 1U);
            addField(result, QStringLiteral("MFT 起始簇"), QString::number(le64(firstBytes, 48)), QStringLiteral("$MFT 的逻辑簇号"), partitionOffset + 48U, 8U);
            addField(result, QStringLiteral("MFT 镜像簇"), QString::number(le64(firstBytes, 56)), QStringLiteral("$MFTMirr 的逻辑簇号"), partitionOffset + 56U, 8U);
        }
        else if (bytesEqual(firstBytes, 3, "EXFAT   ", 8))
        {
            result.kind = ForensicFileSystemKind::ExFat;
            result.name = fileSystemName(result.kind);
            result.capabilityText = QStringLiteral("原始启动区、FAT/位图、目录项与簇链只读解析；支持删除目录项取证");
            const std::uint32_t bytesPerSectorShift =
                static_cast<unsigned char>(firstBytes.at(108));
            const std::uint32_t sectorsPerClusterShift =
                static_cast<unsigned char>(firstBytes.at(109));
            result.logicalSectorSize = 1U << bytesPerSectorShift;
            result.blockSize = result.logicalSectorSize
                * (1U << sectorsPerClusterShift);
            result.totalBytes = le64(firstBytes, 72) * result.logicalSectorSize;
            result.rootObject = le32(firstBytes, 96);
            addField(result, QStringLiteral("文件系统标识"), boundedLatin1(firstBytes, 3, 8), QStringLiteral("exFAT 启动扇区签名"), partitionOffset + 3U, 8U);
            addField(result, QStringLiteral("FAT 起始扇区"), QString::number(le32(firstBytes, 80)), QStringLiteral("相对分区起点"), partitionOffset + 80U, 4U);
            addField(result, QStringLiteral("簇堆起始扇区"), QString::number(le32(firstBytes, 88)), QStringLiteral("相对分区起点"), partitionOffset + 88U, 4U);
            addField(result, QStringLiteral("根目录簇"), QString::number(result.rootObject), QStringLiteral("根目录簇链起点"), partitionOffset + 96U, 4U);
            addField(result, QStringLiteral("卷序列号"), QStringLiteral("0x%1").arg(le32(firstBytes, 100), 8, 16, QChar('0')).toUpper(), QStringLiteral("exFAT 卷标识"), partitionOffset + 100U, 4U);
        }
        else if (bytesEqual(firstBytes, 3, "ReFS", 4))
        {
            result.kind = ForensicFileSystemKind::ReFs;
            result.name = fileSystemName(result.kind);
            result.capabilityText = QStringLiteral("原始 VBR、版本与扇区/簇几何只读探测；已挂载文件支持物理区间映射");
            result.logicalSectorSize = le32(firstBytes, 32);
            result.blockSize = le32(firstBytes, 36);
            result.totalBytes = le64(firstBytes, 24) * result.logicalSectorSize;
            addField(result, QStringLiteral("文件系统标识"), boundedLatin1(firstBytes, 3, 8), QStringLiteral("ReFS VBR 标识"), partitionOffset + 3U, 8U);
            addField(result, QStringLiteral("扇区总数"), QString::number(le64(firstBytes, 24)), QStringLiteral("VBR 记录的卷长度"), partitionOffset + 24U, 8U);
            addField(result, QStringLiteral("每扇区字节"), QString::number(result.logicalSectorSize), QStringLiteral("ReFS 逻辑扇区"), partitionOffset + 32U, 4U);
            addField(result, QStringLiteral("每簇扇区"), QString::number(result.blockSize), QStringLiteral("ReFS 簇几何字段"), partitionOffset + 36U, 4U);
            addField(
                result,
                QStringLiteral("版本"),
                QStringLiteral("%1.%2")
                    .arg(static_cast<unsigned char>(firstBytes.at(40)))
                    .arg(static_cast<unsigned char>(firstBytes.at(41))),
                QStringLiteral("ReFS 主/次版本"),
                partitionOffset + 40U,
                2U);
        }
        else
        {
            const std::uint16_t bytesPerSector = le16(firstBytes, 11);
            const std::uint32_t sectorsPerCluster =
                firstBytes.size() > 13
                ? static_cast<unsigned char>(firstBytes.at(13))
                : 0U;
            const std::uint32_t reservedSectors = le16(firstBytes, 14);
            const std::uint32_t fatCount =
                firstBytes.size() > 16
                ? static_cast<unsigned char>(firstBytes.at(16))
                : 0U;
            const std::uint32_t rootEntries = le16(firstBytes, 17);
            const std::uint32_t totalSectors = le16(firstBytes, 19) != 0U
                ? le16(firstBytes, 19)
                : le32(firstBytes, 32);
            const std::uint32_t fatSectors = le16(firstBytes, 22) != 0U
                ? le16(firstBytes, 22)
                : le32(firstBytes, 36);
            if ((bytesPerSector == 512U
                    || bytesPerSector == 1024U
                    || bytesPerSector == 2048U
                    || bytesPerSector == 4096U)
                && sectorsPerCluster != 0U
                && fatCount != 0U
                && totalSectors != 0U
                && fatSectors != 0U)
            {
                const std::uint32_t rootDirectorySectors =
                    ((rootEntries * 32U) + (bytesPerSector - 1U))
                    / bytesPerSector;
                const std::uint32_t dataSectors = totalSectors
                    - (reservedSectors
                        + (fatCount * fatSectors)
                        + rootDirectorySectors);
                const std::uint32_t clusterCount =
                    dataSectors / sectorsPerCluster;
                if (clusterCount < 4085U)
                {
                    result.kind = ForensicFileSystemKind::Fat12;
                }
                else if (clusterCount < 65525U)
                {
                    result.kind = ForensicFileSystemKind::Fat16;
                }
                else
                {
                    result.kind = ForensicFileSystemKind::Fat32;
                }
                result.name = fileSystemName(result.kind);
                result.capabilityText = QStringLiteral("原始 BPB、FAT、目录项与簇链只读解析；支持删除目录项取证");
                result.logicalSectorSize = bytesPerSector;
                result.blockSize = bytesPerSector * sectorsPerCluster;
                result.totalBytes =
                    static_cast<std::uint64_t>(totalSectors) * bytesPerSector;
                result.rootObject = result.kind == ForensicFileSystemKind::Fat32
                    ? le32(firstBytes, 44)
                    : reservedSectors + (fatCount * fatSectors);
                addField(result, QStringLiteral("FAT 类型"), result.name, QStringLiteral("按数据簇数量判定，不依赖易伪造的类型文本"), partitionOffset + 11U, 53U);
                addField(result, QStringLiteral("每扇区字节"), QString::number(bytesPerSector), QStringLiteral("BPB_BytsPerSec"), partitionOffset + 11U, 2U);
                addField(result, QStringLiteral("每簇扇区"), QString::number(sectorsPerCluster), QStringLiteral("BPB_SecPerClus"), partitionOffset + 13U, 1U);
                addField(result, QStringLiteral("FAT 数量"), QString::number(fatCount), QStringLiteral("BPB_NumFATs"), partitionOffset + 16U, 1U);
                addField(result, QStringLiteral("数据簇数量"), QString::number(clusterCount), QStringLiteral("用于 FAT12/16/32 分类"), partitionOffset, 0U);
            }
        }

        if (result.kind == ForensicFileSystemKind::Unknown
            && firstBytes.size() >= 2048)
        {
            const int superOffset = 1024;
            if (le16(firstBytes, superOffset + 56) == 0xEF53U)
            {
                const std::uint32_t compatible = le32(firstBytes, superOffset + 92);
                const std::uint32_t incompatible = le32(firstBytes, superOffset + 96);
                const bool hasJournal = (compatible & 0x00000004U) != 0U;
                const bool hasExtents = (incompatible & 0x00000040U) != 0U;
                const bool has64Bit = (incompatible & 0x00000080U) != 0U;
                result.kind = hasExtents || has64Bit
                    ? ForensicFileSystemKind::Ext4
                    : (hasJournal
                        ? ForensicFileSystemKind::Ext3
                        : ForensicFileSystemKind::Ext2);
                result.name = fileSystemName(result.kind);
                result.capabilityText = QStringLiteral("原始超级块、块组几何与兼容特征只读探测");
                const std::uint32_t logBlockSize = le32(firstBytes, superOffset + 24);
                result.blockSize = 1024U << std::min<std::uint32_t>(logBlockSize, 6U);
                const std::uint64_t lowBlocks = le32(firstBytes, superOffset + 4);
                const std::uint64_t highBlocks = has64Bit
                    ? le32(firstBytes, superOffset + 0x150)
                    : 0U;
                result.totalBytes = (lowBlocks | (highBlocks << 32U))
                    * result.blockSize;
                result.rootObject = 2U;
                result.volumeLabel = boundedLatin1(firstBytes, superOffset + 120, 16);
                addField(result, QStringLiteral("超级块魔数"), QStringLiteral("0xEF53"), QStringLiteral("Ext 系列超级块"), partitionOffset + superOffset + 56U, 2U);
                addField(result, QStringLiteral("块大小"), QString::number(result.blockSize), QStringLiteral("1024 << s_log_block_size"), partitionOffset + superOffset + 24U, 4U);
                addField(result, QStringLiteral("每块组块数"), QString::number(le32(firstBytes, superOffset + 32)), QStringLiteral("s_blocks_per_group"), partitionOffset + superOffset + 32U, 4U);
                addField(result, QStringLiteral("每块组 inode"), QString::number(le32(firstBytes, superOffset + 40)), QStringLiteral("s_inodes_per_group"), partitionOffset + superOffset + 40U, 4U);
                addField(result, QStringLiteral("卷标"), result.volumeLabel, QStringLiteral("s_volume_name"), partitionOffset + superOffset + 120U, 16U);
                addField(result, QStringLiteral("文件系统 UUID"), guidText(firstBytes, superOffset + 104), QStringLiteral("s_uuid"), partitionOffset + superOffset + 104U, 16U);
                addField(result, QStringLiteral("不兼容特性"), QStringLiteral("0x%1").arg(incompatible, 8, 16, QChar('0')).toUpper(), QStringLiteral("extent/64bit 等能力位"), partitionOffset + superOffset + 96U, 4U);
            }
            else
            {
                const std::uint16_t hfsSignature = be16(firstBytes, superOffset);
                if (hfsSignature == 0x4244U)
                {
                    result.kind = ForensicFileSystemKind::Hfs;
                    result.name = fileSystemName(result.kind);
                    result.capabilityText = QStringLiteral("原始 MDB、分配块与 Catalog 文件定位参数只读探测");
                    result.blockSize = be32(firstBytes, superOffset + 20);
                    result.totalBytes = static_cast<std::uint64_t>(
                        be16(firstBytes, superOffset + 18))
                        * result.blockSize;
                    addField(result, QStringLiteral("MDB 签名"), QStringLiteral("0x4244"), QStringLiteral("HFS 主目录块"), partitionOffset + superOffset, 2U);
                    addField(result, QStringLiteral("分配块数量"), QString::number(be16(firstBytes, superOffset + 18)), QStringLiteral("drNmAlBlks"), partitionOffset + superOffset + 18U, 2U);
                    addField(result, QStringLiteral("分配块大小"), QString::number(result.blockSize), QStringLiteral("drAlBlkSiz"), partitionOffset + superOffset + 20U, 4U);
                    addField(result, QStringLiteral("目录文件大小"), QString::number(be32(firstBytes, superOffset + 146)), QStringLiteral("catalog B-Tree 文件大小"), partitionOffset + superOffset + 146U, 4U);
                }
                else if (hfsSignature == 0x482BU || hfsSignature == 0x4858U)
                {
                    result.kind = ForensicFileSystemKind::HfsPlus;
                    result.name = fileSystemName(result.kind);
                    result.capabilityText = QStringLiteral("原始卷头、分配块与 Catalog 文件定位参数只读探测");
                    result.blockSize = be32(firstBytes, superOffset + 40);
                    result.totalBytes = be64(firstBytes, superOffset + 44)
                        * result.blockSize;
                    result.rootObject = 2U;
                    addField(result, QStringLiteral("卷头签名"), hfsSignature == 0x4858U ? QStringLiteral("HFSX") : QStringLiteral("HFS+"), QStringLiteral("HFS Plus 卷头"), partitionOffset + superOffset, 2U);
                    addField(result, QStringLiteral("版本"), QString::number(be16(firstBytes, superOffset + 2)), QStringLiteral("HFS Plus 版本"), partitionOffset + superOffset + 2U, 2U);
                    addField(result, QStringLiteral("块大小"), QString::number(result.blockSize), QStringLiteral("allocation block size"), partitionOffset + superOffset + 40U, 4U);
                    addField(result, QStringLiteral("总块数"), QString::number(be32(firstBytes, superOffset + 44)), QStringLiteral("totalBlocks"), partitionOffset + superOffset + 44U, 4U);
                    addField(result, QStringLiteral("Catalog 文件逻辑大小"), QString::number(be64(firstBytes, superOffset + 272)), QStringLiteral("catalogFile.logicalSize"), partitionOffset + superOffset + 272U, 8U);
                }
            }
        }

        if (result.kind == ForensicFileSystemKind::Unknown
            && firstBytes.size() >= 4096
            && bytesEqual(firstBytes, 32, "NXSB", 4))
        {
            result.kind = ForensicFileSystemKind::Apfs;
            result.name = fileSystemName(result.kind);
            result.capabilityText = QStringLiteral("原始容器超级块、对象映射 OID 与容器几何只读探测");
            result.blockSize = le32(firstBytes, 36);
            result.totalBytes = le64(firstBytes, 40) * result.blockSize;
            result.rootObject = le64(firstBytes, 160);
            addField(result, QStringLiteral("容器魔数"), QStringLiteral("NXSB"), QStringLiteral("APFS container superblock"), partitionOffset + 32U, 4U);
            addField(result, QStringLiteral("块大小"), QString::number(result.blockSize), QStringLiteral("nx_block_size"), partitionOffset + 36U, 4U);
            addField(result, QStringLiteral("块数量"), QString::number(le64(firstBytes, 40)), QStringLiteral("nx_block_count"), partitionOffset + 40U, 8U);
            addField(result, QStringLiteral("容器 UUID"), guidText(firstBytes, 72), QStringLiteral("nx_uuid"), partitionOffset + 72U, 16U);
            addField(result, QStringLiteral("对象映射 OID"), QString::number(result.rootObject), QStringLiteral("nx_omap_oid"), partitionOffset + 160U, 8U);
        }

        if (result.kind == ForensicFileSystemKind::Unknown
            && partitionLength >= 69632U)
        {
            QByteArray btrfsBytes;
            QString btrfsError;
            const std::uint64_t btrfsOffset = partitionOffset + 65536U;
            if (DiskEditorBackend::readBytesWithBackend(
                diskIndex,
                backend,
                btrfsOffset,
                std::max<std::uint32_t>(4096U, sectorSize),
                btrfsBytes,
                btrfsError)
                && bytesEqual(btrfsBytes, 64, "_BHRfS_M", 8))
            {
                result.kind = ForensicFileSystemKind::Btrfs;
                result.name = fileSystemName(result.kind);
                result.capabilityText = QStringLiteral("原始超级块、根对象、节点几何与校验元数据只读探测");
                result.totalBytes = le64(btrfsBytes, 112);
                result.rootObject = le64(btrfsBytes, 80);
                result.logicalSectorSize = le32(btrfsBytes, 144);
                result.blockSize = le32(btrfsBytes, 148);
                result.volumeLabel = boundedLatin1(btrfsBytes, 299, 256);
                addField(result, QStringLiteral("超级块魔数"), QStringLiteral("_BHRfS_M"), QStringLiteral("BtrFS 第一超级块镜像"), btrfsOffset + 64U, 8U);
                addField(result, QStringLiteral("文件系统 UUID"), guidText(btrfsBytes, 32), QStringLiteral("fsid"), btrfsOffset + 32U, 16U);
                addField(result, QStringLiteral("总字节数"), QString::number(result.totalBytes), QStringLiteral("total_bytes"), btrfsOffset + 112U, 8U);
                addField(result, QStringLiteral("扇区大小"), QString::number(result.logicalSectorSize), QStringLiteral("sectorsize"), btrfsOffset + 144U, 4U);
                addField(result, QStringLiteral("节点大小"), QString::number(result.blockSize), QStringLiteral("nodesize"), btrfsOffset + 148U, 4U);
                addField(result, QStringLiteral("卷标"), result.volumeLabel, QStringLiteral("label"), btrfsOffset + 299U, 256U);
            }
        }

        if (result.kind == ForensicFileSystemKind::Unknown)
        {
            result.errorText = QStringLiteral("未识别到受支持的文件系统超级块；可继续在 HEX 视图检查该分区。");
            return result;
        }

        result.success = true;
        if (result.totalBytes == 0U)
        {
            result.totalBytes = partitionLength;
        }
        return result;
    }

    FileExtentResult DiskFileSystemForensics::resolveFileExtents(
        const QString& filePath)
    {
        FileExtentResult result;
        result.filePath = QFileInfo(filePath).absoluteFilePath();
        if (result.filePath.isEmpty())
        {
            result.errorText = QStringLiteral("文件路径为空。");
            return result;
        }

        std::array<wchar_t, MAX_PATH> volumeRoot{};
        if (::GetVolumePathNameW(
            reinterpret_cast<LPCWSTR>(result.filePath.utf16()),
            volumeRoot.data(),
            static_cast<DWORD>(volumeRoot.size())) == FALSE)
        {
            result.errorText = win32ErrorText(QStringLiteral("解析文件所在卷"));
            return result;
        }
        result.volumePath = QString::fromWCharArray(volumeRoot.data());

        DWORD sectorsPerCluster = 0;
        DWORD bytesPerSector = 0;
        DWORD freeClusters = 0;
        DWORD totalClusters = 0;
        if (::GetDiskFreeSpaceW(
            volumeRoot.data(),
            &sectorsPerCluster,
            &bytesPerSector,
            &freeClusters,
            &totalClusters) == FALSE)
        {
            result.errorText = win32ErrorText(QStringLiteral("查询卷簇大小"));
            return result;
        }
        result.bytesPerCluster = sectorsPerCluster * bytesPerSector;

        std::array<wchar_t, MAX_PATH> fileSystemNameBuffer{};
        if (::GetVolumeInformationW(
            volumeRoot.data(),
            nullptr,
            0,
            nullptr,
            nullptr,
            nullptr,
            fileSystemNameBuffer.data(),
            static_cast<DWORD>(fileSystemNameBuffer.size())) != FALSE)
        {
            result.fileSystemName =
                QString::fromWCharArray(fileSystemNameBuffer.data());
        }

        HANDLE fileHandle = ::CreateFileW(
            reinterpret_cast<LPCWSTR>(result.filePath.utf16()),
            FILE_READ_ATTRIBUTES,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            nullptr,
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS,
            nullptr);
        if (fileHandle == INVALID_HANDLE_VALUE)
        {
            result.errorText = win32ErrorText(QStringLiteral("打开目标文件"));
            return result;
        }

        LARGE_INTEGER fileSize{};
        if (::GetFileSizeEx(fileHandle, &fileSize) != FALSE
            && fileSize.QuadPart >= 0)
        {
            result.fileSizeBytes =
                static_cast<std::uint64_t>(fileSize.QuadPart);
        }

        STARTING_VCN_INPUT_BUFFER input{};
        constexpr DWORD retrievalBytes = 1024U * 1024U;
        std::vector<std::byte> retrievalBuffer(retrievalBytes);
        DWORD returnedBytes = 0;
        BOOL retrievalOk = ::DeviceIoControl(
            fileHandle,
            FSCTL_GET_RETRIEVAL_POINTERS,
            &input,
            sizeof(input),
            retrievalBuffer.data(),
            static_cast<DWORD>(retrievalBuffer.size()),
            &returnedBytes,
            nullptr);
        const DWORD retrievalError = retrievalOk != FALSE
            ? ERROR_SUCCESS
            : ::GetLastError();
        ::CloseHandle(fileHandle);
        if (retrievalOk == FALSE && retrievalError != ERROR_MORE_DATA)
        {
            ::SetLastError(retrievalError);
            result.errorText = win32ErrorText(QStringLiteral("查询文件 VCN/LCN 区间"));
            return result;
        }
        if (returnedBytes < offsetof(RETRIEVAL_POINTERS_BUFFER, Extents))
        {
            result.errorText = QStringLiteral("文件区间响应头不完整。");
            return result;
        }

        std::array<wchar_t, MAX_PATH> volumeName{};
        if (::GetVolumeNameForVolumeMountPointW(
            volumeRoot.data(),
            volumeName.data(),
            static_cast<DWORD>(volumeName.size())) == FALSE)
        {
            result.errorText = win32ErrorText(QStringLiteral("解析卷 GUID 路径"));
            return result;
        }
        QString volumeDevice = QString::fromWCharArray(volumeName.data());
        while (volumeDevice.endsWith(QLatin1Char('\\')))
        {
            volumeDevice.chop(1);
        }
        volumeDevice.replace(0, 4, QStringLiteral("\\\\.\\"));
        HANDLE volumeHandle = ::CreateFileW(
            reinterpret_cast<LPCWSTR>(volumeDevice.utf16()),
            0,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            nullptr,
            OPEN_EXISTING,
            0,
            nullptr);

        std::vector<std::byte> extentBuffer(
            sizeof(VOLUME_DISK_EXTENTS) + (sizeof(DISK_EXTENT) * 64U));
        DWORD volumeExtentBytes = 0;
        bool singleVolumeExtent = false;
        DISK_EXTENT singleExtent{};
        if (volumeHandle != INVALID_HANDLE_VALUE
            && ::DeviceIoControl(
                volumeHandle,
                IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS,
                nullptr,
                0,
                extentBuffer.data(),
                static_cast<DWORD>(extentBuffer.size()),
                &volumeExtentBytes,
                nullptr) != FALSE
            && volumeExtentBytes >= sizeof(VOLUME_DISK_EXTENTS))
        {
            const auto* volumeExtents =
                reinterpret_cast<const VOLUME_DISK_EXTENTS*>(extentBuffer.data());
            if (volumeExtents->NumberOfDiskExtents == 1U)
            {
                singleVolumeExtent = true;
                singleExtent = volumeExtents->Extents[0];
            }
        }
        if (volumeHandle != INVALID_HANDLE_VALUE)
        {
            ::CloseHandle(volumeHandle);
        }

        const auto* retrieval =
            reinterpret_cast<const RETRIEVAL_POINTERS_BUFFER*>(retrievalBuffer.data());
        const std::size_t availableExtents =
            (returnedBytes - offsetof(RETRIEVAL_POINTERS_BUFFER, Extents))
            / sizeof(retrieval->Extents[0]);
        const std::size_t extentCount = std::min<std::size_t>(
            retrieval->ExtentCount,
            availableExtents);
        std::int64_t previousVcn = retrieval->StartingVcn.QuadPart;
        for (std::size_t index = 0; index < extentCount; ++index)
        {
            const std::int64_t nextVcn =
                retrieval->Extents[index].NextVcn.QuadPart;
            if (nextVcn <= previousVcn)
            {
                break;
            }
            PhysicalFileExtent extent;
            extent.startingVcn = previousVcn;
            extent.startingLcn =
                retrieval->Extents[index].Lcn.QuadPart;
            extent.sparse = extent.startingLcn < 0;
            extent.fileOffset = static_cast<std::uint64_t>(previousVcn)
                * result.bytesPerCluster;
            extent.lengthBytes = static_cast<std::uint64_t>(
                nextVcn - previousVcn)
                * result.bytesPerCluster;
            if (!extent.sparse)
            {
                extent.volumeOffset =
                    static_cast<std::uint64_t>(extent.startingLcn)
                    * result.bytesPerCluster;
                if (singleVolumeExtent)
                {
                    extent.diskNumber =
                        static_cast<int>(singleExtent.DiskNumber);
                    extent.physicalOffset =
                        static_cast<std::uint64_t>(
                            singleExtent.StartingOffset.QuadPart)
                        + extent.volumeOffset;
                    extent.physicalMappingExact = true;
                }
            }
            result.extents.push_back(extent);
            previousVcn = nextVcn;
        }

        result.success = !result.extents.empty()
            || result.fileSizeBytes == 0U;
        if (!result.success)
        {
            result.errorText = QStringLiteral("文件没有返回可解析的物理区间。");
        }
        return result;
    }

    ReverseClusterResult DiskFileSystemForensics::reverseLookupCluster(
        const QString& volumePath,
        const std::uint64_t cluster,
        const std::uint32_t clusterCount)
    {
        ReverseClusterResult result;
        result.volumePath = normalizeVolumeDevicePath(volumePath);
        if (result.volumePath.isEmpty() || clusterCount == 0U)
        {
            result.errorText = QStringLiteral("卷路径或簇数量无效。");
            return result;
        }

        HANDLE volumeHandle = ::CreateFileW(
            reinterpret_cast<LPCWSTR>(result.volumePath.utf16()),
            FILE_READ_ATTRIBUTES,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            nullptr,
            OPEN_EXISTING,
            0,
            nullptr);
        if (volumeHandle == INVALID_HANDLE_VALUE)
        {
            result.errorText = win32ErrorText(QStringLiteral("打开卷进行簇反查"));
            return result;
        }

        LOOKUP_STREAM_FROM_CLUSTER_INPUT input{};
        input.Flags = 0U;
        input.NumberOfClusters = clusterCount;
        input.Cluster[0].QuadPart = static_cast<LONGLONG>(cluster);
        constexpr DWORD outputBytes = 4U * 1024U * 1024U;
        std::vector<std::byte> output(outputBytes);
        DWORD returnedBytes = 0;
        const BOOL ioctlOk = ::DeviceIoControl(
            volumeHandle,
            FSCTL_LOOKUP_STREAM_FROM_CLUSTER,
            &input,
            sizeof(input),
            output.data(),
            static_cast<DWORD>(output.size()),
            &returnedBytes,
            nullptr);
        const DWORD ioctlError = ioctlOk != FALSE
            ? ERROR_SUCCESS
            : ::GetLastError();
        ::CloseHandle(volumeHandle);
        if (ioctlOk == FALSE
            && ioctlError != ERROR_MORE_DATA)
        {
            ::SetLastError(ioctlError);
            result.errorText = win32ErrorText(QStringLiteral("按簇反查文件流"));
            return result;
        }
        if (returnedBytes < sizeof(LOOKUP_STREAM_FROM_CLUSTER_OUTPUT))
        {
            result.errorText = QStringLiteral("簇反查响应头不完整。");
            return result;
        }

        const auto* header =
            reinterpret_cast<const LOOKUP_STREAM_FROM_CLUSTER_OUTPUT*>(output.data());
        DWORD offset = header->Offset;
        std::uint32_t parsed = 0U;
        while (offset != 0U
            && offset < returnedBytes
            && parsed < header->NumberOfMatches)
        {
            if (offset > returnedBytes
                - offsetof(LOOKUP_STREAM_FROM_CLUSTER_ENTRY, FileName))
            {
                break;
            }
            const auto* entry =
                reinterpret_cast<const LOOKUP_STREAM_FROM_CLUSTER_ENTRY*>(
                    reinterpret_cast<const std::byte*>(output.data()) + offset);
            const std::size_t remaining = returnedBytes - offset;
            const std::size_t maxNameChars =
                (remaining - offsetof(LOOKUP_STREAM_FROM_CLUSTER_ENTRY, FileName))
                / sizeof(wchar_t);
            std::size_t nameChars = 0U;
            while (nameChars < maxNameChars
                && entry->FileName[nameChars] != L'\0')
            {
                ++nameChars;
            }

            ReverseClusterEntry parsedEntry;
            parsedEntry.cluster =
                static_cast<std::uint64_t>(entry->Cluster.QuadPart);
            parsedEntry.clusterCount = 1U;
            parsedEntry.streamPath =
                QString::fromWCharArray(entry->FileName, static_cast<int>(nameChars));
            result.entries.push_back(std::move(parsedEntry));
            ++parsed;
            if (entry->OffsetToNext == 0U
                || entry->OffsetToNext > returnedBytes - offset)
            {
                break;
            }
            offset += entry->OffsetToNext;
        }

        result.success = true;
        return result;
    }
}
