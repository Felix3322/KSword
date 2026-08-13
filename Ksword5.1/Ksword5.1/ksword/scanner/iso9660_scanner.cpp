#include "scanner_internal.h"

// ============================================================
// ksword/scanner/iso9660_scanner.cpp
// 作用：
// - 从稳定内存快照解析 ISO9660/Joliet 卷和目录；
// - 不调用系统挂载、Shell 或加载器，不把容器成员写入磁盘；
// - 把成员的原始范围交给攻击路径检测器做只读关联。
// ============================================================

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <utility>
#include <vector>

namespace ks::scanner::detail
{
    namespace
    {
        constexpr std::uint64_t kDescriptorSectorBytes = 2048;
        constexpr std::uint64_t kFirstDescriptorSector = 16;
        constexpr std::size_t kMaximumDescriptors = 64;
        constexpr std::size_t kMaximumDirectoryDepth = 32;

        // VolumeDescriptor 作用：保存最终选中的主卷或 Joliet 补充卷元数据。
        struct VolumeDescriptor
        {
            bool valid = false;
            bool joliet = false;
            int jolietLevel = 0;
            std::uint64_t offset = 0;
            std::uint16_t logicalBlockSize = 0;
            std::uint32_t rootExtent = 0;
            std::uint32_t rootSize = 0;
            std::string volumeId;
        };

        // DirectoryTask 作用：以显式队列替代递归，统一限制目录深度和循环。
        struct DirectoryTask
        {
            std::string path;
            std::uint64_t offset = 0;
            std::uint64_t size = 0;
            std::size_t depth = 0;
        };

        bool Contains(
            const std::span<const std::uint8_t> bytes,
            const std::uint64_t offset,
            const std::uint64_t length)
        {
            return offset <= bytes.size() && length <= bytes.size() - offset;
        }

        bool ReadU16Le(
            const std::span<const std::uint8_t> bytes,
            const std::uint64_t offset,
            std::uint16_t& valueOut)
        {
            if (!Contains(bytes, offset, 2))
            {
                return false;
            }
            valueOut = static_cast<std::uint16_t>(bytes[offset]) |
                static_cast<std::uint16_t>(bytes[offset + 1U] << 8U);
            return true;
        }

        bool ReadU16Be(
            const std::span<const std::uint8_t> bytes,
            const std::uint64_t offset,
            std::uint16_t& valueOut)
        {
            if (!Contains(bytes, offset, 2))
            {
                return false;
            }
            valueOut = static_cast<std::uint16_t>(bytes[offset] << 8U) |
                static_cast<std::uint16_t>(bytes[offset + 1U]);
            return true;
        }

        bool ReadU32Le(
            const std::span<const std::uint8_t> bytes,
            const std::uint64_t offset,
            std::uint32_t& valueOut)
        {
            if (!Contains(bytes, offset, 4))
            {
                return false;
            }
            valueOut = static_cast<std::uint32_t>(bytes[offset]) |
                (static_cast<std::uint32_t>(bytes[offset + 1U]) << 8U) |
                (static_cast<std::uint32_t>(bytes[offset + 2U]) << 16U) |
                (static_cast<std::uint32_t>(bytes[offset + 3U]) << 24U);
            return true;
        }

        bool ReadU32Be(
            const std::span<const std::uint8_t> bytes,
            const std::uint64_t offset,
            std::uint32_t& valueOut)
        {
            if (!Contains(bytes, offset, 4))
            {
                return false;
            }
            valueOut = (static_cast<std::uint32_t>(bytes[offset]) << 24U) |
                (static_cast<std::uint32_t>(bytes[offset + 1U]) << 16U) |
                (static_cast<std::uint32_t>(bytes[offset + 2U]) << 8U) |
                static_cast<std::uint32_t>(bytes[offset + 3U]);
            return true;
        }

        // ISO 的关键数值同时保存小端和大端副本；不一致时直接拒绝该记录。
        bool ReadBothEndian16(
            const std::span<const std::uint8_t> bytes,
            const std::uint64_t offset,
            std::uint16_t& valueOut)
        {
            std::uint16_t little = 0;
            std::uint16_t big = 0;
            if (!ReadU16Le(bytes, offset, little) ||
                !ReadU16Be(bytes, offset + 2U, big) ||
                little != big)
            {
                return false;
            }
            valueOut = little;
            return true;
        }

        bool ReadBothEndian32(
            const std::span<const std::uint8_t> bytes,
            const std::uint64_t offset,
            std::uint32_t& valueOut)
        {
            std::uint32_t little = 0;
            std::uint32_t big = 0;
            if (!ReadU32Le(bytes, offset, little) ||
                !ReadU32Be(bytes, offset + 4U, big) ||
                little != big)
            {
                return false;
            }
            valueOut = little;
            return true;
        }

        void AppendUtf8(std::string& output, const std::uint32_t codePoint)
        {
            if (codePoint <= 0x7FU)
            {
                output.push_back(static_cast<char>(codePoint));
            }
            else if (codePoint <= 0x7FFU)
            {
                output.push_back(static_cast<char>(0xC0U | (codePoint >> 6U)));
                output.push_back(static_cast<char>(0x80U | (codePoint & 0x3FU)));
            }
            else
            {
                output.push_back(static_cast<char>(0xE0U | (codePoint >> 12U)));
                output.push_back(static_cast<char>(0x80U | ((codePoint >> 6U) & 0x3FU)));
                output.push_back(static_cast<char>(0x80U | (codePoint & 0x3FU)));
            }
        }

        // DecodeUcs2Be 只接受 BMP 非代理项；异常码点用问号保留目录结构。
        std::string DecodeUcs2Be(const std::span<const std::uint8_t> field)
        {
            std::string output;
            for (std::size_t offset = 0; offset + 1U < field.size(); offset += 2U)
            {
                const std::uint16_t codePoint =
                    static_cast<std::uint16_t>(field[offset] << 8U) |
                    static_cast<std::uint16_t>(field[offset + 1U]);
                if (codePoint == 0)
                {
                    break;
                }
                AppendUtf8(
                    output,
                    codePoint >= 0xD800U && codePoint <= 0xDFFFU
                        ? static_cast<std::uint32_t>('?')
                        : codePoint);
            }
            return output;
        }

        std::string DecodeAscii(const std::span<const std::uint8_t> field)
        {
            std::string output;
            output.reserve(field.size());
            for (const std::uint8_t byte : field)
            {
                if (byte == 0)
                {
                    break;
                }
                output.push_back(
                    byte >= 0x20U && byte <= 0x7EU
                        ? static_cast<char>(byte)
                        : '?');
            }
            return output;
        }

        std::string TrimVolumeText(std::string value)
        {
            while (!value.empty() && value.back() == ' ')
            {
                value.pop_back();
            }
            return value;
        }

        // NormalizeIdentifier 去除 ISO 版本后缀并替换路径分隔符，防止伪造层级。
        std::string NormalizeIdentifier(std::string value)
        {
            const std::size_t versionOffset = value.find(';');
            if (versionOffset != std::string::npos)
            {
                value.resize(versionOffset);
            }
            if (!value.empty() && value.back() == '.')
            {
                value.pop_back();
            }
            for (char& character : value)
            {
                const unsigned char byte = static_cast<unsigned char>(character);
                if (character == '/' || character == '\\' || byte < 0x20U)
                {
                    character = '_';
                }
            }
            return value.empty() ? std::string("<unnamed>") : value;
        }

        bool HasDescriptorSignature(
            const std::span<const std::uint8_t> bytes,
            const std::uint64_t offset)
        {
            static constexpr std::array<std::uint8_t, 5> signature{
                'C', 'D', '0', '0', '1'
            };
            return Contains(bytes, offset, kDescriptorSectorBytes) &&
                std::equal(
                    signature.begin(),
                    signature.end(),
                    bytes.begin() + static_cast<std::ptrdiff_t>(offset + 1U)) &&
                bytes[offset + 6U] == 1U;
        }

        int JolietLevel(const std::span<const std::uint8_t> bytes, const std::uint64_t offset)
        {
            if (bytes[offset + 88U] != '%' || bytes[offset + 89U] != '/')
            {
                return 0;
            }
            switch (bytes[offset + 90U])
            {
            case 0x40U: return 1;
            case 0x43U: return 2;
            case 0x45U: return 3;
            default: return 0;
            }
        }

        bool ParseDescriptor(
            const std::span<const std::uint8_t> bytes,
            const std::uint64_t offset,
            const bool joliet,
            const int jolietLevel,
            VolumeDescriptor& descriptorOut)
        {
            std::uint16_t blockSize = 0;
            std::uint32_t rootExtent = 0;
            std::uint32_t rootSize = 0;
            if (bytes[offset + 156U] < 34U ||
                !ReadBothEndian16(bytes, offset + 128U, blockSize) ||
                !ReadBothEndian32(bytes, offset + 156U + 2U, rootExtent) ||
                !ReadBothEndian32(bytes, offset + 156U + 10U, rootSize) ||
                blockSize < 512U || blockSize > 32768U ||
                (blockSize & (blockSize - 1U)) != 0)
            {
                return false;
            }

            std::uint64_t rootOffset = 0;
            if (!CheckedMultiply(rootExtent, blockSize, rootOffset) ||
                !Contains(bytes, rootOffset, rootSize))
            {
                return false;
            }
            const auto volumeField = bytes.subspan(
                static_cast<std::size_t>(offset + 40U),
                32U);
            descriptorOut.valid = true;
            descriptorOut.joliet = joliet;
            descriptorOut.jolietLevel = jolietLevel;
            descriptorOut.offset = offset;
            descriptorOut.logicalBlockSize = blockSize;
            descriptorOut.rootExtent = rootExtent;
            descriptorOut.rootSize = rootSize;
            descriptorOut.volumeId = TrimVolumeText(
                joliet ? DecodeUcs2Be(volumeField) : DecodeAscii(volumeField));
            return true;
        }

        bool AlreadyVisited(
            const std::vector<std::pair<std::uint64_t, std::uint64_t>>& visited,
            const std::uint64_t offset,
            const std::uint64_t size)
        {
            return std::find(visited.begin(), visited.end(), std::make_pair(offset, size)) !=
                visited.end();
        }

        std::string JoinPath(const std::string& parent, const std::string& name)
        {
            return parent == "/" ? parent + name : parent + "/" + name;
        }
    }

    bool ParseIso9660(
        const std::span<const std::uint8_t> bytes,
        const ScanOptions& options,
        BinaryScanResult& result)
    {
        result.recognized = true;
        result.format = BinaryFormat::Iso9660;
        result.byteOrder = ByteOrder::BothEndian;

        // 先记录有效主卷，再优先选择级别最高的有效 Joliet 补充卷。
        VolumeDescriptor primary{};
        VolumeDescriptor selected{};
        for (std::size_t index = 0; index < kMaximumDescriptors; ++index)
        {
            const std::uint64_t sector = kFirstDescriptorSector + index;
            std::uint64_t descriptorOffset = 0;
            if (!CheckedMultiply(sector, kDescriptorSectorBytes, descriptorOffset) ||
                !Contains(bytes, descriptorOffset, kDescriptorSectorBytes))
            {
                break;
            }
            if (!HasDescriptorSignature(bytes, descriptorOffset))
            {
                continue;
            }

            const std::uint8_t type = bytes[descriptorOffset];
            if (type == 1U)
            {
                VolumeDescriptor candidate{};
                if (ParseDescriptor(bytes, descriptorOffset, false, 0, candidate))
                {
                    primary = candidate;
                }
            }
            else if (type == 2U)
            {
                const int level = JolietLevel(bytes, descriptorOffset);
                VolumeDescriptor candidate{};
                if (level != 0 &&
                    ParseDescriptor(bytes, descriptorOffset, true, level, candidate) &&
                    (!selected.valid || level > selected.jolietLevel))
                {
                    selected = candidate;
                }
            }
            else if (type == 255U)
            {
                break;
            }
        }

        if (!selected.valid)
        {
            selected = primary;
        }
        if (!selected.valid)
        {
            AddDiagnostic(
                result,
                DiagnosticSeverity::Error,
                "iso.volume_descriptor_invalid",
                "ISO9660 volume descriptors or the root directory are invalid.");
            return false;
        }

        AddField(result.summary, "Format", selected.joliet ? "ISO9660 + Joliet" : "ISO9660");
        AddField(result.summary, "Byte Order", "Both-endian fields");
        AddField(result.summary, "Volume ID", selected.volumeId);
        AddField(result.summary, "Filename Encoding", selected.joliet ? "Joliet UCS-2BE" : "ISO 646");
        AddField(result.summary, "Logical Block Size", Decimal(selected.logicalBlockSize));
        AddField(result.headers, "Volume Descriptor Offset", Hex(selected.offset));
        AddField(result.headers, "Root Directory Extent", Decimal(selected.rootExtent));
        AddField(result.headers, "Root Directory Size", Decimal(selected.rootSize));

        BinaryTable entries{
            "container_entries",
            "Container Entries",
            { "Path", "Type", "Offset", "Size", "Extent" },
            {},
            false
        };
        std::vector<ContainerMember> members;
        std::vector<DirectoryTask> pending;
        std::vector<std::pair<std::uint64_t, std::uint64_t>> visited;

        std::uint64_t rootOffset = 0;
        CheckedMultiply(selected.rootExtent, selected.logicalBlockSize, rootOffset);
        pending.push_back(DirectoryTask{ "/", rootOffset, selected.rootSize, 0 });
        visited.emplace_back(rootOffset, selected.rootSize);
        members.push_back(ContainerMember{ "/", rootOffset, selected.rootSize, true });
        AppendRow(entries, { "/", "Directory", Hex(rootOffset), Decimal(selected.rootSize), Decimal(selected.rootExtent) }, options);

        bool limitReached = false;
        while (!pending.empty() && !limitReached)
        {
            DirectoryTask task = std::move(pending.back());
            pending.pop_back();
            const std::uint64_t directoryEnd = task.offset + task.size;
            std::uint64_t cursor = task.offset;

            while (cursor < directoryEnd)
            {
                if (!Contains(bytes, cursor, 1))
                {
                    break;
                }
                const std::uint8_t recordLength = bytes[cursor];
                if (recordLength == 0)
                {
                    const std::uint64_t relative = cursor - task.offset;
                    const std::uint64_t nextBlock =
                        ((relative / selected.logicalBlockSize) + 1U) *
                        selected.logicalBlockSize;
                    cursor = task.offset + nextBlock;
                    continue;
                }
                if (recordLength < 34U ||
                    !Contains(bytes, cursor, recordLength) ||
                    cursor + recordLength > directoryEnd)
                {
                    AddDiagnosticAt(
                        result,
                        DiagnosticSeverity::Warning,
                        "iso.directory_record_invalid",
                        "An ISO9660 directory record is truncated or malformed.",
                        cursor);
                    break;
                }

                const std::uint8_t identifierLength = bytes[cursor + 32U];
                if (33U + identifierLength > recordLength)
                {
                    AddDiagnosticAt(
                        result,
                        DiagnosticSeverity::Warning,
                        "iso.identifier_invalid",
                        "An ISO9660 file identifier exceeds its directory record.",
                        cursor);
                    cursor += recordLength;
                    continue;
                }
                const auto identifierBytes = bytes.subspan(
                    static_cast<std::size_t>(cursor + 33U),
                    identifierLength);
                const bool specialEntry = identifierLength == 1U &&
                    (identifierBytes[0] == 0U || identifierBytes[0] == 1U);
                if (specialEntry)
                {
                    cursor += recordLength;
                    continue;
                }

                std::uint32_t extent = 0;
                std::uint32_t dataSize = 0;
                const std::uint8_t extendedAttributeBlocks = bytes[cursor + 1U];
                if (!ReadBothEndian32(bytes, cursor + 2U, extent) ||
                    !ReadBothEndian32(bytes, cursor + 10U, dataSize))
                {
                    AddDiagnosticAt(
                        result,
                        DiagnosticSeverity::Warning,
                        "iso.extent_mismatch",
                        "An ISO9660 extent has inconsistent little-endian and big-endian values.",
                        cursor);
                    cursor += recordLength;
                    continue;
                }

                std::uint64_t dataBlock = 0;
                std::uint64_t dataOffset = 0;
                if (!CheckedAdd(extent, extendedAttributeBlocks, dataBlock) ||
                    !CheckedMultiply(dataBlock, selected.logicalBlockSize, dataOffset) ||
                    !Contains(bytes, dataOffset, dataSize))
                {
                    AddDiagnosticAt(
                        result,
                        DiagnosticSeverity::Warning,
                        "iso.extent_out_of_bounds",
                        "An ISO9660 member extent is outside the image snapshot.",
                        cursor);
                    cursor += recordLength;
                    continue;
                }

                const std::string decodedName = selected.joliet
                    ? DecodeUcs2Be(identifierBytes)
                    : DecodeAscii(identifierBytes);
                const std::string memberPath = JoinPath(
                    task.path,
                    NormalizeIdentifier(decodedName));
                const std::uint8_t flags = bytes[cursor + 25U];
                const bool directory = (flags & 0x02U) != 0;
                const bool multiExtent = (flags & 0x80U) != 0;
                if (members.size() >= options.maxContainerEntries)
                {
                    entries.truncated = true;
                    limitReached = true;
                    break;
                }
                members.push_back(ContainerMember{
                    memberPath,
                    dataOffset,
                    dataSize,
                    directory
                });
                AppendRow(
                    entries,
                    {
                        memberPath,
                        multiExtent ? "File (multi-extent)" : (directory ? "Directory" : "File"),
                        Hex(dataOffset),
                        Decimal(dataSize),
                        Decimal(extent)
                    },
                    options);

                if (directory && !multiExtent && task.depth < kMaximumDirectoryDepth &&
                    !AlreadyVisited(visited, dataOffset, dataSize))
                {
                    visited.emplace_back(dataOffset, dataSize);
                    pending.push_back(DirectoryTask{
                        memberPath,
                        dataOffset,
                        dataSize,
                        task.depth + 1U
                    });
                }
                cursor += recordLength;
            }
        }

        if (limitReached)
        {
            AddDiagnostic(
                result,
                DiagnosticSeverity::Warning,
                "iso.entry_limit_reached",
                "ISO9660 traversal stopped at ScanOptions.maxContainerEntries.");
        }
        AddField(result.summary, "Container Entries", Decimal(members.size()));
        result.tables.push_back(std::move(entries));
        DetectAttackPathInContainer(bytes, members, options, result);
        AddDiagnostic(
            result,
            DiagnosticSeverity::Information,
            "iso.read_only_analysis",
            "The image was parsed from a stable byte snapshot without mounting or executing members.");
        result.success = true;
        return true;
    }
}
