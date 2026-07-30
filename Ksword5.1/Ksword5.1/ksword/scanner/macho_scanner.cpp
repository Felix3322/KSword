#include "scanner_internal.h"

// ============================================================
// ksword/scanner/macho_scanner.cpp
// Purpose:
// - Parse 32/64-bit thin Mach-O in little- or big-endian form.
// - Parse 32/64-bit fat headers and enumerate every bounded architecture slice.
// - Expose load commands, segments, sections, dylibs, and nlist symbols.
// ============================================================

#include <algorithm>
#include <array>
#include <cstdint>
#include <span>
#include <string>
#include <utility>
#include <vector>

namespace ks::scanner::detail
{
    namespace
    {
        constexpr std::uint32_t kMagic32 = 0xFEEDFACEU;
        constexpr std::uint32_t kMagic64 = 0xFEEDFACFU;
        constexpr std::uint32_t kFatMagic32 = 0xCAFEBABEU;
        constexpr std::uint32_t kFatMagic64 = 0xCAFEBABFU;

        constexpr std::uint32_t kLoadSegment = 0x1U;
        constexpr std::uint32_t kLoadSymtab = 0x2U;
        constexpr std::uint32_t kLoadDysymtab = 0xBU;
        constexpr std::uint32_t kLoadDylib = 0xCU;
        constexpr std::uint32_t kIdDylib = 0xDU;
        constexpr std::uint32_t kLoadWeakDylib = 0x80000018U;
        constexpr std::uint32_t kLoadSegment64 = 0x19U;
        constexpr std::uint32_t kLoadUuid = 0x1BU;
        constexpr std::uint32_t kLoadCodeSignature = 0x1DU;
        constexpr std::uint32_t kLoadLazyDylib = 0x20U;
        constexpr std::uint32_t kLoadReexportDylib = 0x8000001FU;
        constexpr std::uint32_t kLoadUpwardDylib = 0x80000023U;
        constexpr std::uint32_t kLoadMain = 0x80000028U;

        constexpr std::uint8_t kNStabMask = 0xE0U;
        constexpr std::uint8_t kNExternal = 0x01U;
        constexpr std::uint8_t kNTypeMask = 0x0EU;
        constexpr std::uint8_t kNUndefined = 0x00U;

        struct MachMagic
        {
            bool recognized = false;
            bool universal = false;
            bool is64 = false;
            ByteOrder byteOrder = ByteOrder::Unknown;
        };

        struct SymtabCommand
        {
            bool present = false;
            std::uint64_t commandOffset = 0;
            std::uint32_t symbolOffset = 0;
            std::uint32_t symbolCount = 0;
            std::uint32_t stringOffset = 0;
            std::uint32_t stringSize = 0;
        };

        MachMagic DetectMagic(const std::span<const std::uint8_t> bytes)
        {
            if (bytes.size() < 4)
            {
                return {};
            }
            const std::array<std::uint8_t, 4> value{
                bytes[0], bytes[1], bytes[2], bytes[3]
            };
            if (value == std::array<std::uint8_t, 4>{ 0xCE, 0xFA, 0xED, 0xFE })
            {
                return { true, false, false, ByteOrder::LittleEndian };
            }
            if (value == std::array<std::uint8_t, 4>{ 0xFE, 0xED, 0xFA, 0xCE })
            {
                return { true, false, false, ByteOrder::BigEndian };
            }
            if (value == std::array<std::uint8_t, 4>{ 0xCF, 0xFA, 0xED, 0xFE })
            {
                return { true, false, true, ByteOrder::LittleEndian };
            }
            if (value == std::array<std::uint8_t, 4>{ 0xFE, 0xED, 0xFA, 0xCF })
            {
                return { true, false, true, ByteOrder::BigEndian };
            }
            if (value == std::array<std::uint8_t, 4>{ 0xCA, 0xFE, 0xBA, 0xBE })
            {
                return { true, true, false, ByteOrder::BigEndian };
            }
            if (value == std::array<std::uint8_t, 4>{ 0xBE, 0xBA, 0xFE, 0xCA })
            {
                return { true, true, false, ByteOrder::LittleEndian };
            }
            if (value == std::array<std::uint8_t, 4>{ 0xCA, 0xFE, 0xBA, 0xBF })
            {
                return { true, true, true, ByteOrder::BigEndian };
            }
            if (value == std::array<std::uint8_t, 4>{ 0xBF, 0xBA, 0xFE, 0xCA })
            {
                return { true, true, true, ByteOrder::LittleEndian };
            }
            return {};
        }

        const char* CpuTypeName(const std::uint32_t cpuType)
        {
            switch (cpuType)
            {
            case 7U: return "x86";
            case 0x01000007U: return "x86-64";
            case 12U: return "ARM";
            case 0x0100000CU: return "ARM64";
            case 18U: return "PowerPC";
            case 0x01000012U: return "PowerPC64";
            default: return "Unknown";
            }
        }

        const char* FileTypeName(const std::uint32_t fileType)
        {
            switch (fileType)
            {
            case 1: return "Object";
            case 2: return "Executable";
            case 3: return "Fixed VM library";
            case 4: return "Core";
            case 5: return "Preloaded executable";
            case 6: return "Dynamic library";
            case 7: return "Dynamic linker";
            case 8: return "Bundle";
            case 9: return "Dynamic library stub";
            case 10: return "Debug symbols";
            case 11: return "Kernel extension";
            case 12: return "File set";
            default: return "Unknown";
            }
        }

        const char* LoadCommandName(const std::uint32_t command)
        {
            switch (command)
            {
            case kLoadSegment: return "LC_SEGMENT";
            case kLoadSymtab: return "LC_SYMTAB";
            case kLoadDysymtab: return "LC_DYSYMTAB";
            case kLoadDylib: return "LC_LOAD_DYLIB";
            case kIdDylib: return "LC_ID_DYLIB";
            case 0xEU: return "LC_LOAD_DYLINKER";
            case 0xFU: return "LC_ID_DYLINKER";
            case 0x11U: return "LC_ROUTINES";
            case 0x80000012U: return "LC_SUB_UMBRELLA";
            case 0x80000015U: return "LC_LOAD_WEAK_DYLIB_OLD";
            case kLoadWeakDylib: return "LC_LOAD_WEAK_DYLIB";
            case kLoadSegment64: return "LC_SEGMENT_64";
            case kLoadUuid: return "LC_UUID";
            case 0x1CU: return "LC_RPATH";
            case kLoadCodeSignature: return "LC_CODE_SIGNATURE";
            case 0x1EU: return "LC_SEGMENT_SPLIT_INFO";
            case kLoadReexportDylib: return "LC_REEXPORT_DYLIB";
            case kLoadLazyDylib: return "LC_LAZY_LOAD_DYLIB";
            case 0x22U: return "LC_DYLD_INFO";
            case 0x80000022U: return "LC_DYLD_INFO_ONLY";
            case kLoadUpwardDylib: return "LC_LOAD_UPWARD_DYLIB";
            case 0x24U: return "LC_VERSION_MIN_MACOSX";
            case 0x25U: return "LC_VERSION_MIN_IPHONEOS";
            case 0x26U: return "LC_FUNCTION_STARTS";
            case 0x27U: return "LC_DYLD_ENVIRONMENT";
            case kLoadMain: return "LC_MAIN";
            case 0x29U: return "LC_DATA_IN_CODE";
            case 0x2AU: return "LC_SOURCE_VERSION";
            case 0x2BU: return "LC_DYLIB_CODE_SIGN_DRS";
            case 0x2CU: return "LC_ENCRYPTION_INFO_64";
            case 0x2DU: return "LC_LINKER_OPTION";
            case 0x2EU: return "LC_LINKER_OPTIMIZATION_HINT";
            case 0x32U: return "LC_BUILD_VERSION";
            case 0x33U: return "LC_DYLD_EXPORTS_TRIE";
            case 0x34U: return "LC_DYLD_CHAINED_FIXUPS";
            case 0x35U: return "LC_FILESET_ENTRY";
            default: return "LC_UNKNOWN";
            }
        }

        std::string ProtectionText(const std::uint32_t value)
        {
            std::string text;
            text += (value & 1U) != 0 ? 'R' : '-';
            text += (value & 2U) != 0 ? 'W' : '-';
            text += (value & 4U) != 0 ? 'X' : '-';
            return text;
        }

        const char* NListTypeName(const std::uint8_t type)
        {
            switch (type & kNTypeMask)
            {
            case 0x0: return "UNDF";
            case 0x2: return "ABS";
            case 0x4: return "TEXT";
            case 0x6: return "DATA";
            case 0x8: return "BSS";
            case 0xA: return "INDR";
            case 0xC: return "COMM";
            case 0xE: return "SECT";
            default: return "OTHER";
            }
        }

        std::string SliceFormatName(
            const EndianReader& reader,
            const std::uint64_t offset,
            const std::uint64_t size)
        {
            const std::span<const std::uint8_t> slice = reader.slice(offset, size);
            const MachMagic magic = DetectMagic(slice);
            if (!magic.recognized)
            {
                return "Unknown";
            }
            if (magic.universal)
            {
                return magic.is64 ? "Universal64" : "Universal32";
            }
            return magic.is64 ? "Mach-O 64" : "Mach-O 32";
        }

        bool ParseUniversal(
            const std::span<const std::uint8_t> bytes,
            const MachMagic& magic,
            const ScanOptions& options,
            BinaryScanResult& result)
        {
            const EndianReader reader(bytes, magic.byteOrder);
            std::uint32_t architectureCount = 0;
            if (!reader.readU32(4, architectureCount))
            {
                AddDiagnostic(
                    result,
                    DiagnosticSeverity::Error,
                    "macho.fat_header_truncated",
                    "The universal Mach-O header is truncated.");
                return false;
            }
            if (architectureCount > options.maxContainerEntries)
            {
                AddDiagnostic(
                    result,
                    DiagnosticSeverity::Error,
                    "macho.fat_count_excessive",
                    "Universal Mach-O slice count exceeds maxContainerEntries.");
                return false;
            }

            const std::uint64_t entrySize = magic.is64 ? 32U : 20U;
            std::uint64_t tableBytes = 0;
            if (!CheckedMultiply(architectureCount, entrySize, tableBytes) ||
                !reader.contains(8, tableBytes))
            {
                AddDiagnosticAt(
                    result,
                    DiagnosticSeverity::Error,
                    "macho.fat_table_invalid",
                    "Universal Mach-O architecture table is outside the file.",
                    8);
                return false;
            }

            AddField(result.summary, "Format", magic.is64 ? "Universal Mach-O 64" : "Universal Mach-O");
            AddField(result.summary, "Byte Order", ByteOrderName(magic.byteOrder));
            AddField(result.summary, "Slices", Decimal(architectureCount));
            AddField(result.headers, "Magic", magic.is64 ? Hex(kFatMagic64) : Hex(kFatMagic32));
            AddField(result.headers, "Architecture Count", Decimal(architectureCount));

            BinaryTable slices{
                "slices",
                "Universal Slices",
                { "Index", "CPU", "CPU Type", "CPU Subtype", "Offset", "Size",
                  "Alignment Exponent", "Slice Format", "Range Status" },
                {},
                false
            };
            for (std::uint32_t index = 0; index < architectureCount; ++index)
            {
                const std::uint64_t entryOffset = 8ULL + index * entrySize;
                std::uint32_t cpuType = 0;
                std::uint32_t cpuSubtype = 0;
                std::uint32_t alignment = 0;
                std::uint64_t sliceOffset = 0;
                std::uint64_t sliceSize = 0;
                if (!reader.readU32(entryOffset, cpuType) ||
                    !reader.readU32(entryOffset + 4, cpuSubtype))
                {
                    AddDiagnosticAt(
                        result,
                        DiagnosticSeverity::Error,
                        "macho.fat_entry_truncated",
                        "A universal Mach-O architecture entry is truncated.",
                        entryOffset);
                    return false;
                }
                if (magic.is64)
                {
                    if (!reader.readU64(entryOffset + 8, sliceOffset) ||
                        !reader.readU64(entryOffset + 16, sliceSize) ||
                        !reader.readU32(entryOffset + 24, alignment))
                    {
                        return false;
                    }
                }
                else
                {
                    std::uint32_t sliceOffset32 = 0;
                    std::uint32_t sliceSize32 = 0;
                    if (!reader.readU32(entryOffset + 8, sliceOffset32) ||
                        !reader.readU32(entryOffset + 12, sliceSize32) ||
                        !reader.readU32(entryOffset + 16, alignment))
                    {
                        return false;
                    }
                    sliceOffset = sliceOffset32;
                    sliceSize = sliceSize32;
                }

                const bool rangeValid = reader.contains(sliceOffset, sliceSize);
                if (!rangeValid)
                {
                    AddDiagnosticAt(
                        result,
                        DiagnosticSeverity::Warning,
                        "macho.slice_range_invalid",
                        "A universal Mach-O slice is outside the file.",
                        sliceOffset);
                }
                AppendRow(
                    slices,
                    {
                        Decimal(index),
                        CpuTypeName(cpuType),
                        Hex(cpuType),
                        Hex(cpuSubtype),
                        Hex(sliceOffset),
                        Hex(sliceSize),
                        Decimal(alignment),
                        rangeValid ? SliceFormatName(reader, sliceOffset, sliceSize) : "Unavailable",
                        rangeValid ? "Valid" : "Invalid"
                    },
                    options);
            }
            result.tables.push_back(std::move(slices));
            result.success = true;
            return true;
        }

        bool ParseSegment(
            const EndianReader& reader,
            const std::uint64_t commandOffset,
            const std::uint32_t commandSize,
            const bool is64,
            const ScanOptions& options,
            BinaryScanResult& result,
            BinaryTable& segments,
            BinaryTable& sections,
            std::string& detailsOut)
        {
            const std::uint64_t segmentHeaderSize = is64 ? 72U : 56U;
            const std::uint64_t sectionEntrySize = is64 ? 80U : 68U;
            if (commandSize < segmentHeaderSize)
            {
                return false;
            }

            const std::string segmentName = reader.fixedString(
                commandOffset + 8,
                16,
                options.maxStringBytes);
            std::uint64_t virtualAddress = 0;
            std::uint64_t virtualSize = 0;
            std::uint64_t fileOffset = 0;
            std::uint64_t fileSize = 0;
            std::uint32_t maxProtection = 0;
            std::uint32_t initialProtection = 0;
            std::uint32_t sectionCount = 0;
            std::uint32_t flags = 0;
            if (is64)
            {
                if (!reader.readU64(commandOffset + 24, virtualAddress) ||
                    !reader.readU64(commandOffset + 32, virtualSize) ||
                    !reader.readU64(commandOffset + 40, fileOffset) ||
                    !reader.readU64(commandOffset + 48, fileSize) ||
                    !reader.readU32(commandOffset + 56, maxProtection) ||
                    !reader.readU32(commandOffset + 60, initialProtection) ||
                    !reader.readU32(commandOffset + 64, sectionCount) ||
                    !reader.readU32(commandOffset + 68, flags))
                {
                    return false;
                }
            }
            else
            {
                std::uint32_t virtualAddress32 = 0;
                std::uint32_t virtualSize32 = 0;
                std::uint32_t fileOffset32 = 0;
                std::uint32_t fileSize32 = 0;
                if (!reader.readU32(commandOffset + 24, virtualAddress32) ||
                    !reader.readU32(commandOffset + 28, virtualSize32) ||
                    !reader.readU32(commandOffset + 32, fileOffset32) ||
                    !reader.readU32(commandOffset + 36, fileSize32) ||
                    !reader.readU32(commandOffset + 40, maxProtection) ||
                    !reader.readU32(commandOffset + 44, initialProtection) ||
                    !reader.readU32(commandOffset + 48, sectionCount) ||
                    !reader.readU32(commandOffset + 52, flags))
                {
                    return false;
                }
                virtualAddress = virtualAddress32;
                virtualSize = virtualSize32;
                fileOffset = fileOffset32;
                fileSize = fileSize32;
            }
            if (sectionCount > options.maxContainerEntries)
            {
                AddDiagnosticAt(
                    result,
                    DiagnosticSeverity::Warning,
                    "macho.section_count_excessive",
                    "A segment section count exceeds maxContainerEntries.",
                    commandOffset);
                return false;
            }
            std::uint64_t sectionBytes = 0;
            if (!CheckedMultiply(sectionCount, sectionEntrySize, sectionBytes) ||
                sectionBytes > commandSize - segmentHeaderSize)
            {
                return false;
            }

            AppendRow(
                segments,
                {
                    segmentName,
                    Hex(virtualAddress),
                    Hex(virtualSize),
                    Hex(fileOffset),
                    Hex(fileSize),
                    ProtectionText(maxProtection),
                    ProtectionText(initialProtection),
                    Decimal(sectionCount),
                    Hex(flags)
                },
                options);
            detailsOut = "segment=" + segmentName + ", sections=" + Decimal(sectionCount);

            for (std::uint32_t index = 0; index < sectionCount; ++index)
            {
                const std::uint64_t sectionOffset =
                    commandOffset + segmentHeaderSize + index * sectionEntrySize;
                const std::string sectionName = reader.fixedString(
                    sectionOffset,
                    16,
                    options.maxStringBytes);
                const std::string owningSegment = reader.fixedString(
                    sectionOffset + 16,
                    16,
                    options.maxStringBytes);
                std::uint64_t address = 0;
                std::uint64_t size = 0;
                std::uint32_t rawOffset = 0;
                std::uint32_t alignment = 0;
                std::uint32_t relocationOffset = 0;
                std::uint32_t relocationCount = 0;
                std::uint32_t sectionFlags = 0;
                if (is64)
                {
                    if (!reader.readU64(sectionOffset + 32, address) ||
                        !reader.readU64(sectionOffset + 40, size) ||
                        !reader.readU32(sectionOffset + 48, rawOffset) ||
                        !reader.readU32(sectionOffset + 52, alignment) ||
                        !reader.readU32(sectionOffset + 56, relocationOffset) ||
                        !reader.readU32(sectionOffset + 60, relocationCount) ||
                        !reader.readU32(sectionOffset + 64, sectionFlags))
                    {
                        return false;
                    }
                }
                else
                {
                    std::uint32_t address32 = 0;
                    std::uint32_t size32 = 0;
                    if (!reader.readU32(sectionOffset + 32, address32) ||
                        !reader.readU32(sectionOffset + 36, size32) ||
                        !reader.readU32(sectionOffset + 40, rawOffset) ||
                        !reader.readU32(sectionOffset + 44, alignment) ||
                        !reader.readU32(sectionOffset + 48, relocationOffset) ||
                        !reader.readU32(sectionOffset + 52, relocationCount) ||
                        !reader.readU32(sectionOffset + 56, sectionFlags))
                    {
                        return false;
                    }
                    address = address32;
                    size = size32;
                }
                AppendRow(
                    sections,
                    {
                        owningSegment,
                        sectionName,
                        Hex(address),
                        Hex(size),
                        Hex(rawOffset),
                        Decimal(alignment),
                        Hex(relocationOffset),
                        Decimal(relocationCount),
                        Hex(sectionFlags)
                    },
                    options);
            }
            return true;
        }

        std::string ReadDylibName(
            const EndianReader& reader,
            const std::uint64_t commandOffset,
            const std::uint32_t commandSize,
            const ScanOptions& options)
        {
            std::uint32_t nameOffset = 0;
            if (commandSize < 24 ||
                !reader.readU32(commandOffset + 8, nameOffset) ||
                nameOffset >= commandSize)
            {
                return {};
            }
            return reader.cString(
                commandOffset + nameOffset,
                commandOffset + commandSize,
                options.maxStringBytes);
        }

        std::string FormatUuid(
            const EndianReader& reader,
            const std::uint64_t commandOffset,
            const std::uint32_t commandSize)
        {
            if (commandSize < 24)
            {
                return {};
            }
            const std::span<const std::uint8_t> bytes = reader.slice(commandOffset + 8, 16);
            if (bytes.size() != 16)
            {
                return {};
            }
            std::string value;
            for (std::size_t index = 0; index < bytes.size(); ++index)
            {
                if (index == 4 || index == 6 || index == 8 || index == 10)
                {
                    value += '-';
                }
                std::ostringstream stream;
                stream << std::uppercase << std::hex << std::setfill('0')
                    << std::setw(2) << static_cast<unsigned int>(bytes[index]);
                value += stream.str();
            }
            return value;
        }

        void ParseSymbols(
            const EndianReader& reader,
            const bool is64,
            const SymtabCommand& symtab,
            const ScanOptions& options,
            BinaryScanResult& result,
            BinaryTable& symbols,
            BinaryTable& imports,
            BinaryTable& exports)
        {
            if (!symtab.present)
            {
                return;
            }
            const std::uint64_t entrySize = is64 ? 16U : 12U;
            if (symtab.symbolCount > options.maxContainerEntries)
            {
                AddDiagnosticAt(
                    result,
                    DiagnosticSeverity::Warning,
                    "macho.symbol_count_limited",
                    "Mach-O symbol count exceeds maxContainerEntries; the table was bounded.",
                    symtab.commandOffset);
            }
            const std::uint64_t symbolCount = std::min<std::uint64_t>(
                symtab.symbolCount,
                options.maxContainerEntries);
            std::uint64_t symbolBytes = 0;
            if (!CheckedMultiply(symbolCount, entrySize, symbolBytes) ||
                !reader.contains(symtab.symbolOffset, symbolBytes) ||
                !reader.contains(symtab.stringOffset, symtab.stringSize))
            {
                AddDiagnosticAt(
                    result,
                    DiagnosticSeverity::Warning,
                    "macho.symbol_range_invalid",
                    "Mach-O symbol or string table is outside the file.",
                    symtab.commandOffset);
                return;
            }
            const std::uint64_t stringEnd =
                static_cast<std::uint64_t>(symtab.stringOffset) + symtab.stringSize;
            for (std::uint64_t index = 0; index < symbolCount; ++index)
            {
                const std::uint64_t entryOffset =
                    static_cast<std::uint64_t>(symtab.symbolOffset) + index * entrySize;
                std::uint32_t stringIndex = 0;
                std::uint8_t type = 0;
                std::uint8_t section = 0;
                std::uint16_t description = 0;
                std::uint64_t value = 0;
                if (!reader.readU32(entryOffset, stringIndex) ||
                    !reader.readU8(entryOffset + 4, type) ||
                    !reader.readU8(entryOffset + 5, section) ||
                    !reader.readU16(entryOffset + 6, description))
                {
                    break;
                }
                if (is64)
                {
                    if (!reader.readU64(entryOffset + 8, value))
                    {
                        break;
                    }
                }
                else
                {
                    std::uint32_t value32 = 0;
                    if (!reader.readU32(entryOffset + 8, value32))
                    {
                        break;
                    }
                    value = value32;
                }

                std::string name;
                if (stringIndex < symtab.stringSize)
                {
                    name = reader.cString(
                        static_cast<std::uint64_t>(symtab.stringOffset) + stringIndex,
                        stringEnd,
                        options.maxStringBytes);
                }
                const bool debugSymbol = (type & kNStabMask) != 0;
                const bool external = (type & kNExternal) != 0;
                const bool undefined = (type & kNTypeMask) == kNUndefined;
                AppendRow(
                    symbols,
                    {
                        Decimal(index),
                        name,
                        debugSymbol ? "STAB" : NListTypeName(type),
                        external ? "Yes" : "No",
                        Decimal(section),
                        Hex(description),
                        Hex(value)
                    },
                    options);

                if (!debugSymbol && external && !name.empty())
                {
                    BinaryTable& classification = undefined ? imports : exports;
                    AppendRow(
                        classification,
                        {
                            name,
                            NListTypeName(type),
                            Decimal(section),
                            Hex(description),
                            Hex(value)
                        },
                        options);
                }
            }
        }

        bool ParseThin(
            const std::span<const std::uint8_t> bytes,
            const MachMagic& magic,
            const ScanOptions& options,
            BinaryScanResult& result)
        {
            const EndianReader reader(bytes, magic.byteOrder);
            const std::uint64_t headerSize = magic.is64 ? 32U : 28U;
            if (bytes.size() < headerSize)
            {
                AddDiagnostic(
                    result,
                    DiagnosticSeverity::Error,
                    "macho.header_truncated",
                    "The Mach-O header is truncated.");
                return false;
            }

            std::uint32_t cpuType = 0;
            std::uint32_t cpuSubtype = 0;
            std::uint32_t fileType = 0;
            std::uint32_t commandCount = 0;
            std::uint32_t commandsSize = 0;
            std::uint32_t flags = 0;
            std::uint32_t reserved = 0;
            if (!reader.readU32(4, cpuType) ||
                !reader.readU32(8, cpuSubtype) ||
                !reader.readU32(12, fileType) ||
                !reader.readU32(16, commandCount) ||
                !reader.readU32(20, commandsSize) ||
                !reader.readU32(24, flags) ||
                (magic.is64 && !reader.readU32(28, reserved)))
            {
                return false;
            }
            if (commandCount > options.maxContainerEntries)
            {
                AddDiagnostic(
                    result,
                    DiagnosticSeverity::Error,
                    "macho.command_count_excessive",
                    "Mach-O load command count exceeds maxContainerEntries.");
                return false;
            }
            if (!reader.contains(headerSize, commandsSize))
            {
                AddDiagnosticAt(
                    result,
                    DiagnosticSeverity::Error,
                    "macho.command_region_invalid",
                    "Mach-O load command region is outside the file.",
                    headerSize);
                return false;
            }

            AddField(result.summary, "Format", magic.is64 ? "Mach-O 64" : "Mach-O 32");
            AddField(result.summary, "Byte Order", ByteOrderName(magic.byteOrder));
            AddField(result.summary, "Architecture", CpuTypeName(cpuType));
            AddField(result.summary, "File Type", FileTypeName(fileType));
            AddField(result.summary, "Load Commands", Decimal(commandCount));
            AddField(result.headers, "Magic", magic.is64 ? Hex(kMagic64) : Hex(kMagic32));
            AddField(result.headers, "CPU Type", std::string(CpuTypeName(cpuType)) + " (" + Hex(cpuType) + ")");
            AddField(result.headers, "CPU Subtype", Hex(cpuSubtype));
            AddField(result.headers, "File Type", std::string(FileTypeName(fileType)) + " (" + Hex(fileType) + ")");
            AddField(result.headers, "Load Command Count", Decimal(commandCount));
            AddField(result.headers, "Load Commands Size", Decimal(commandsSize));
            AddField(result.headers, "Flags", Hex(flags));
            if (magic.is64)
            {
                AddField(result.headers, "Reserved", Hex(reserved));
            }

            BinaryTable commands{
                "load_commands",
                "Load Commands",
                { "Index", "Command", "Value", "Offset", "Size", "Details" },
                {},
                false
            };
            BinaryTable segments{
                "segments",
                "Segments",
                { "Name", "VM Address", "VM Size", "File Offset", "File Size",
                  "Max Protection", "Initial Protection", "Section Count", "Flags" },
                {},
                false
            };
            BinaryTable sections{
                "sections",
                "Sections",
                { "Segment", "Name", "Address", "Size", "File Offset", "Alignment",
                  "Relocation Offset", "Relocation Count", "Flags" },
                {},
                false
            };
            BinaryTable dylibs{
                "dynamic_libraries",
                "Dynamic Libraries",
                { "Command", "Path", "Timestamp", "Current Version", "Compatibility Version" },
                {},
                false
            };
            SymtabCommand symtab{};

            const std::uint64_t commandEnd = headerSize + commandsSize;
            std::uint64_t commandOffset = headerSize;
            for (std::uint32_t index = 0; index < commandCount; ++index)
            {
                std::uint32_t command = 0;
                std::uint32_t commandSize = 0;
                if (!reader.readU32(commandOffset, command) ||
                    !reader.readU32(commandOffset + 4, commandSize) ||
                    commandSize < 8 ||
                    commandSize > commandEnd - commandOffset)
                {
                    AddDiagnosticAt(
                        result,
                        DiagnosticSeverity::Error,
                        "macho.command_invalid",
                        "A Mach-O load command has an invalid size or range.",
                        commandOffset);
                    return false;
                }

                std::string details;
                if (command == kLoadSegment || command == kLoadSegment64)
                {
                    const bool commandIs64 = command == kLoadSegment64;
                    if (commandIs64 != magic.is64)
                    {
                        AddDiagnosticAt(
                            result,
                            DiagnosticSeverity::Warning,
                            "macho.segment_class_mismatch",
                            "A segment command class differs from the Mach-O header class.",
                            commandOffset);
                    }
                    if (!ParseSegment(
                            reader,
                            commandOffset,
                            commandSize,
                            commandIs64,
                            options,
                            result,
                            segments,
                            sections,
                            details))
                    {
                        AddDiagnosticAt(
                            result,
                            DiagnosticSeverity::Error,
                            "macho.segment_invalid",
                            "A Mach-O segment or section table is invalid.",
                            commandOffset);
                        return false;
                    }
                }
                else if (command == kLoadSymtab)
                {
                    if (commandSize < 24 ||
                        !reader.readU32(commandOffset + 8, symtab.symbolOffset) ||
                        !reader.readU32(commandOffset + 12, symtab.symbolCount) ||
                        !reader.readU32(commandOffset + 16, symtab.stringOffset) ||
                        !reader.readU32(commandOffset + 20, symtab.stringSize))
                    {
                        AddDiagnosticAt(
                            result,
                            DiagnosticSeverity::Error,
                            "macho.symtab_command_invalid",
                            "LC_SYMTAB is truncated.",
                            commandOffset);
                        return false;
                    }
                    symtab.present = true;
                    symtab.commandOffset = commandOffset;
                    details = "symbols=" + Decimal(symtab.symbolCount);
                }
                else if (command == kLoadDylib ||
                    command == kIdDylib ||
                    command == kLoadWeakDylib ||
                    command == kLoadLazyDylib ||
                    command == kLoadReexportDylib ||
                    command == kLoadUpwardDylib)
                {
                    std::uint32_t timestamp = 0;
                    std::uint32_t currentVersion = 0;
                    std::uint32_t compatibilityVersion = 0;
                    if (commandSize < 24 ||
                        !reader.readU32(commandOffset + 12, timestamp) ||
                        !reader.readU32(commandOffset + 16, currentVersion) ||
                        !reader.readU32(commandOffset + 20, compatibilityVersion))
                    {
                        return false;
                    }
                    const std::string name =
                        ReadDylibName(reader, commandOffset, commandSize, options);
                    details = name;
                    AppendRow(
                        dylibs,
                        {
                            LoadCommandName(command),
                            name,
                            Decimal(timestamp),
                            Hex(currentVersion),
                            Hex(compatibilityVersion)
                        },
                        options);
                }
                else if (command == kLoadMain)
                {
                    std::uint64_t entryOffset = 0;
                    std::uint64_t stackSize = 0;
                    if (commandSize < 24 ||
                        !reader.readU64(commandOffset + 8, entryOffset) ||
                        !reader.readU64(commandOffset + 16, stackSize))
                    {
                        return false;
                    }
                    details = "entryoff=" + Hex(entryOffset) + ", stack=" + Hex(stackSize);
                    AddField(result.summary, "Entry File Offset", Hex(entryOffset));
                }
                else if (command == kLoadUuid)
                {
                    details = FormatUuid(reader, commandOffset, commandSize);
                    if (!details.empty())
                    {
                        AddField(result.summary, "UUID", details);
                    }
                }
                else if (command == kLoadCodeSignature && commandSize >= 16)
                {
                    std::uint32_t dataOffset = 0;
                    std::uint32_t dataSize = 0;
                    if (reader.readU32(commandOffset + 8, dataOffset) &&
                        reader.readU32(commandOffset + 12, dataSize))
                    {
                        details = "offset=" + Hex(dataOffset) + ", size=" + Hex(dataSize);
                    }
                }

                AppendRow(
                    commands,
                    {
                        Decimal(index),
                        LoadCommandName(command),
                        Hex(command),
                        Hex(commandOffset),
                        Decimal(commandSize),
                        details
                    },
                    options);
                commandOffset += commandSize;
            }
            if (commandOffset != commandEnd)
            {
                AddDiagnosticAt(
                    result,
                    DiagnosticSeverity::Warning,
                    "macho.command_size_mismatch",
                    "Load commands do not consume the complete sizeofcmds region.",
                    commandOffset);
            }

            BinaryTable symbols{
                "symbols",
                "Symbols",
                { "Index", "Name", "Type", "External", "Section", "Description", "Value" },
                {},
                false
            };
            BinaryTable imports{
                "imports",
                "Imported Symbols",
                { "Name", "Type", "Section", "Description", "Value" },
                {},
                false
            };
            BinaryTable exports{
                "exports",
                "Exported Symbols",
                { "Name", "Type", "Section", "Description", "Value" },
                {},
                false
            };
            ParseSymbols(
                reader,
                magic.is64,
                symtab,
                options,
                result,
                symbols,
                imports,
                exports);

            result.tables.push_back(std::move(commands));
            result.tables.push_back(std::move(segments));
            result.tables.push_back(std::move(sections));
            result.tables.push_back(std::move(dylibs));
            result.tables.push_back(std::move(symbols));
            result.tables.push_back(std::move(imports));
            result.tables.push_back(std::move(exports));
            result.success = true;
            return true;
        }
    }

    bool ParseMachO(
        const std::span<const std::uint8_t> bytes,
        const ScanOptions& options,
        BinaryScanResult& result)
    {
        result.recognized = true;
        const MachMagic magic = DetectMagic(bytes);
        if (!magic.recognized)
        {
            AddDiagnostic(
                result,
                DiagnosticSeverity::Error,
                "macho.magic_invalid",
                "Mach-O magic is invalid.");
            return false;
        }

        result.byteOrder = magic.byteOrder;
        if (magic.universal)
        {
            result.format = BinaryFormat::MachOUniversal;
            return ParseUniversal(bytes, magic, options, result);
        }
        result.format = magic.is64 ? BinaryFormat::MachO64 : BinaryFormat::MachO32;
        return ParseThin(bytes, magic, options, result);
    }
}
