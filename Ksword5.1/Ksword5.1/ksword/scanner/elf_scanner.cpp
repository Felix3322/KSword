#include "scanner_internal.h"

// ============================================================
// ksword/scanner/elf_scanner.cpp
// Purpose:
// - Parse ELF32 and ELF64 in either byte order without platform ELF headers.
// - Expose headers, program headers, sections, dependencies, and symbols.
// - Classify global/weak undefined symbols as imports and defined symbols as exports.
//
// No structure is cast directly over file bytes. This keeps unaligned and
// opposite-endian files safe on Windows hosts.
// ============================================================

#include <algorithm>
#include <cstdint>
#include <limits>
#include <span>
#include <string>
#include <utility>
#include <vector>

namespace ks::scanner::detail
{
    namespace
    {
        constexpr std::uint8_t kElfClass32 = 1;
        constexpr std::uint8_t kElfClass64 = 2;
        constexpr std::uint8_t kElfDataLittle = 1;
        constexpr std::uint8_t kElfDataBig = 2;
        constexpr std::uint16_t kSectionIndexUndefined = 0;
        constexpr std::uint16_t kSectionIndexExtended = 0xFFFF;
        constexpr std::uint16_t kProgramCountExtended = 0xFFFF;
        constexpr std::uint32_t kSectionTypeSymbolTable = 2;
        constexpr std::uint32_t kSectionTypeStringTable = 3;
        constexpr std::uint32_t kSectionTypeDynamic = 6;
        constexpr std::uint32_t kSectionTypeDynamicSymbols = 11;
        constexpr std::uint64_t kDynamicNull = 0;
        constexpr std::uint64_t kDynamicNeeded = 1;

        struct ElfHeaderView
        {
            bool is64 = false;
            ByteOrder byteOrder = ByteOrder::Unknown;
            std::uint16_t type = 0;
            std::uint16_t machine = 0;
            std::uint32_t version = 0;
            std::uint64_t entry = 0;
            std::uint64_t programOffset = 0;
            std::uint64_t sectionOffset = 0;
            std::uint32_t flags = 0;
            std::uint16_t headerSize = 0;
            std::uint16_t programEntrySize = 0;
            std::uint64_t programCount = 0;
            std::uint16_t sectionEntrySize = 0;
            std::uint64_t sectionCount = 0;
            std::uint64_t sectionNameIndex = 0;
        };

        struct ElfSectionView
        {
            std::uint32_t nameOffset = 0;
            std::uint32_t type = 0;
            std::uint64_t flags = 0;
            std::uint64_t address = 0;
            std::uint64_t offset = 0;
            std::uint64_t size = 0;
            std::uint32_t link = 0;
            std::uint32_t info = 0;
            std::uint64_t alignment = 0;
            std::uint64_t entrySize = 0;
            std::string name;
        };

        const char* ElfTypeName(const std::uint16_t value)
        {
            switch (value)
            {
            case 0: return "None";
            case 1: return "Relocatable";
            case 2: return "Executable";
            case 3: return "Shared object";
            case 4: return "Core";
            default: return "Processor/OS-specific";
            }
        }

        const char* ElfMachineName(const std::uint16_t value)
        {
            switch (value)
            {
            case 3: return "x86";
            case 8: return "MIPS";
            case 20: return "PowerPC";
            case 21: return "PowerPC64";
            case 40: return "ARM";
            case 50: return "IA-64";
            case 62: return "x86-64";
            case 183: return "AArch64";
            case 243: return "RISC-V";
            default: return "Unknown";
            }
        }

        const char* ProgramTypeName(const std::uint32_t value)
        {
            switch (value)
            {
            case 0: return "NULL";
            case 1: return "LOAD";
            case 2: return "DYNAMIC";
            case 3: return "INTERP";
            case 4: return "NOTE";
            case 5: return "SHLIB";
            case 6: return "PHDR";
            case 7: return "TLS";
            case 0x6474E550U: return "GNU_EH_FRAME";
            case 0x6474E551U: return "GNU_STACK";
            case 0x6474E552U: return "GNU_RELRO";
            case 0x6474E553U: return "GNU_PROPERTY";
            default: return "OTHER";
            }
        }

        const char* SectionTypeName(const std::uint32_t value)
        {
            switch (value)
            {
            case 0: return "NULL";
            case 1: return "PROGBITS";
            case 2: return "SYMTAB";
            case 3: return "STRTAB";
            case 4: return "RELA";
            case 5: return "HASH";
            case 6: return "DYNAMIC";
            case 7: return "NOTE";
            case 8: return "NOBITS";
            case 9: return "REL";
            case 10: return "SHLIB";
            case 11: return "DYNSYM";
            case 14: return "INIT_ARRAY";
            case 15: return "FINI_ARRAY";
            case 16: return "PREINIT_ARRAY";
            case 17: return "GROUP";
            case 18: return "SYMTAB_SHNDX";
            case 0x6FFFFFF6U: return "GNU_HASH";
            case 0x6FFFFFFDU: return "GNU_VERDEF";
            case 0x6FFFFFFEU: return "GNU_VERNEED";
            case 0x6FFFFFFFU: return "GNU_VERSYM";
            default: return "OTHER";
            }
        }

        std::string ProgramFlags(const std::uint32_t flags)
        {
            std::string text;
            if ((flags & 4U) != 0) { text += 'R'; }
            if ((flags & 2U) != 0) { text += 'W'; }
            if ((flags & 1U) != 0) { text += 'X'; }
            return text.empty() ? "-" : text;
        }

        std::string SectionFlags(const std::uint64_t flags)
        {
            std::string text;
            if ((flags & 0x1ULL) != 0) { text += 'W'; }
            if ((flags & 0x2ULL) != 0) { text += 'A'; }
            if ((flags & 0x4ULL) != 0) { text += 'X'; }
            if ((flags & 0x10ULL) != 0) { text += 'M'; }
            if ((flags & 0x20ULL) != 0) { text += 'S'; }
            if ((flags & 0x40ULL) != 0) { text += 'I'; }
            if ((flags & 0x80ULL) != 0) { text += 'L'; }
            if ((flags & 0x400ULL) != 0) { text += 'T'; }
            return text.empty() ? "-" : text;
        }

        const char* SymbolBindingName(const std::uint8_t binding)
        {
            switch (binding)
            {
            case 0: return "LOCAL";
            case 1: return "GLOBAL";
            case 2: return "WEAK";
            case 10: return "GNU_UNIQUE";
            default: return "OTHER";
            }
        }

        const char* SymbolTypeName(const std::uint8_t type)
        {
            switch (type)
            {
            case 0: return "NOTYPE";
            case 1: return "OBJECT";
            case 2: return "FUNC";
            case 3: return "SECTION";
            case 4: return "FILE";
            case 5: return "COMMON";
            case 6: return "TLS";
            case 10: return "GNU_IFUNC";
            default: return "OTHER";
            }
        }

        const char* SymbolVisibilityName(const std::uint8_t visibility)
        {
            switch (visibility & 0x3U)
            {
            case 0: return "DEFAULT";
            case 1: return "INTERNAL";
            case 2: return "HIDDEN";
            case 3: return "PROTECTED";
            default: return "UNKNOWN";
            }
        }

        bool ValidateTableRange(
            const EndianReader& reader,
            std::uint64_t offset,
            std::uint64_t count,
            std::uint64_t entrySize,
            std::uint64_t minimumEntrySize)
        {
            if (count == 0)
            {
                return true;
            }
            if (entrySize < minimumEntrySize)
            {
                return false;
            }
            std::uint64_t tableBytes = 0;
            return CheckedMultiply(count, entrySize, tableBytes) &&
                reader.contains(offset, tableBytes);
        }

        bool ReadHeader(
            const EndianReader& reader,
            bool is64,
            ElfHeaderView& headerOut)
        {
            if (is64)
            {
                return false;
            }
            headerOut.is64 = is64;
            headerOut.byteOrder = reader.byteOrder();
            if (!reader.readU16(16, headerOut.type) ||
                !reader.readU16(18, headerOut.machine) ||
                !reader.readU32(20, headerOut.version))
            {
                return false;
            }

            std::uint32_t entry32 = 0;
            std::uint32_t programOffset32 = 0;
            std::uint32_t sectionOffset32 = 0;
            std::uint16_t programCount16 = 0;
            std::uint16_t sectionCount16 = 0;
            std::uint16_t sectionNameIndex16 = 0;
            if (!reader.readU32(24, entry32) ||
                !reader.readU32(28, programOffset32) ||
                !reader.readU32(32, sectionOffset32) ||
                !reader.readU32(36, headerOut.flags) ||
                !reader.readU16(40, headerOut.headerSize) ||
                !reader.readU16(42, headerOut.programEntrySize) ||
                !reader.readU16(44, programCount16) ||
                !reader.readU16(46, headerOut.sectionEntrySize) ||
                !reader.readU16(48, sectionCount16) ||
                !reader.readU16(50, sectionNameIndex16))
            {
                return false;
            }
            headerOut.entry = entry32;
            headerOut.programOffset = programOffset32;
            headerOut.sectionOffset = sectionOffset32;
            headerOut.programCount = programCount16;
            headerOut.sectionCount = sectionCount16;
            headerOut.sectionNameIndex = sectionNameIndex16;
            return true;
        }

        // ReadHeader stores 16-bit counts in 64-bit members without aliasing.
        bool ReadHeaderSafe(
            const EndianReader& reader,
            bool is64,
            ElfHeaderView& headerOut)
        {
            if (!is64)
            {
                return ReadHeader(reader, false, headerOut);
            }

            std::uint16_t programCount16 = 0;
            std::uint16_t sectionCount16 = 0;
            std::uint16_t sectionNameIndex16 = 0;
            headerOut.is64 = true;
            headerOut.byteOrder = reader.byteOrder();
            if (!reader.readU16(16, headerOut.type) ||
                !reader.readU16(18, headerOut.machine) ||
                !reader.readU32(20, headerOut.version) ||
                !reader.readU64(24, headerOut.entry) ||
                !reader.readU64(32, headerOut.programOffset) ||
                !reader.readU64(40, headerOut.sectionOffset) ||
                !reader.readU32(48, headerOut.flags) ||
                !reader.readU16(52, headerOut.headerSize) ||
                !reader.readU16(54, headerOut.programEntrySize) ||
                !reader.readU16(56, programCount16) ||
                !reader.readU16(58, headerOut.sectionEntrySize) ||
                !reader.readU16(60, sectionCount16) ||
                !reader.readU16(62, sectionNameIndex16))
            {
                return false;
            }
            headerOut.programCount = programCount16;
            headerOut.sectionCount = sectionCount16;
            headerOut.sectionNameIndex = sectionNameIndex16;
            return true;
        }

        bool ReadSection(
            const EndianReader& reader,
            bool is64,
            std::uint64_t offset,
            ElfSectionView& sectionOut)
        {
            if (!reader.readU32(offset, sectionOut.nameOffset) ||
                !reader.readU32(offset + 4, sectionOut.type))
            {
                return false;
            }

            if (is64)
            {
                return reader.readU64(offset + 8, sectionOut.flags) &&
                    reader.readU64(offset + 16, sectionOut.address) &&
                    reader.readU64(offset + 24, sectionOut.offset) &&
                    reader.readU64(offset + 32, sectionOut.size) &&
                    reader.readU32(offset + 40, sectionOut.link) &&
                    reader.readU32(offset + 44, sectionOut.info) &&
                    reader.readU64(offset + 48, sectionOut.alignment) &&
                    reader.readU64(offset + 56, sectionOut.entrySize);
            }

            std::uint32_t flags32 = 0;
            std::uint32_t address32 = 0;
            std::uint32_t offset32 = 0;
            std::uint32_t size32 = 0;
            std::uint32_t alignment32 = 0;
            std::uint32_t entrySize32 = 0;
            if (!reader.readU32(offset + 8, flags32) ||
                !reader.readU32(offset + 12, address32) ||
                !reader.readU32(offset + 16, offset32) ||
                !reader.readU32(offset + 20, size32) ||
                !reader.readU32(offset + 24, sectionOut.link) ||
                !reader.readU32(offset + 28, sectionOut.info) ||
                !reader.readU32(offset + 32, alignment32) ||
                !reader.readU32(offset + 36, entrySize32))
            {
                return false;
            }
            sectionOut.flags = flags32;
            sectionOut.address = address32;
            sectionOut.offset = offset32;
            sectionOut.size = size32;
            sectionOut.alignment = alignment32;
            sectionOut.entrySize = entrySize32;
            return true;
        }

        bool ResolveExtendedCounts(
            const EndianReader& reader,
            ElfHeaderView& header)
        {
            if (header.sectionOffset == 0)
            {
                header.sectionCount = 0;
                if (header.sectionNameIndex != 0)
                {
                    return false;
                }
                return header.programCount != kProgramCountExtended;
            }
            if (header.sectionEntrySize < (header.is64 ? 64U : 40U) ||
                !reader.contains(header.sectionOffset, header.sectionEntrySize))
            {
                return false;
            }

            ElfSectionView firstSection{};
            if (!ReadSection(reader, header.is64, header.sectionOffset, firstSection))
            {
                return false;
            }
            if (header.sectionCount == 0)
            {
                header.sectionCount = firstSection.size;
            }
            if (header.sectionNameIndex == kSectionIndexExtended)
            {
                header.sectionNameIndex = firstSection.link;
            }
            if (header.programCount == kProgramCountExtended)
            {
                header.programCount = firstSection.info;
            }
            return true;
        }

        std::string ReadSectionString(
            const EndianReader& reader,
            const ElfSectionView& stringSection,
            std::uint64_t relativeOffset,
            const ScanOptions& options)
        {
            std::uint64_t stringOffset = 0;
            std::uint64_t stringEnd = 0;
            if (relativeOffset >= stringSection.size ||
                !CheckedAdd(stringSection.offset, relativeOffset, stringOffset) ||
                !CheckedAdd(stringSection.offset, stringSection.size, stringEnd) ||
                !reader.contains(stringSection.offset, stringSection.size))
            {
                return {};
            }
            return reader.cString(
                stringOffset,
                stringEnd,
                options.maxStringBytes);
        }

        void ParseProgramHeaders(
            const EndianReader& reader,
            const ElfHeaderView& header,
            const ScanOptions& options,
            BinaryScanResult& result)
        {
            BinaryTable table{
                "program_headers",
                "Program Headers",
                { "Index", "Type", "Flags", "File Offset", "Virtual Address",
                  "Physical Address", "File Size", "Memory Size", "Alignment" },
                {},
                false
            };

            for (std::uint64_t index = 0; index < header.programCount; ++index)
            {
                const std::uint64_t offset =
                    header.programOffset + index * header.programEntrySize;
                std::uint32_t type = 0;
                std::uint32_t flags = 0;
                std::uint64_t fileOffset = 0;
                std::uint64_t virtualAddress = 0;
                std::uint64_t physicalAddress = 0;
                std::uint64_t fileSize = 0;
                std::uint64_t memorySize = 0;
                std::uint64_t alignment = 0;

                if (header.is64)
                {
                    if (!reader.readU32(offset, type) ||
                        !reader.readU32(offset + 4, flags) ||
                        !reader.readU64(offset + 8, fileOffset) ||
                        !reader.readU64(offset + 16, virtualAddress) ||
                        !reader.readU64(offset + 24, physicalAddress) ||
                        !reader.readU64(offset + 32, fileSize) ||
                        !reader.readU64(offset + 40, memorySize) ||
                        !reader.readU64(offset + 48, alignment))
                    {
                        AddDiagnosticAt(
                            result,
                            DiagnosticSeverity::Warning,
                            "elf.program_header_truncated",
                            "A program header could not be read.",
                            offset);
                        break;
                    }
                }
                else
                {
                    std::uint32_t fileOffset32 = 0;
                    std::uint32_t virtualAddress32 = 0;
                    std::uint32_t physicalAddress32 = 0;
                    std::uint32_t fileSize32 = 0;
                    std::uint32_t memorySize32 = 0;
                    std::uint32_t alignment32 = 0;
                    if (!reader.readU32(offset, type) ||
                        !reader.readU32(offset + 4, fileOffset32) ||
                        !reader.readU32(offset + 8, virtualAddress32) ||
                        !reader.readU32(offset + 12, physicalAddress32) ||
                        !reader.readU32(offset + 16, fileSize32) ||
                        !reader.readU32(offset + 20, memorySize32) ||
                        !reader.readU32(offset + 24, flags) ||
                        !reader.readU32(offset + 28, alignment32))
                    {
                        AddDiagnosticAt(
                            result,
                            DiagnosticSeverity::Warning,
                            "elf.program_header_truncated",
                            "A program header could not be read.",
                            offset);
                        break;
                    }
                    fileOffset = fileOffset32;
                    virtualAddress = virtualAddress32;
                    physicalAddress = physicalAddress32;
                    fileSize = fileSize32;
                    memorySize = memorySize32;
                    alignment = alignment32;
                }

                AppendRow(
                    table,
                    {
                        Decimal(index),
                        std::string(ProgramTypeName(type)) + " (" + Hex(type) + ")",
                        ProgramFlags(flags),
                        Hex(fileOffset),
                        Hex(virtualAddress),
                        Hex(physicalAddress),
                        Hex(fileSize),
                        Hex(memorySize),
                        Hex(alignment)
                    },
                    options);
            }
            result.tables.push_back(std::move(table));
        }

        void ParseDynamicDependencies(
            const EndianReader& reader,
            const ElfHeaderView& header,
            const std::vector<ElfSectionView>& sections,
            const ScanOptions& options,
            BinaryScanResult& result,
            BinaryTable& dependencies)
        {
            const std::uint64_t minimumEntrySize = header.is64 ? 16U : 8U;
            for (std::size_t sectionIndex = 0; sectionIndex < sections.size(); ++sectionIndex)
            {
                const ElfSectionView& dynamicSection = sections[sectionIndex];
                if (dynamicSection.type != kSectionTypeDynamic)
                {
                    continue;
                }
                if (dynamicSection.link >= sections.size())
                {
                    AddDiagnostic(
                        result,
                        DiagnosticSeverity::Warning,
                        "elf.dynamic_string_link_invalid",
                        "A dynamic section references an invalid string table.");
                    continue;
                }

                const ElfSectionView& stringSection = sections[dynamicSection.link];
                const std::uint64_t entrySize =
                    dynamicSection.entrySize == 0 ? minimumEntrySize : dynamicSection.entrySize;
                if (entrySize < minimumEntrySize ||
                    !reader.contains(dynamicSection.offset, dynamicSection.size))
                {
                    AddDiagnosticAt(
                        result,
                        DiagnosticSeverity::Warning,
                        "elf.dynamic_range_invalid",
                        "A dynamic section is outside the file or has a short entry size.",
                        dynamicSection.offset);
                    continue;
                }

                const std::uint64_t count = std::min<std::uint64_t>(
                    dynamicSection.size / entrySize,
                    options.maxContainerEntries);
                for (std::uint64_t index = 0; index < count; ++index)
                {
                    const std::uint64_t offset =
                        dynamicSection.offset + index * entrySize;
                    std::uint64_t tag = 0;
                    std::uint64_t value = 0;
                    if (header.is64)
                    {
                        if (!reader.readU64(offset, tag) ||
                            !reader.readU64(offset + 8, value))
                        {
                            break;
                        }
                    }
                    else
                    {
                        std::uint32_t tag32 = 0;
                        std::uint32_t value32 = 0;
                        if (!reader.readU32(offset, tag32) ||
                            !reader.readU32(offset + 4, value32))
                        {
                            break;
                        }
                        tag = tag32;
                        value = value32;
                    }
                    if (tag == kDynamicNull)
                    {
                        break;
                    }
                    if (tag == kDynamicNeeded)
                    {
                        AppendRow(
                            dependencies,
                            {
                                Decimal(sectionIndex),
                                dynamicSection.name,
                                ReadSectionString(reader, stringSection, value, options)
                            },
                            options);
                    }
                }
            }
        }

        void ParseSymbols(
            const EndianReader& reader,
            const ElfHeaderView& header,
            const std::vector<ElfSectionView>& sections,
            const ScanOptions& options,
            BinaryScanResult& result,
            BinaryTable& symbols,
            BinaryTable& imports,
            BinaryTable& exports)
        {
            const std::uint64_t minimumEntrySize = header.is64 ? 24U : 16U;
            for (std::size_t sectionIndex = 0; sectionIndex < sections.size(); ++sectionIndex)
            {
                const ElfSectionView& symbolSection = sections[sectionIndex];
                if (symbolSection.type != kSectionTypeSymbolTable &&
                    symbolSection.type != kSectionTypeDynamicSymbols)
                {
                    continue;
                }
                if (symbolSection.link >= sections.size())
                {
                    AddDiagnostic(
                        result,
                        DiagnosticSeverity::Warning,
                        "elf.symbol_string_link_invalid",
                        "A symbol table references an invalid string table.");
                    continue;
                }
                const ElfSectionView& stringSection = sections[symbolSection.link];
                if (stringSection.type != kSectionTypeStringTable)
                {
                    AddDiagnostic(
                        result,
                        DiagnosticSeverity::Warning,
                        "elf.symbol_string_type_invalid",
                        "A symbol table link does not point to a string table.");
                }

                const std::uint64_t entrySize =
                    symbolSection.entrySize == 0 ? minimumEntrySize : symbolSection.entrySize;
                if (entrySize < minimumEntrySize ||
                    !reader.contains(symbolSection.offset, symbolSection.size))
                {
                    AddDiagnosticAt(
                        result,
                        DiagnosticSeverity::Warning,
                        "elf.symbol_range_invalid",
                        "A symbol table is outside the file or has a short entry size.",
                        symbolSection.offset);
                    continue;
                }

                const std::uint64_t rawCount = symbolSection.size / entrySize;
                const std::uint64_t count = std::min<std::uint64_t>(
                    rawCount,
                    options.maxContainerEntries);
                if (rawCount > count)
                {
                    AddDiagnostic(
                        result,
                        DiagnosticSeverity::Warning,
                        "elf.symbol_count_limited",
                        "A symbol table exceeded maxContainerEntries.");
                }

                for (std::uint64_t index = 0; index < count; ++index)
                {
                    const std::uint64_t offset =
                        symbolSection.offset + index * entrySize;
                    std::uint32_t nameOffset = 0;
                    std::uint8_t info = 0;
                    std::uint8_t other = 0;
                    std::uint16_t symbolSectionIndex = 0;
                    std::uint64_t value = 0;
                    std::uint64_t size = 0;

                    if (header.is64)
                    {
                        if (!reader.readU32(offset, nameOffset) ||
                            !reader.readU8(offset + 4, info) ||
                            !reader.readU8(offset + 5, other) ||
                            !reader.readU16(offset + 6, symbolSectionIndex) ||
                            !reader.readU64(offset + 8, value) ||
                            !reader.readU64(offset + 16, size))
                        {
                            break;
                        }
                    }
                    else
                    {
                        std::uint32_t value32 = 0;
                        std::uint32_t size32 = 0;
                        if (!reader.readU32(offset, nameOffset) ||
                            !reader.readU32(offset + 4, value32) ||
                            !reader.readU32(offset + 8, size32) ||
                            !reader.readU8(offset + 12, info) ||
                            !reader.readU8(offset + 13, other) ||
                            !reader.readU16(offset + 14, symbolSectionIndex))
                        {
                            break;
                        }
                        value = value32;
                        size = size32;
                    }

                    const std::string name =
                        ReadSectionString(reader, stringSection, nameOffset, options);
                    const std::uint8_t binding = static_cast<std::uint8_t>(info >> 4U);
                    const std::uint8_t type = static_cast<std::uint8_t>(info & 0x0FU);
                    const std::uint8_t visibility = static_cast<std::uint8_t>(other & 0x03U);
                    const std::string source = symbolSection.name.empty()
                        ? ("Section " + Decimal(sectionIndex))
                        : symbolSection.name;

                    AppendRow(
                        symbols,
                        {
                            source,
                            Decimal(index),
                            name,
                            SymbolBindingName(binding),
                            SymbolTypeName(type),
                            SymbolVisibilityName(visibility),
                            Hex(symbolSectionIndex),
                            Hex(value),
                            Hex(size)
                        },
                        options);

                    const bool externallyVisible = binding == 1 || binding == 2 || binding == 10;
                    if (!name.empty() && externallyVisible)
                    {
                        BinaryTable& classification =
                            symbolSectionIndex == kSectionIndexUndefined ? imports : exports;
                        AppendRow(
                            classification,
                            {
                                name,
                                SymbolBindingName(binding),
                                SymbolTypeName(type),
                                source,
                                Hex(value),
                                Hex(size)
                            },
                            options);
                    }
                }
            }
        }
    }

    bool ParseElf(
        const std::span<const std::uint8_t> bytes,
        const ScanOptions& options,
        BinaryScanResult& result)
    {
        result.recognized = true;
        if (bytes.size() < 16 ||
            bytes[0] != 0x7FU ||
            bytes[1] != 'E' ||
            bytes[2] != 'L' ||
            bytes[3] != 'F')
        {
            AddDiagnostic(
                result,
                DiagnosticSeverity::Error,
                "elf.magic_invalid",
                "ELF magic is invalid.");
            return false;
        }

        const std::uint8_t objectClass = bytes[4];
        const std::uint8_t dataEncoding = bytes[5];
        const bool is64 = objectClass == kElfClass64;
        if (objectClass != kElfClass32 && objectClass != kElfClass64)
        {
            AddDiagnosticAt(
                result,
                DiagnosticSeverity::Error,
                "elf.class_unsupported",
                "ELF class is neither ELF32 nor ELF64.",
                4);
            return false;
        }
        if (dataEncoding != kElfDataLittle && dataEncoding != kElfDataBig)
        {
            AddDiagnosticAt(
                result,
                DiagnosticSeverity::Error,
                "elf.byte_order_unsupported",
                "ELF data encoding is neither little-endian nor big-endian.",
                5);
            return false;
        }

        result.format = is64 ? BinaryFormat::Elf64 : BinaryFormat::Elf32;
        result.byteOrder = dataEncoding == kElfDataLittle
            ? ByteOrder::LittleEndian
            : ByteOrder::BigEndian;
        const EndianReader reader(bytes, result.byteOrder);
        const std::size_t minimumHeaderSize = is64 ? 64U : 52U;
        if (bytes.size() < minimumHeaderSize)
        {
            AddDiagnostic(
                result,
                DiagnosticSeverity::Error,
                "elf.header_truncated",
                "The ELF header is truncated.");
            return false;
        }

        ElfHeaderView header{};
        if (!ReadHeaderSafe(reader, is64, header))
        {
            AddDiagnostic(
                result,
                DiagnosticSeverity::Error,
                "elf.header_read_failed",
                "The ELF header could not be decoded.");
            return false;
        }
        if (header.headerSize < minimumHeaderSize)
        {
            AddDiagnosticAt(
                result,
                DiagnosticSeverity::Error,
                "elf.header_size_invalid",
                "ELF e_ehsize is smaller than the required header.",
                is64 ? 52 : 40);
            return false;
        }
        if (!ResolveExtendedCounts(reader, header))
        {
            AddDiagnostic(
                result,
                DiagnosticSeverity::Error,
                "elf.extended_counts_invalid",
                "ELF extended table counts could not be resolved.");
            return false;
        }
        if (header.programCount > options.maxContainerEntries ||
            header.sectionCount > options.maxContainerEntries)
        {
            AddDiagnostic(
                result,
                DiagnosticSeverity::Error,
                "elf.entry_count_excessive",
                "ELF table count exceeds maxContainerEntries.");
            return false;
        }

        const std::uint64_t minimumProgramEntrySize = is64 ? 56U : 32U;
        const std::uint64_t minimumSectionEntrySize = is64 ? 64U : 40U;
        if (!ValidateTableRange(
                reader,
                header.programOffset,
                header.programCount,
                header.programEntrySize,
                minimumProgramEntrySize))
        {
            AddDiagnosticAt(
                result,
                DiagnosticSeverity::Error,
                "elf.program_table_invalid",
                "ELF program header table is outside the file or has short entries.",
                header.programOffset);
            return false;
        }
        if (!ValidateTableRange(
                reader,
                header.sectionOffset,
                header.sectionCount,
                header.sectionEntrySize,
                minimumSectionEntrySize))
        {
            AddDiagnosticAt(
                result,
                DiagnosticSeverity::Error,
                "elf.section_table_invalid",
                "ELF section header table is outside the file or has short entries.",
                header.sectionOffset);
            return false;
        }
        if (header.sectionCount != 0 &&
            header.sectionNameIndex != 0 &&
            header.sectionNameIndex >= header.sectionCount)
        {
            AddDiagnostic(
                result,
                DiagnosticSeverity::Error,
                "elf.section_name_index_invalid",
                "ELF section name string table index is outside the section table.");
            return false;
        }

        AddField(result.summary, "Format", is64 ? "ELF64" : "ELF32");
        AddField(result.summary, "Byte Order", ByteOrderName(result.byteOrder));
        AddField(result.summary, "Architecture", ElfMachineName(header.machine));
        AddField(result.summary, "Object Type", ElfTypeName(header.type));
        AddField(result.summary, "Entry Point", Hex(header.entry));
        AddField(result.summary, "Program Headers", Decimal(header.programCount));
        AddField(result.summary, "Sections", Decimal(header.sectionCount));

        AddField(result.headers, "Class", is64 ? "ELFCLASS64 (2)" : "ELFCLASS32 (1)");
        AddField(result.headers, "Data Encoding", ByteOrderName(result.byteOrder));
        AddField(result.headers, "OS ABI", Decimal(bytes[7]));
        AddField(result.headers, "ABI Version", Decimal(bytes[8]));
        AddField(result.headers, "Type", std::string(ElfTypeName(header.type)) + " (" + Hex(header.type) + ")");
        AddField(result.headers, "Machine", std::string(ElfMachineName(header.machine)) + " (" + Hex(header.machine) + ")");
        AddField(result.headers, "Version", Hex(header.version));
        AddField(result.headers, "Entry", Hex(header.entry));
        AddField(result.headers, "Program Header Offset", Hex(header.programOffset));
        AddField(result.headers, "Section Header Offset", Hex(header.sectionOffset));
        AddField(result.headers, "Flags", Hex(header.flags));
        AddField(result.headers, "Header Size", Decimal(header.headerSize));
        AddField(result.headers, "Program Entry Size", Decimal(header.programEntrySize));
        AddField(result.headers, "Program Entry Count", Decimal(header.programCount));
        AddField(result.headers, "Section Entry Size", Decimal(header.sectionEntrySize));
        AddField(result.headers, "Section Entry Count", Decimal(header.sectionCount));
        AddField(result.headers, "Section Name Index", Decimal(header.sectionNameIndex));

        ParseProgramHeaders(reader, header, options, result);

        std::vector<ElfSectionView> sections;
        sections.reserve(static_cast<std::size_t>(header.sectionCount));
        for (std::uint64_t index = 0; index < header.sectionCount; ++index)
        {
            ElfSectionView section{};
            const std::uint64_t offset =
                header.sectionOffset + index * header.sectionEntrySize;
            if (!ReadSection(reader, is64, offset, section))
            {
                AddDiagnosticAt(
                    result,
                    DiagnosticSeverity::Error,
                    "elf.section_read_failed",
                    "An ELF section header could not be decoded.",
                    offset);
                return false;
            }
            sections.push_back(section);
        }

        if (header.sectionNameIndex < sections.size())
        {
            const ElfSectionView& nameSection = sections[
                static_cast<std::size_t>(header.sectionNameIndex)];
            for (ElfSectionView& section : sections)
            {
                section.name = ReadSectionString(
                    reader,
                    nameSection,
                    section.nameOffset,
                    options);
            }
        }

        BinaryTable sectionTable{
            "sections",
            "Sections",
            { "Index", "Name", "Type", "Flags", "Address", "File Offset",
              "Size", "Link", "Info", "Alignment", "Entry Size" },
            {},
            false
        };
        for (std::size_t index = 0; index < sections.size(); ++index)
        {
            const ElfSectionView& section = sections[index];
            AppendRow(
                sectionTable,
                {
                    Decimal(index),
                    section.name,
                    std::string(SectionTypeName(section.type)) + " (" + Hex(section.type) + ")",
                    SectionFlags(section.flags) + " (" + Hex(section.flags) + ")",
                    Hex(section.address),
                    Hex(section.offset),
                    Hex(section.size),
                    Decimal(section.link),
                    Decimal(section.info),
                    Hex(section.alignment),
                    Hex(section.entrySize)
                },
                options);
        }
        result.tables.push_back(std::move(sectionTable));

        BinaryTable dependencies{
            "dynamic_dependencies",
            "Dynamic Dependencies",
            { "Section Index", "Section", "Library" },
            {},
            false
        };
        BinaryTable symbols{
            "symbols",
            "Symbols",
            { "Source", "Index", "Name", "Binding", "Type", "Visibility",
              "Section Index", "Value", "Size" },
            {},
            false
        };
        BinaryTable imports{
            "imports",
            "Imported Symbols",
            { "Name", "Binding", "Type", "Source", "Value", "Size" },
            {},
            false
        };
        BinaryTable exports{
            "exports",
            "Exported Symbols",
            { "Name", "Binding", "Type", "Source", "Value", "Size" },
            {},
            false
        };

        ParseDynamicDependencies(
            reader,
            header,
            sections,
            options,
            result,
            dependencies);
        ParseSymbols(
            reader,
            header,
            sections,
            options,
            result,
            symbols,
            imports,
            exports);

        result.tables.push_back(std::move(dependencies));
        result.tables.push_back(std::move(symbols));
        result.tables.push_back(std::move(imports));
        result.tables.push_back(std::move(exports));
        result.success = true;
        return true;
    }
}
