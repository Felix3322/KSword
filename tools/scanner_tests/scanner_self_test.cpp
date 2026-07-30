#include "../../Ksword5.1/Ksword5.1/ksword/scanner/atomic_file_patch.h"
#include "../../Ksword5.1/Ksword5.1/ksword/scanner/binary_scanner.h"

// ============================================================
// tools/scanner_tests/scanner_self_test.cpp
// Purpose:
// - Exercise a real KSword PE plus synthetic cross-endian ELF/Mach-O inputs.
// - Verify recognized malformed files fail without an out-of-bounds walk.
// - Verify atomic patch backup, compare-before-write, and range rejection.
//
// The test has no framework dependency and returns nonzero on any failure.
// Pass a current KSword executable path as argv[1].
// ============================================================

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>

#include <algorithm>
#include <cstdint>
#include <iostream>
#include <span>
#include <string>
#include <vector>

namespace
{
    int gFailureCount = 0;

    void Expect(const bool condition, const char* message)
    {
        if (condition)
        {
            std::cout << "[PASS] " << message << '\n';
            return;
        }
        ++gFailureCount;
        std::cerr << "[FAIL] " << message << '\n';
    }

    void Put16(
        std::vector<std::uint8_t>& bytes,
        const std::size_t offset,
        const std::uint16_t value,
        const ks::scanner::ByteOrder byteOrder)
    {
        if (byteOrder == ks::scanner::ByteOrder::LittleEndian)
        {
            bytes[offset] = static_cast<std::uint8_t>(value);
            bytes[offset + 1] = static_cast<std::uint8_t>(value >> 8U);
        }
        else
        {
            bytes[offset] = static_cast<std::uint8_t>(value >> 8U);
            bytes[offset + 1] = static_cast<std::uint8_t>(value);
        }
    }

    void Put32(
        std::vector<std::uint8_t>& bytes,
        const std::size_t offset,
        const std::uint32_t value,
        const ks::scanner::ByteOrder byteOrder)
    {
        for (std::size_t index = 0; index < 4; ++index)
        {
            const std::size_t shiftIndex =
                byteOrder == ks::scanner::ByteOrder::LittleEndian
                    ? index
                    : 3U - index;
            bytes[offset + index] =
                static_cast<std::uint8_t>(value >> (shiftIndex * 8U));
        }
    }

    void Put64(
        std::vector<std::uint8_t>& bytes,
        const std::size_t offset,
        const std::uint64_t value,
        const ks::scanner::ByteOrder byteOrder)
    {
        for (std::size_t index = 0; index < 8; ++index)
        {
            const std::size_t shiftIndex =
                byteOrder == ks::scanner::ByteOrder::LittleEndian
                    ? index
                    : 7U - index;
            bytes[offset + index] =
                static_cast<std::uint8_t>(value >> (shiftIndex * 8U));
        }
    }

    std::vector<std::uint8_t> MakeElf(
        const bool is64,
        const ks::scanner::ByteOrder byteOrder)
    {
        const std::size_t headerSize = is64 ? 64U : 52U;
        std::vector<std::uint8_t> bytes(headerSize, 0);
        bytes[0] = 0x7F;
        bytes[1] = 'E';
        bytes[2] = 'L';
        bytes[3] = 'F';
        bytes[4] = is64 ? 2 : 1;
        bytes[5] = byteOrder == ks::scanner::ByteOrder::LittleEndian ? 1 : 2;
        bytes[6] = 1;
        bytes[7] = 0;
        Put16(bytes, 16, 2, byteOrder);
        Put16(bytes, 18, is64 ? 62 : 3, byteOrder);
        Put32(bytes, 20, 1, byteOrder);
        if (is64)
        {
            Put64(bytes, 24, 0x401000, byteOrder);
            Put64(bytes, 32, 0, byteOrder);
            Put64(bytes, 40, 0, byteOrder);
            Put32(bytes, 48, 0, byteOrder);
            Put16(bytes, 52, 64, byteOrder);
            Put16(bytes, 54, 56, byteOrder);
            Put16(bytes, 56, 0, byteOrder);
            Put16(bytes, 58, 64, byteOrder);
            Put16(bytes, 60, 0, byteOrder);
            Put16(bytes, 62, 0, byteOrder);
        }
        else
        {
            Put32(bytes, 24, 0x8048000, byteOrder);
            Put32(bytes, 28, 0, byteOrder);
            Put32(bytes, 32, 0, byteOrder);
            Put32(bytes, 36, 0, byteOrder);
            Put16(bytes, 40, 52, byteOrder);
            Put16(bytes, 42, 32, byteOrder);
            Put16(bytes, 44, 0, byteOrder);
            Put16(bytes, 46, 40, byteOrder);
            Put16(bytes, 48, 0, byteOrder);
            Put16(bytes, 50, 0, byteOrder);
        }
        return bytes;
    }

    std::vector<std::uint8_t> MakeMachO(
        const bool is64,
        const ks::scanner::ByteOrder byteOrder)
    {
        std::vector<std::uint8_t> bytes(is64 ? 32U : 28U, 0);
        if (is64 && byteOrder == ks::scanner::ByteOrder::LittleEndian)
        {
            bytes[0] = 0xCF; bytes[1] = 0xFA; bytes[2] = 0xED; bytes[3] = 0xFE;
        }
        else if (is64)
        {
            bytes[0] = 0xFE; bytes[1] = 0xED; bytes[2] = 0xFA; bytes[3] = 0xCF;
        }
        else if (byteOrder == ks::scanner::ByteOrder::LittleEndian)
        {
            bytes[0] = 0xCE; bytes[1] = 0xFA; bytes[2] = 0xED; bytes[3] = 0xFE;
        }
        else
        {
            bytes[0] = 0xFE; bytes[1] = 0xED; bytes[2] = 0xFA; bytes[3] = 0xCE;
        }
        Put32(bytes, 4, is64 ? 0x01000007U : 7U, byteOrder);
        Put32(bytes, 8, 3, byteOrder);
        Put32(bytes, 12, 2, byteOrder);
        Put32(bytes, 16, 0, byteOrder);
        Put32(bytes, 20, 0, byteOrder);
        Put32(bytes, 24, 0, byteOrder);
        if (is64)
        {
            Put32(bytes, 28, 0, byteOrder);
        }
        return bytes;
    }

    std::vector<std::uint8_t> MakeUniversalMachO()
    {
        constexpr std::size_t firstSliceOffset = 0x80;
        constexpr std::size_t secondSliceOffset = 0xC0;
        const std::vector<std::uint8_t> firstSlice =
            MakeMachO(false, ks::scanner::ByteOrder::LittleEndian);
        const std::vector<std::uint8_t> secondSlice =
            MakeMachO(true, ks::scanner::ByteOrder::BigEndian);
        std::vector<std::uint8_t> bytes(
            secondSliceOffset + secondSlice.size(),
            0);
        bytes[0] = 0xCA;
        bytes[1] = 0xFE;
        bytes[2] = 0xBA;
        bytes[3] = 0xBE;
        Put32(bytes, 4, 2, ks::scanner::ByteOrder::BigEndian);

        Put32(bytes, 8, 7, ks::scanner::ByteOrder::BigEndian);
        Put32(bytes, 12, 3, ks::scanner::ByteOrder::BigEndian);
        Put32(bytes, 16, firstSliceOffset, ks::scanner::ByteOrder::BigEndian);
        Put32(bytes, 20, static_cast<std::uint32_t>(firstSlice.size()), ks::scanner::ByteOrder::BigEndian);
        Put32(bytes, 24, 2, ks::scanner::ByteOrder::BigEndian);

        Put32(bytes, 28, 0x01000007U, ks::scanner::ByteOrder::BigEndian);
        Put32(bytes, 32, 3, ks::scanner::ByteOrder::BigEndian);
        Put32(bytes, 36, secondSliceOffset, ks::scanner::ByteOrder::BigEndian);
        Put32(bytes, 40, static_cast<std::uint32_t>(secondSlice.size()), ks::scanner::ByteOrder::BigEndian);
        Put32(bytes, 44, 3, ks::scanner::ByteOrder::BigEndian);

        std::copy(firstSlice.begin(), firstSlice.end(), bytes.begin() + firstSliceOffset);
        std::copy(secondSlice.begin(), secondSlice.end(), bytes.begin() + secondSliceOffset);
        return bytes;
    }

    bool WriteBytes(
        const std::wstring& path,
        const std::vector<std::uint8_t>& bytes)
    {
        HANDLE handle = ::CreateFileW(
            path.c_str(),
            GENERIC_WRITE,
            0,
            nullptr,
            CREATE_ALWAYS,
            FILE_ATTRIBUTE_NORMAL,
            nullptr);
        if (handle == INVALID_HANDLE_VALUE)
        {
            return false;
        }
        std::size_t writtenTotal = 0;
        while (writtenTotal < bytes.size())
        {
            const DWORD requested = static_cast<DWORD>(std::min<std::size_t>(
                bytes.size() - writtenTotal,
                1024U * 1024U));
            DWORD written = 0;
            if (::WriteFile(
                    handle,
                    bytes.data() + writtenTotal,
                    requested,
                    &written,
                    nullptr) == FALSE ||
                written == 0)
            {
                ::CloseHandle(handle);
                return false;
            }
            writtenTotal += written;
        }
        ::CloseHandle(handle);
        return true;
    }

    std::vector<std::uint8_t> ReadBytes(const std::wstring& path)
    {
        HANDLE handle = ::CreateFileW(
            path.c_str(),
            GENERIC_READ,
            FILE_SHARE_READ,
            nullptr,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            nullptr);
        if (handle == INVALID_HANDLE_VALUE)
        {
            return {};
        }
        LARGE_INTEGER size{};
        if (::GetFileSizeEx(handle, &size) == FALSE ||
            size.QuadPart < 0 ||
            static_cast<std::uint64_t>(size.QuadPart) >
                static_cast<std::uint64_t>(SIZE_MAX))
        {
            ::CloseHandle(handle);
            return {};
        }
        std::vector<std::uint8_t> bytes(static_cast<std::size_t>(size.QuadPart));
        DWORD read = 0;
        const bool success = bytes.empty() ||
            (::ReadFile(
                handle,
                bytes.data(),
                static_cast<DWORD>(bytes.size()),
                &read,
                nullptr) != FALSE &&
             read == bytes.size());
        ::CloseHandle(handle);
        return success ? bytes : std::vector<std::uint8_t>{};
    }

    const ks::scanner::BinaryTable* FindTable(
        const ks::scanner::BinaryScanResult& result,
        const std::string& id)
    {
        const auto iterator = std::find_if(
            result.tables.begin(),
            result.tables.end(),
            [&id](const ks::scanner::BinaryTable& table)
            {
                return table.id == id;
            });
        return iterator == result.tables.end() ? nullptr : &*iterator;
    }

    void ScanSynthetic(
        const std::wstring& path,
        const std::vector<std::uint8_t>& bytes,
        const ks::scanner::BinaryFormat expectedFormat,
        const ks::scanner::ByteOrder expectedOrder,
        const char* label)
    {
        Expect(WriteBytes(path, bytes), "write synthetic input");
        const ks::scanner::BinaryScanResult result =
            ks::scanner::ScanBinaryFile(path);
        Expect(result.recognized, label);
        Expect(result.success, "synthetic input parses successfully");
        Expect(result.format == expectedFormat, "synthetic format classification");
        Expect(result.byteOrder == expectedOrder, "synthetic byte-order classification");
        Expect(FindTable(result, "sections") != nullptr ||
            FindTable(result, "slices") != nullptr,
            "synthetic result exposes sections or slices table");
    }

    std::wstring CreateTestDirectory()
    {
        wchar_t temporaryRoot[MAX_PATH] = {};
        if (::GetTempPathW(MAX_PATH, temporaryRoot) == 0)
        {
            return {};
        }
        const std::wstring path =
            std::wstring(temporaryRoot) +
            L"ksword-scanner-self-test-" +
            std::to_wstring(::GetCurrentProcessId()) +
            L"-" +
            std::to_wstring(::GetTickCount64());
        return ::CreateDirectoryW(path.c_str(), nullptr) != FALSE
            ? path
            : std::wstring();
    }
}

int wmain(const int argc, wchar_t** argv)
{
    const std::wstring testDirectory = CreateTestDirectory();
    Expect(!testDirectory.empty(), "create isolated test directory");
    if (testDirectory.empty())
    {
        return 1;
    }
    const auto pathFor = [&testDirectory](const wchar_t* name)
    {
        return testDirectory + L"\\" + name;
    };

    if (argc >= 2)
    {
        const ks::scanner::BinaryScanResult pe =
            ks::scanner::ScanBinaryFile(argv[1]);
        Expect(pe.recognized, "current KSword executable recognized");
        Expect(pe.success, "current KSword executable parsed");
        Expect(
            pe.format == ks::scanner::BinaryFormat::Pe32Plus ||
                pe.format == ks::scanner::BinaryFormat::Pe32,
            "current KSword executable classified as PE");
        Expect(FindTable(pe, "sections") != nullptr, "PE exposes sections table");
        Expect(FindTable(pe, "imports") != nullptr, "PE exposes imports table");
        Expect(FindTable(pe, "exports") != nullptr, "PE exposes exports table");

        ks::scanner::ScanOptions boundedOptions{};
        boundedOptions.maxRowsPerTable = 1;
        const ks::scanner::BinaryScanResult boundedPe =
            ks::scanner::ScanBinaryFile(argv[1], boundedOptions);
        const bool everyPeTableBounded = std::all_of(
            boundedPe.tables.begin(),
            boundedPe.tables.end(),
            [](const ks::scanner::BinaryTable& table)
            {
                return table.rows.size() <= 1;
            });
        Expect(boundedPe.success && everyPeTableBounded, "per-table row limit is enforced");
    }
    else
    {
        ++gFailureCount;
        std::cerr << "[FAIL] pass a current KSword executable path as argv[1]\n";
    }

    ScanSynthetic(
        pathFor(L"elf32le.bin"),
        MakeElf(false, ks::scanner::ByteOrder::LittleEndian),
        ks::scanner::BinaryFormat::Elf32,
        ks::scanner::ByteOrder::LittleEndian,
        "ELF32 little-endian recognized");
    ScanSynthetic(
        pathFor(L"elf32be.bin"),
        MakeElf(false, ks::scanner::ByteOrder::BigEndian),
        ks::scanner::BinaryFormat::Elf32,
        ks::scanner::ByteOrder::BigEndian,
        "ELF32 big-endian recognized");
    ScanSynthetic(
        pathFor(L"elf64le.bin"),
        MakeElf(true, ks::scanner::ByteOrder::LittleEndian),
        ks::scanner::BinaryFormat::Elf64,
        ks::scanner::ByteOrder::LittleEndian,
        "ELF64 little-endian recognized");
    ScanSynthetic(
        pathFor(L"elf64be.bin"),
        MakeElf(true, ks::scanner::ByteOrder::BigEndian),
        ks::scanner::BinaryFormat::Elf64,
        ks::scanner::ByteOrder::BigEndian,
        "ELF64 big-endian recognized");

    ScanSynthetic(
        pathFor(L"macho32le.bin"),
        MakeMachO(false, ks::scanner::ByteOrder::LittleEndian),
        ks::scanner::BinaryFormat::MachO32,
        ks::scanner::ByteOrder::LittleEndian,
        "Mach-O 32 little-endian recognized");
    ScanSynthetic(
        pathFor(L"macho32be.bin"),
        MakeMachO(false, ks::scanner::ByteOrder::BigEndian),
        ks::scanner::BinaryFormat::MachO32,
        ks::scanner::ByteOrder::BigEndian,
        "Mach-O 32 big-endian recognized");
    ScanSynthetic(
        pathFor(L"macho64le.bin"),
        MakeMachO(true, ks::scanner::ByteOrder::LittleEndian),
        ks::scanner::BinaryFormat::MachO64,
        ks::scanner::ByteOrder::LittleEndian,
        "Mach-O 64 little-endian recognized");
    ScanSynthetic(
        pathFor(L"macho64be.bin"),
        MakeMachO(true, ks::scanner::ByteOrder::BigEndian),
        ks::scanner::BinaryFormat::MachO64,
        ks::scanner::ByteOrder::BigEndian,
        "Mach-O 64 big-endian recognized");
    ScanSynthetic(
        pathFor(L"universal.bin"),
        MakeUniversalMachO(),
        ks::scanner::BinaryFormat::MachOUniversal,
        ks::scanner::ByteOrder::BigEndian,
        "Universal Mach-O recognized");
    const ks::scanner::BinaryScanResult universal =
        ks::scanner::ScanBinaryFile(pathFor(L"universal.bin"));
    const ks::scanner::BinaryTable* slices = FindTable(universal, "slices");
    Expect(slices != nullptr && slices->rows.size() == 2, "universal file lists both slices");

    const std::wstring truncatedElfPath = pathFor(L"truncated-elf.bin");
    WriteBytes(truncatedElfPath, { 0x7F, 'E', 'L', 'F', 2, 1 });
    const ks::scanner::BinaryScanResult truncatedElf =
        ks::scanner::ScanBinaryFile(truncatedElfPath);
    Expect(truncatedElf.recognized && !truncatedElf.success, "truncated ELF rejected safely");

    const std::wstring truncatedMachPath = pathFor(L"truncated-macho.bin");
    WriteBytes(truncatedMachPath, { 0xCF, 0xFA, 0xED, 0xFE });
    const ks::scanner::BinaryScanResult truncatedMach =
        ks::scanner::ScanBinaryFile(truncatedMachPath);
    Expect(truncatedMach.recognized && !truncatedMach.success, "truncated Mach-O rejected safely");

    const std::wstring truncatedPePath = pathFor(L"truncated-pe.bin");
    WriteBytes(truncatedPePath, { 'M', 'Z' });
    const ks::scanner::BinaryScanResult truncatedPe =
        ks::scanner::ScanBinaryFile(truncatedPePath);
    Expect(truncatedPe.recognized && !truncatedPe.success, "truncated PE rejected safely");

    std::vector<std::uint8_t> excessiveElf =
        MakeElf(true, ks::scanner::ByteOrder::LittleEndian);
    Put16(excessiveElf, 56, 0xFFFF, ks::scanner::ByteOrder::LittleEndian);
    const std::wstring excessiveElfPath = pathFor(L"excessive-elf.bin");
    WriteBytes(excessiveElfPath, excessiveElf);
    const ks::scanner::BinaryScanResult excessiveElfResult =
        ks::scanner::ScanBinaryFile(excessiveElfPath);
    Expect(
        excessiveElfResult.recognized && !excessiveElfResult.success,
        "unresolvable ELF extended count rejected safely");

    std::vector<std::uint8_t> excessiveMach =
        MakeMachO(true, ks::scanner::ByteOrder::LittleEndian);
    Put32(excessiveMach, 16, 0xFFFFFFFFU, ks::scanner::ByteOrder::LittleEndian);
    const std::wstring excessiveMachPath = pathFor(L"excessive-macho.bin");
    WriteBytes(excessiveMachPath, excessiveMach);
    const ks::scanner::BinaryScanResult excessiveMachResult =
        ks::scanner::ScanBinaryFile(excessiveMachPath);
    Expect(
        excessiveMachResult.recognized && !excessiveMachResult.success,
        "excessive Mach-O command count rejected safely");

    if (argc >= 3)
    {
        const ks::scanner::BinaryScanResult realElf =
            ks::scanner::ScanBinaryFile(argv[2]);
        const ks::scanner::BinaryTable* programHeaders =
            FindTable(realElf, "program_headers");
        const ks::scanner::BinaryTable* elfSections =
            FindTable(realElf, "sections");
        const ks::scanner::BinaryTable* dependencies =
            FindTable(realElf, "dynamic_dependencies");
        const ks::scanner::BinaryTable* symbols =
            FindTable(realElf, "symbols");
        Expect(realElf.success, "real ELF binary parses");
        Expect(
            realElf.format == ks::scanner::BinaryFormat::Elf64 ||
                realElf.format == ks::scanner::BinaryFormat::Elf32,
            "real ELF format classified");
        Expect(programHeaders != nullptr && !programHeaders->rows.empty(), "real ELF program headers populated");
        Expect(elfSections != nullptr && !elfSections->rows.empty(), "real ELF sections populated");
        Expect(dependencies != nullptr && !dependencies->rows.empty(), "real ELF dependencies populated");
        Expect(symbols != nullptr && !symbols->rows.empty(), "real ELF symbols populated");
    }

    if (argc >= 4)
    {
        const ks::scanner::BinaryScanResult realMach =
            ks::scanner::ScanBinaryFile(argv[3]);
        const ks::scanner::BinaryTable* commands =
            FindTable(realMach, "load_commands");
        const ks::scanner::BinaryTable* machSections =
            FindTable(realMach, "sections");
        const ks::scanner::BinaryTable* symbols =
            FindTable(realMach, "symbols");
        const ks::scanner::BinaryTable* imports =
            FindTable(realMach, "imports");
        const ks::scanner::BinaryTable* exports =
            FindTable(realMach, "exports");
        Expect(realMach.success, "real Mach-O object parses");
        Expect(
            realMach.format == ks::scanner::BinaryFormat::MachO64 ||
                realMach.format == ks::scanner::BinaryFormat::MachO32,
            "real Mach-O format classified");
        Expect(commands != nullptr && !commands->rows.empty(), "real Mach-O load commands populated");
        Expect(machSections != nullptr && !machSections->rows.empty(), "real Mach-O sections populated");
        Expect(symbols != nullptr && !symbols->rows.empty(), "real Mach-O symbols populated");
        Expect(imports != nullptr && !imports->rows.empty(), "real Mach-O imports populated");
        Expect(exports != nullptr && !exports->rows.empty(), "real Mach-O exports populated");
    }

    const std::wstring patchPath = pathFor(L"patch-target.bin");
    const std::wstring backupPath = pathFor(L"patch-target.backup.bin");
    const std::vector<std::uint8_t> original{ 0, 1, 2, 3, 4, 5, 6, 7 };
    Expect(WriteBytes(patchPath, original), "write atomic patch target");
    ks::scanner::AtomicPatchOptions patchOptions{};
    patchOptions.backupPath = backupPath;
    patchOptions.expectedBytes = { 2, 3 };
    const ks::scanner::AtomicPatchResult patch =
        ks::scanner::PatchFileAtOffsetAtomic(
            patchPath,
            2,
            { 0xAA, 0xBB },
            patchOptions);
    Expect(patch.success && patch.changed, "atomic patch commits");
    Expect(
        ReadBytes(patchPath) == std::vector<std::uint8_t>({ 0, 1, 0xAA, 0xBB, 4, 5, 6, 7 }),
        "atomic patch modifies only selected range");
    Expect(ReadBytes(backupPath) == original, "atomic patch preserves original backup");

    ks::scanner::AtomicPatchOptions noBackupOptions{};
    noBackupOptions.createBackup = false;
    noBackupOptions.expectedBytes = { 4, 5 };
    const ks::scanner::AtomicPatchResult noBackup =
        ks::scanner::PatchFileAtOffsetAtomic(
            patchPath,
            4,
            { 0xCC, 0xDD },
            noBackupOptions);
    Expect(noBackup.success && noBackup.changed, "ReplaceFileW commits with a null backup path");
    Expect(
        ReadBytes(patchPath) == std::vector<std::uint8_t>({ 0, 1, 0xAA, 0xBB, 0xCC, 0xDD, 6, 7 }),
        "no-backup atomic patch preserves unrelated bytes");

    ks::scanner::AtomicPatchOptions staleOptions{};
    staleOptions.createBackup = false;
    staleOptions.expectedBytes = { 2, 3 };
    const ks::scanner::AtomicPatchResult stale =
        ks::scanner::PatchFileAtOffsetAtomic(
            patchPath,
            2,
            { 9, 9 },
            staleOptions);
    Expect(!stale.success && !stale.changed, "compare-before-write rejects stale bytes");
    Expect(
        ReadBytes(patchPath) == std::vector<std::uint8_t>({ 0, 1, 0xAA, 0xBB, 0xCC, 0xDD, 6, 7 }),
        "stale comparison leaves file unchanged");

    const ks::scanner::AtomicPatchResult outOfBounds =
        ks::scanner::PatchFileAtOffsetAtomic(
            patchPath,
            7,
            { 1, 2 },
            staleOptions);
    Expect(!outOfBounds.success, "out-of-bounds patch rejected");

    const std::wstring lockedPath = pathFor(L"locked-target.bin");
    const std::vector<std::uint8_t> lockedOriginal{ 1, 2, 3, 4 };
    WriteBytes(lockedPath, lockedOriginal);
    HANDLE competingWriter = ::CreateFileW(
        lockedPath.c_str(),
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        nullptr);
    Expect(competingWriter != INVALID_HANDLE_VALUE, "open competing writer");
    const ks::scanner::AtomicPatchResult lockedPatch =
        ks::scanner::PatchFileAtOffsetAtomic(
            lockedPath,
            1,
            { 9 },
            staleOptions);
    Expect(!lockedPatch.success, "active competing writer blocks atomic patch");
    if (competingWriter != INVALID_HANDLE_VALUE)
    {
        ::CloseHandle(competingWriter);
    }
    Expect(ReadBytes(lockedPath) == lockedOriginal, "writer conflict leaves target unchanged");

    const std::wstring linkPath = pathFor(L"reparse-target-link.bin");
    const DWORD symbolicLinkFlags = 0x2U; // SYMBOLIC_LINK_FLAG_ALLOW_UNPRIVILEGED_CREATE
    if (::CreateSymbolicLinkW(linkPath.c_str(), patchPath.c_str(), symbolicLinkFlags) != FALSE)
    {
        const std::vector<std::uint8_t> beforeLinkAttempt = ReadBytes(patchPath);
        const ks::scanner::AtomicPatchResult linkPatch =
            ks::scanner::PatchFileAtOffsetAtomic(
                linkPath,
                0,
                { 9 },
                staleOptions);
        Expect(!linkPatch.success, "reparse-point target rejected");
        Expect(ReadBytes(patchPath) == beforeLinkAttempt, "reparse rejection leaves destination unchanged");
        ::DeleteFileW(linkPath.c_str());
    }
    else
    {
        std::cout << "[SKIP] symbolic-link creation unavailable; handle-level reparse check compiled\n";
    }

    const wchar_t* generatedFiles[] = {
        L"elf32le.bin", L"elf32be.bin", L"elf64le.bin", L"elf64be.bin",
        L"macho32le.bin", L"macho32be.bin", L"macho64le.bin", L"macho64be.bin",
        L"universal.bin", L"truncated-elf.bin", L"truncated-macho.bin",
        L"truncated-pe.bin", L"excessive-elf.bin", L"excessive-macho.bin",
        L"patch-target.bin", L"patch-target.backup.bin", L"locked-target.bin"
    };
    for (const wchar_t* fileName : generatedFiles)
    {
        ::DeleteFileW(pathFor(fileName).c_str());
    }
    ::RemoveDirectoryW(testDirectory.c_str());

    if (gFailureCount != 0)
    {
        std::cerr << gFailureCount << " scanner self-test assertion(s) failed.\n";
        return 1;
    }
    std::cout << "All scanner self-tests passed.\n";
    return 0;
}
