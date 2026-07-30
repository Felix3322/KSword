#pragma once

// ============================================================
// ksword/scanner/binary_scanner.h
// Namespace: ks::scanner
// Purpose:
// - Define a Qt-free, format-neutral model for binary inspection.
// - Scan PE32/PE32+, ELF32/ELF64, thin Mach-O, and universal Mach-O.
// - Return bounded key/value and tabular data that UI, CLI, or tests can render.
//
// Security boundary:
// - Callers provide limits through ScanOptions.
// - Parsers never return borrowed pointers into the input file.
// - File loading denies new writers/deletes and verifies a second full read before
//   parsing, rejecting mixed snapshots instead of silently accepting a short read.
// - A writable mapping created before the scanner opens the file remains an OS
//   boundary; callers should rescan files that are actively mapped by another tool.
// - A recognized but malformed file returns recognized=true, success=false.
// ============================================================

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace ks::scanner
{
    // BinaryFormat identifies the exact container/class combination discovered
    // from the on-disk magic and format header.
    enum class BinaryFormat
    {
        Unknown = 0,
        Pe32,
        Pe32Plus,
        Elf32,
        Elf64,
        MachO32,
        MachO64,
        MachOUniversal
    };

    // ByteOrder describes how multi-byte fields in the selected object are stored.
    // Universal Mach-O files report the byte order of the fat header itself.
    enum class ByteOrder
    {
        Unknown = 0,
        LittleEndian,
        BigEndian
    };

    // DiagnosticSeverity lets frontends distinguish recoverable truncation from a
    // fatal parse rejection without interpreting localized text.
    enum class DiagnosticSeverity
    {
        Information = 0,
        Warning,
        Error
    };

    // BinaryField is used for summary and header key/value collections.
    struct BinaryField
    {
        std::string name;
        std::string value;
    };

    // BinaryTable is a format-neutral rectangular result set.
    // Every row is normalized to columns.size() cells by the parser.
    struct BinaryTable
    {
        std::string id;                         // Stable ASCII identifier for callers.
        std::string title;                      // Human-readable English title.
        std::vector<std::string> columns;
        std::vector<std::vector<std::string>> rows;
        bool truncated = false;                // True when ScanOptions.maxRowsPerTable was reached.
    };

    // BinaryDiagnostic records parser observations with an optional byte offset.
    // hasOffset=false is used for whole-file or adapter errors.
    struct BinaryDiagnostic
    {
        DiagnosticSeverity severity = DiagnosticSeverity::Information;
        std::string code;                       // Stable machine-readable identifier.
        std::string message;
        bool hasOffset = false;
        std::uint64_t offset = 0;
    };

    // ScanOptions bounds memory usage, entry walks, and strings from hostile files.
    // Values are intentionally conservative for an interactive desktop application.
    struct ScanOptions
    {
        std::uint64_t maxFileBytes = 512ULL * 1024ULL * 1024ULL;
        std::size_t maxRowsPerTable = 10000;
        std::size_t maxStringBytes = 4096;
        std::size_t maxContainerEntries = 65536;
    };

    // BinaryScanResult is the complete scanner response.
    // recognized says the magic is supported; success says its required header and
    // primary table layout passed validation. Warnings can coexist with success.
    struct BinaryScanResult
    {
        bool recognized = false;
        bool success = false;
        BinaryFormat format = BinaryFormat::Unknown;
        ByteOrder byteOrder = ByteOrder::Unknown;
        std::uint64_t fileSize = 0;
        std::vector<BinaryField> summary;
        std::vector<BinaryField> headers;
        std::vector<BinaryTable> tables;
        std::vector<BinaryDiagnostic> diagnostics;
    };

    // ScanBinaryFile loads and scans one ordinary file.
    // PE files reuse ks::file::AnalyzePeBytes over the same bounded snapshot for
    // canonical validation, sections, and imports; the scanner adds only
    // format-neutral adaptation and structured exports.
    BinaryScanResult ScanBinaryFile(
        const std::wstring& filePath,
        const ScanOptions& options = ScanOptions{});

    // FormatName and ByteOrderName provide stable ASCII labels for UI/CLI output.
    const char* FormatName(BinaryFormat format);
    const char* ByteOrderName(ByteOrder byteOrder);
}
