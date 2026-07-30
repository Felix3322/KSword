#pragma once

// ============================================================
// ksword/scanner/atomic_file_patch.h
// Namespace: ks::scanner
// Purpose:
// - Apply a bounded same-size byte patch to an ordinary file.
// - Write a complete sibling temporary file, flush it, and replace atomically.
// - Optionally retain the original as a backup through ReplaceFileW.
//
// This helper deliberately does not insert/delete bytes. Offset writes preserve
// the original file size, which keeps binary structure edits explicit and bounded.
//
// Concurrency guarantee:
// - The source is opened without write/delete sharing and remains locked through
//   temporary-file FlushFileBuffers and a final identity/full-content verification.
// - The full comparison detects changes made during the copy by ordinary writers
//   and most writable mappings that were created before the source lock.
// - ReplaceFileW requires that lock to be released before commit, so Win32 offers
//   no compare-and-swap guarantee for the tiny close-to-replace path window.
// - A pre-existing writable mapping can still change an already-verified page in
//   that final window; callers must rescan after a successful high-risk edit.
// - Callers editing adversarially mutable paths should also use expectedBytes and
//   treat sharing/identity failures as a request to rescan before retrying.
// ============================================================

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace ks::scanner
{
    struct AtomicPatchOptions
    {
        std::uint64_t maxFileBytes = 512ULL * 1024ULL * 1024ULL;
        std::size_t maxPatchBytes = 16ULL * 1024ULL * 1024ULL;
        bool createBackup = true;
        bool overwriteBackup = false;
        bool rejectReparsePoints = true;
        std::wstring backupPath; // Empty means "<target>.ksword.bak".
        std::vector<std::uint8_t> expectedBytes; // Empty disables compare-before-write.
    };

    struct AtomicPatchResult
    {
        bool success = false;
        bool changed = false;
        bool recoveredAfterReplaceFailure = false;
        std::uint32_t systemError = 0;
        std::wstring backupPath;
        std::wstring errorText;
    };

    // PatchFileAtOffsetAtomic applies replacementBytes without changing file size.
    // expectedBytes, when supplied, must have exactly replacementBytes.size() bytes
    // and match the target range before any temporary file is committed.
    AtomicPatchResult PatchFileAtOffsetAtomic(
        const std::wstring& filePath,
        std::uint64_t offset,
        const std::vector<std::uint8_t>& replacementBytes,
        const AtomicPatchOptions& options = AtomicPatchOptions{});
}
