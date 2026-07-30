#include "atomic_file_patch.h"

// ============================================================
// ksword/scanner/atomic_file_patch.cpp
// Purpose:
// - Implement compare-before-write and range checks over an ordinary file.
// - Copy the complete source to a unique sibling temporary file.
// - Flush and commit with ReplaceFileW, optionally retaining a backup.
//
// ReplaceFileW failure is returned to the caller; there is intentionally no
// delete-and-rename fallback because that would weaken atomic replacement.
// The source lock is retained through temporary-file flush and final verification.
// Win32 still requires releasing a non-delete-shared source handle immediately
// before ReplaceFileW, leaving a documented, irreducible path-name race window.
// ============================================================

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>

#include <algorithm>
#include <cstdint>
#include <cwchar>
#include <limits>
#include <string>
#include <vector>

namespace ks::scanner
{
    namespace
    {
        struct FileIdentity
        {
            DWORD volumeSerial = 0;
            DWORD fileIndexHigh = 0;
            DWORD fileIndexLow = 0;
        };

        std::wstring SystemErrorText(const DWORD errorCode)
        {
            wchar_t* messageBuffer = nullptr;
            const DWORD length = ::FormatMessageW(
                FORMAT_MESSAGE_ALLOCATE_BUFFER |
                    FORMAT_MESSAGE_FROM_SYSTEM |
                    FORMAT_MESSAGE_IGNORE_INSERTS,
                nullptr,
                errorCode,
                0,
                reinterpret_cast<wchar_t*>(&messageBuffer),
                0,
                nullptr);
            std::wstring message;
            if (length != 0 && messageBuffer != nullptr)
            {
                message.assign(messageBuffer, messageBuffer + length);
                while (!message.empty() &&
                    (message.back() == L'\r' ||
                     message.back() == L'\n' ||
                     message.back() == L' '))
                {
                    message.pop_back();
                }
            }
            if (messageBuffer != nullptr)
            {
                ::LocalFree(messageBuffer);
            }
            if (message.empty())
            {
                message = L"Win32 error " + std::to_wstring(errorCode);
            }
            return message;
        }

        AtomicPatchResult Failure(
            const std::wstring& action,
            const DWORD errorCode,
            const std::wstring& backupPath = {})
        {
            AtomicPatchResult result{};
            result.systemError = errorCode;
            result.backupPath = backupPath;
            result.errorText = action;
            if (errorCode != ERROR_SUCCESS)
            {
                result.errorText += L": " + SystemErrorText(errorCode);
            }
            return result;
        }

        bool ReadExactly(
            const HANDLE handle,
            std::uint8_t* destination,
            std::size_t byteCount,
            DWORD& errorOut)
        {
            std::size_t totalRead = 0;
            while (totalRead < byteCount)
            {
                const DWORD requested = static_cast<DWORD>(std::min<std::size_t>(
                    byteCount - totalRead,
                    1024U * 1024U));
                DWORD bytesRead = 0;
                if (::ReadFile(
                        handle,
                        destination + totalRead,
                        requested,
                        &bytesRead,
                        nullptr) == FALSE)
                {
                    errorOut = ::GetLastError();
                    return false;
                }
                if (bytesRead == 0)
                {
                    errorOut = ERROR_HANDLE_EOF;
                    return false;
                }
                totalRead += bytesRead;
            }
            return true;
        }

        bool WriteExactly(
            const HANDLE handle,
            const std::uint8_t* source,
            std::size_t byteCount,
            DWORD& errorOut)
        {
            std::size_t totalWritten = 0;
            while (totalWritten < byteCount)
            {
                const DWORD requested = static_cast<DWORD>(std::min<std::size_t>(
                    byteCount - totalWritten,
                    1024U * 1024U));
                DWORD bytesWritten = 0;
                if (::WriteFile(
                        handle,
                        source + totalWritten,
                        requested,
                        &bytesWritten,
                        nullptr) == FALSE)
                {
                    errorOut = ::GetLastError();
                    return false;
                }
                if (bytesWritten == 0)
                {
                    errorOut = ERROR_WRITE_FAULT;
                    return false;
                }
                totalWritten += bytesWritten;
            }
            return true;
        }

        bool SeekAbsolute(
            const HANDLE handle,
            const std::uint64_t offset,
            DWORD& errorOut)
        {
            if (offset > static_cast<std::uint64_t>(
                    std::numeric_limits<LONGLONG>::max()))
            {
                errorOut = ERROR_ARITHMETIC_OVERFLOW;
                return false;
            }
            LARGE_INTEGER distance{};
            distance.QuadPart = static_cast<LONGLONG>(offset);
            if (::SetFilePointerEx(handle, distance, nullptr, FILE_BEGIN) == FALSE)
            {
                errorOut = ::GetLastError();
                return false;
            }
            return true;
        }

        // VerifyTemporarySnapshot compares the complete locked source with the
        // flushed temporary image. Outside the patch range every byte must match;
        // inside it the source must still equal currentBytes and the temporary
        // file must contain replacementBytes. This catches ordinary writes and
        // most pre-existing writable-mapping changes that raced the copy pass.
        bool VerifyTemporarySnapshot(
            const HANDLE sourceHandle,
            const HANDLE temporaryHandle,
            const std::uint64_t fileSize,
            const std::uint64_t patchOffset,
            const std::vector<std::uint8_t>& currentBytes,
            const std::vector<std::uint8_t>& replacementBytes,
            DWORD& errorOut)
        {
            if (!SeekAbsolute(sourceHandle, 0, errorOut) ||
                !SeekAbsolute(temporaryHandle, 0, errorOut))
            {
                return false;
            }

            constexpr std::size_t kVerificationChunkBytes = 1024U * 1024U;
            std::vector<std::uint8_t> sourceBuffer(kVerificationChunkBytes);
            std::vector<std::uint8_t> temporaryBuffer(kVerificationChunkBytes);
            const std::uint64_t patchEnd =
                patchOffset + static_cast<std::uint64_t>(replacementBytes.size());
            std::uint64_t verifiedOffset = 0;

            while (verifiedOffset < fileSize)
            {
                const std::size_t chunk = static_cast<std::size_t>(
                    std::min<std::uint64_t>(
                        fileSize - verifiedOffset,
                        kVerificationChunkBytes));
                if (!ReadExactly(
                        sourceHandle,
                        sourceBuffer.data(),
                        chunk,
                        errorOut) ||
                    !ReadExactly(
                        temporaryHandle,
                        temporaryBuffer.data(),
                        chunk,
                        errorOut))
                {
                    return false;
                }

                for (std::size_t index = 0; index < chunk; ++index)
                {
                    const std::uint64_t absoluteOffset =
                        verifiedOffset + static_cast<std::uint64_t>(index);
                    if (absoluteOffset >= patchOffset &&
                        absoluteOffset < patchEnd)
                    {
                        const std::size_t patchIndex = static_cast<std::size_t>(
                            absoluteOffset - patchOffset);
                        if (sourceBuffer[index] != currentBytes[patchIndex] ||
                            temporaryBuffer[index] != replacementBytes[patchIndex])
                        {
                            errorOut = ERROR_REVISION_MISMATCH;
                            return false;
                        }
                    }
                    else if (sourceBuffer[index] != temporaryBuffer[index])
                    {
                        errorOut = ERROR_REVISION_MISMATCH;
                        return false;
                    }
                }
                verifiedOffset += chunk;
            }
            return true;
        }

        // QueryOrdinaryFileIdentity performs handle-authoritative checks after
        // CreateFileW. FILE_FLAG_OPEN_REPARSE_POINT ensures a raced-in link is
        // inspected as a link instead of silently following it.
        bool QueryOrdinaryFileIdentity(
            const HANDLE handle,
            const bool rejectReparsePoints,
            FileIdentity& identityOut,
            DWORD& errorOut)
        {
            BY_HANDLE_FILE_INFORMATION information{};
            if (::GetFileInformationByHandle(handle, &information) == FALSE)
            {
                errorOut = ::GetLastError();
                return false;
            }
            FILE_ATTRIBUTE_TAG_INFO tagInformation{};
            if (::GetFileInformationByHandleEx(
                    handle,
                    FileAttributeTagInfo,
                    &tagInformation,
                    sizeof(tagInformation)) == FALSE)
            {
                errorOut = ::GetLastError();
                return false;
            }
            if ((tagInformation.FileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0)
            {
                errorOut = ERROR_DIRECTORY;
                return false;
            }
            if (rejectReparsePoints &&
                ((tagInformation.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0 ||
                 tagInformation.ReparseTag != 0))
            {
                errorOut = ERROR_REPARSE_TAG_INVALID;
                return false;
            }
            identityOut.volumeSerial = information.dwVolumeSerialNumber;
            identityOut.fileIndexHigh = information.nFileIndexHigh;
            identityOut.fileIndexLow = information.nFileIndexLow;
            return true;
        }

        bool SameIdentity(
            const FileIdentity& left,
            const FileIdentity& right) noexcept
        {
            return left.volumeSerial == right.volumeSerial &&
                left.fileIndexHigh == right.fileIndexHigh &&
                left.fileIndexLow == right.fileIndexLow;
        }

        HANDLE CreateSiblingTemporaryFile(
            const std::wstring& filePath,
            std::wstring& temporaryPathOut,
            DWORD& errorOut)
        {
            const DWORD processId = ::GetCurrentProcessId();
            const ULONGLONG tick = ::GetTickCount64();
            for (unsigned int attempt = 0; attempt < 128; ++attempt)
            {
                temporaryPathOut =
                    filePath +
                    L".ksword.tmp." +
                    std::to_wstring(processId) +
                    L"." +
                    std::to_wstring(tick) +
                    L"." +
                    std::to_wstring(attempt);
                HANDLE handle = ::CreateFileW(
                    temporaryPathOut.c_str(),
                    GENERIC_READ | GENERIC_WRITE | DELETE,
                    0,
                    nullptr,
                    CREATE_NEW,
                    FILE_ATTRIBUTE_NORMAL,
                    nullptr);
                if (handle != INVALID_HANDLE_VALUE)
                {
                    return handle;
                }
                errorOut = ::GetLastError();
                if (errorOut != ERROR_FILE_EXISTS &&
                    errorOut != ERROR_ALREADY_EXISTS)
                {
                    return INVALID_HANDLE_VALUE;
                }
            }
            errorOut = ERROR_FILE_EXISTS;
            return INVALID_HANDLE_VALUE;
        }

        // VerifyRecoveredTarget confirms that an ambiguous ReplaceFileW failure
        // was repaired by moving the already-flushed temporary image back to the
        // requested path. It never follows a raced-in reparse point.
        bool VerifyRecoveredTarget(
            const std::wstring& filePath,
            const bool rejectReparsePoints,
            const std::uint64_t expectedSize,
            const std::uint64_t patchOffset,
            const std::vector<std::uint8_t>& replacementBytes,
            DWORD& errorOut)
        {
            HANDLE recoveredHandle = ::CreateFileW(
                filePath.c_str(),
                GENERIC_READ,
                FILE_SHARE_READ,
                nullptr,
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
                nullptr);
            if (recoveredHandle == INVALID_HANDLE_VALUE)
            {
                errorOut = ::GetLastError();
                return false;
            }

            FileIdentity recoveredIdentity{};
            LARGE_INTEGER recoveredSize{};
            std::vector<std::uint8_t> recoveredBytes(replacementBytes.size());
            bool verified = QueryOrdinaryFileIdentity(
                recoveredHandle,
                rejectReparsePoints,
                recoveredIdentity,
                errorOut);
            if (verified && ::GetFileSizeEx(recoveredHandle, &recoveredSize) == FALSE)
            {
                errorOut = ::GetLastError();
                verified = false;
            }
            if (verified &&
                (recoveredSize.QuadPart < 0 ||
                 static_cast<std::uint64_t>(recoveredSize.QuadPart) != expectedSize))
            {
                errorOut = ERROR_REVISION_MISMATCH;
                verified = false;
            }
            if (verified &&
                (!SeekAbsolute(recoveredHandle, patchOffset, errorOut) ||
                 !ReadExactly(
                     recoveredHandle,
                     recoveredBytes.data(),
                     recoveredBytes.size(),
                     errorOut) ||
                 recoveredBytes != replacementBytes))
            {
                if (errorOut == ERROR_SUCCESS)
                {
                    errorOut = ERROR_REVISION_MISMATCH;
                }
                verified = false;
            }
            ::CloseHandle(recoveredHandle);
            return verified;
        }

        // HandleReplaceFailure follows the documented 1175/1176/1177 state
        // transitions. In the two ambiguous cases the temporary image may be the
        // only recoverable replacement, so it is moved to the missing target or
        // deliberately preserved for manual recovery instead of being deleted.
        AtomicPatchResult HandleReplaceFailure(
            const std::wstring& filePath,
            const std::wstring& temporaryPath,
            const std::wstring& backupPath,
            const bool createBackup,
            const bool rejectReparsePoints,
            const std::uint64_t expectedSize,
            const std::uint64_t patchOffset,
            const std::vector<std::uint8_t>& replacementBytes,
            const DWORD replaceError)
        {
            const bool targetMayBeMissing =
                (replaceError == ERROR_UNABLE_TO_MOVE_REPLACEMENT &&
                 !createBackup) ||
                replaceError == ERROR_UNABLE_TO_MOVE_REPLACEMENT_2;
            if (!targetMayBeMissing)
            {
                AtomicPatchResult result = Failure(
                    L"Atomic ReplaceFileW commit failed",
                    replaceError,
                    backupPath);
                if (::DeleteFileW(temporaryPath.c_str()) == FALSE &&
                    ::GetFileAttributesW(temporaryPath.c_str()) !=
                        INVALID_FILE_ATTRIBUTES)
                {
                    result.errorText +=
                        L"; the replacement file was preserved at: " +
                        temporaryPath;
                }
                return result;
            }

            // Do not use MOVEFILE_REPLACE_EXISTING: an unexpectedly present
            // target means the documented partial-state assumptions no longer
            // hold, and preserving both paths is safer than overwriting either.
            if (::MoveFileExW(
                    temporaryPath.c_str(),
                    filePath.c_str(),
                    MOVEFILE_WRITE_THROUGH) != FALSE)
            {
                DWORD verificationError = ERROR_SUCCESS;
                if (VerifyRecoveredTarget(
                        filePath,
                        rejectReparsePoints,
                        expectedSize,
                        patchOffset,
                        replacementBytes,
                        verificationError))
                {
                    AtomicPatchResult result{};
                    result.success = true;
                    result.changed = true;
                    result.recoveredAfterReplaceFailure = true;
                    result.backupPath = backupPath;
                    return result;
                }

                AtomicPatchResult result = Failure(
                    L"ReplaceFileW entered a partial state; the replacement was restored to the target path but verification failed",
                    verificationError,
                    backupPath);
                result.errorText +=
                    L"; original ReplaceFileW error: " +
                    std::to_wstring(replaceError);
                return result;
            }

            const DWORD recoveryError = ::GetLastError();
            AtomicPatchResult result = Failure(
                L"ReplaceFileW entered a partial state and automatic recovery failed",
                recoveryError,
                backupPath);
            result.errorText +=
                L"; original ReplaceFileW error: " +
                std::to_wstring(replaceError) +
                L"; the replacement file was preserved at: " +
                temporaryPath;
            return result;
        }
    }

    AtomicPatchResult PatchFileAtOffsetAtomic(
        const std::wstring& filePath,
        const std::uint64_t offset,
        const std::vector<std::uint8_t>& replacementBytes,
        const AtomicPatchOptions& options)
    {
        if (filePath.empty())
        {
            return Failure(L"The file path is empty", ERROR_INVALID_PARAMETER);
        }
        if (options.maxFileBytes == 0 ||
            options.maxPatchBytes == 0 ||
            replacementBytes.size() > options.maxPatchBytes)
        {
            return Failure(L"Patch limits are invalid or exceeded", ERROR_INVALID_PARAMETER);
        }
        if (!options.expectedBytes.empty() &&
            options.expectedBytes.size() != replacementBytes.size())
        {
            return Failure(
                L"expectedBytes must be empty or match replacementBytes size",
                ERROR_INVALID_PARAMETER);
        }
        if (replacementBytes.empty())
        {
            AtomicPatchResult result{};
            result.success = true;
            result.changed = false;
            return result;
        }

        const DWORD attributes = ::GetFileAttributesW(filePath.c_str());
        if (attributes == INVALID_FILE_ATTRIBUTES)
        {
            return Failure(L"GetFileAttributesW failed", ::GetLastError());
        }
        if ((attributes & FILE_ATTRIBUTE_DIRECTORY) != 0)
        {
            return Failure(L"The target is a directory", ERROR_DIRECTORY);
        }
        if (options.rejectReparsePoints &&
            (attributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0)
        {
            return Failure(
                L"Reparse-point targets are rejected by policy",
                ERROR_REPARSE_TAG_INVALID);
        }

        const std::wstring backupPath = options.createBackup
            ? (options.backupPath.empty()
                ? filePath + L".ksword.bak"
                : options.backupPath)
            : std::wstring();
        if (options.createBackup &&
            _wcsicmp(backupPath.c_str(), filePath.c_str()) == 0)
        {
            return Failure(
                L"The backup path must differ from the target",
                ERROR_INVALID_PARAMETER,
                backupPath);
        }
        if (options.createBackup &&
            !options.overwriteBackup &&
            ::GetFileAttributesW(backupPath.c_str()) != INVALID_FILE_ATTRIBUTES)
        {
            return Failure(
                L"The backup path already exists",
                ERROR_FILE_EXISTS,
                backupPath);
        }

        HANDLE sourceHandle = ::CreateFileW(
            filePath.c_str(),
            GENERIC_READ,
            FILE_SHARE_READ,
            nullptr,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL |
                FILE_FLAG_SEQUENTIAL_SCAN |
                FILE_FLAG_OPEN_REPARSE_POINT,
            nullptr);
        if (sourceHandle == INVALID_HANDLE_VALUE)
        {
            return Failure(
                L"Opening the target failed",
                ::GetLastError(),
                backupPath);
        }

        DWORD error = ERROR_SUCCESS;
        FileIdentity initialIdentity{};
        if (!QueryOrdinaryFileIdentity(
                sourceHandle,
                options.rejectReparsePoints,
                initialIdentity,
                error))
        {
            ::CloseHandle(sourceHandle);
            return Failure(
                L"Handle-level target validation failed",
                error,
                backupPath);
        }

        LARGE_INTEGER fileSize{};
        if (::GetFileSizeEx(sourceHandle, &fileSize) == FALSE ||
            fileSize.QuadPart < 0)
        {
            const DWORD sizeError = ::GetLastError();
            ::CloseHandle(sourceHandle);
            return Failure(L"Reading the target size failed", sizeError, backupPath);
        }
        const std::uint64_t unsignedSize =
            static_cast<std::uint64_t>(fileSize.QuadPart);
        if (unsignedSize > options.maxFileBytes)
        {
            ::CloseHandle(sourceHandle);
            return Failure(
                L"The target exceeds maxFileBytes",
                ERROR_FILE_TOO_LARGE,
                backupPath);
        }
        if (offset > unsignedSize ||
            replacementBytes.size() > unsignedSize - offset)
        {
            ::CloseHandle(sourceHandle);
            return Failure(
                L"The patch range is outside the file",
                ERROR_INVALID_PARAMETER,
                backupPath);
        }

        std::vector<std::uint8_t> currentBytes(replacementBytes.size());
        if (!SeekAbsolute(sourceHandle, offset, error) ||
            !ReadExactly(
                sourceHandle,
                currentBytes.data(),
                currentBytes.size(),
                error))
        {
            ::CloseHandle(sourceHandle);
            return Failure(
                L"Reading the target patch range failed",
                error,
                backupPath);
        }
        if (!options.expectedBytes.empty() &&
            currentBytes != options.expectedBytes)
        {
            ::CloseHandle(sourceHandle);
            return Failure(
                L"The target bytes do not match expectedBytes",
                ERROR_REVISION_MISMATCH,
                backupPath);
        }
        if (currentBytes == replacementBytes)
        {
            ::CloseHandle(sourceHandle);
            AtomicPatchResult result{};
            result.success = true;
            result.changed = false;
            result.backupPath = backupPath;
            return result;
        }
        if (!SeekAbsolute(sourceHandle, 0, error))
        {
            ::CloseHandle(sourceHandle);
            return Failure(L"Rewinding the target failed", error, backupPath);
        }

        std::wstring temporaryPath;
        HANDLE temporaryHandle =
            CreateSiblingTemporaryFile(filePath, temporaryPath, error);
        if (temporaryHandle == INVALID_HANDLE_VALUE)
        {
            ::CloseHandle(sourceHandle);
            return Failure(
                L"Creating the sibling temporary file failed",
                error,
                backupPath);
        }

        bool copySucceeded = true;
        std::vector<std::uint8_t> copyBuffer(1024U * 1024U);
        std::uint64_t remaining = unsignedSize;
        while (remaining != 0)
        {
            const std::size_t chunk = static_cast<std::size_t>(
                std::min<std::uint64_t>(remaining, copyBuffer.size()));
            if (!ReadExactly(sourceHandle, copyBuffer.data(), chunk, error) ||
                !WriteExactly(temporaryHandle, copyBuffer.data(), chunk, error))
            {
                copySucceeded = false;
                break;
            }
            remaining -= chunk;
        }

        if (copySucceeded &&
            (!SeekAbsolute(temporaryHandle, offset, error) ||
             !WriteExactly(
                 temporaryHandle,
                 replacementBytes.data(),
                 replacementBytes.size(),
                 error)))
        {
            copySucceeded = false;
        }
        if (copySucceeded && ::FlushFileBuffers(temporaryHandle) == FALSE)
        {
            error = ::GetLastError();
            copySucceeded = false;
        }

        if (!copySucceeded)
        {
            ::CloseHandle(temporaryHandle);
            ::CloseHandle(sourceHandle);
            ::DeleteFileW(temporaryPath.c_str());
            return Failure(
                L"Building the replacement file failed",
                error,
                backupPath);
        }

        // Revalidate the still-locked source after the replacement bytes and all
        // unchanged bytes have reached the temporary file. This closes the prior
        // TOCTOU window in which the source handle was released before Flush.
        LARGE_INTEGER verifiedSize{};
        FileIdentity verifiedIdentity{};
        bool finalVerificationSucceeded = true;
        if (::GetFileSizeEx(sourceHandle, &verifiedSize) == FALSE)
        {
            error = ::GetLastError();
            finalVerificationSucceeded = false;
        }
        else if (verifiedSize.QuadPart != fileSize.QuadPart)
        {
            error = ERROR_REVISION_MISMATCH;
            finalVerificationSucceeded = false;
        }
        if (finalVerificationSucceeded &&
            (!QueryOrdinaryFileIdentity(
                sourceHandle,
                options.rejectReparsePoints,
                verifiedIdentity,
                error) ||
             !SameIdentity(initialIdentity, verifiedIdentity) ||
             !VerifyTemporarySnapshot(
                 sourceHandle,
                 temporaryHandle,
                 unsignedSize,
                 offset,
                 currentBytes,
                 replacementBytes,
                 error)))
        {
            finalVerificationSucceeded = false;
        }
        if (!finalVerificationSucceeded)
        {
            if (error == ERROR_SUCCESS)
            {
                error = ERROR_REVISION_MISMATCH;
            }
            ::CloseHandle(temporaryHandle);
            ::CloseHandle(sourceHandle);
            ::DeleteFileW(temporaryPath.c_str());
            return Failure(
                L"The target changed during replacement preparation",
                error,
                backupPath);
        }

        // Confirm that resolving the path still reaches the same file identity.
        // The original handle denies delete sharing, so the path cannot be swapped
        // while this verification handle is opened.
        HANDLE pathVerificationHandle = ::CreateFileW(
            filePath.c_str(),
            GENERIC_READ,
            FILE_SHARE_READ,
            nullptr,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
            nullptr);
        FileIdentity pathIdentity{};
        if (pathVerificationHandle == INVALID_HANDLE_VALUE ||
            !QueryOrdinaryFileIdentity(
                pathVerificationHandle,
                options.rejectReparsePoints,
                pathIdentity,
                error) ||
            !SameIdentity(initialIdentity, pathIdentity))
        {
            if (pathVerificationHandle == INVALID_HANDLE_VALUE)
            {
                error = ::GetLastError();
            }
            else
            {
                ::CloseHandle(pathVerificationHandle);
            }
            if (error == ERROR_SUCCESS)
            {
                error = ERROR_REVISION_MISMATCH;
            }
            ::CloseHandle(temporaryHandle);
            ::CloseHandle(sourceHandle);
            ::DeleteFileW(temporaryPath.c_str());
            return Failure(
                L"The target path identity changed",
                error,
                backupPath);
        }
        ::CloseHandle(pathVerificationHandle);

        if (options.createBackup &&
            options.overwriteBackup &&
            ::GetFileAttributesW(backupPath.c_str()) != INVALID_FILE_ATTRIBUTES &&
            ::DeleteFileW(backupPath.c_str()) == FALSE)
        {
            error = ::GetLastError();
            ::CloseHandle(temporaryHandle);
            ::CloseHandle(sourceHandle);
            ::DeleteFileW(temporaryPath.c_str());
            return Failure(
                L"Removing the previous backup failed",
                error,
                backupPath);
        }

        // ReplaceFileW cannot commit while the non-delete-shared source handle is
        // open. Release both handles only after all identity/content checks, then
        // commit in the immediately following call.
        ::CloseHandle(temporaryHandle);
        ::CloseHandle(sourceHandle);
        if (::ReplaceFileW(
                filePath.c_str(),
                temporaryPath.c_str(),
                options.createBackup ? backupPath.c_str() : nullptr,
                0,
                nullptr,
                nullptr) == FALSE)
        {
            error = ::GetLastError();
            return HandleReplaceFailure(
                filePath,
                temporaryPath,
                backupPath,
                options.createBackup,
                options.rejectReparsePoints,
                unsignedSize,
                offset,
                replacementBytes,
                error);
        }

        AtomicPatchResult result{};
        result.success = true;
        result.changed = true;
        result.backupPath = backupPath;
        return result;
    }
}
