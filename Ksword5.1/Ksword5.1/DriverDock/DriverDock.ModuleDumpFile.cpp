#include "DriverDock.ModuleDumpFile.h"

#include <QDir>
#include <QFileInfo>

#include <algorithm>
#include <cstring>
#include <limits>
#include <vector>

namespace ksword::driver_dock_internal
{
    namespace
    {
        constexpr unsigned int kTemporaryFileCreateAttempts = 128U;

        // extendedWin32Path：输入普通绝对路径；输出兼容长路径与 UNC 的 Win32 路径。
        QString extendedWin32Path(const QString& rawPath)
        {
            QString nativePath = QDir::toNativeSeparators(rawPath);
            if (nativePath.startsWith(QStringLiteral("\\\\?\\")))
            {
                return nativePath;
            }
            if (nativePath.startsWith(QStringLiteral("\\\\")))
            {
                return QStringLiteral("\\\\?\\UNC\\") + nativePath.mid(2);
            }
            return QStringLiteral("\\\\?\\") + nativePath;
        }

        // closeHandle：输入可空 Win32 句柄引用；关闭后统一重置，防止重复释放。
        void closeHandle(HANDLE& handleValue) noexcept
        {
            if (handleValue != INVALID_HANDLE_VALUE)
            {
                ::CloseHandle(handleValue);
                handleValue = INVALID_HANDLE_VALUE;
            }
        }
    }

    DriverModuleDumpFile::~DriverModuleDumpFile() noexcept
    {
        discard();
    }

    bool DriverModuleDumpFile::create(const QString& targetPath)
    {
        // 每个实例只能对应一次目标，避免旧句柄或旧诊断串入下一次 Dump。
        if (m_fileHandle != INVALID_HANDLE_VALUE ||
            !m_temporaryPath.isEmpty())
        {
            return fail(
                DriverModuleDumpFileError::Create,
                ERROR_INVALID_STATE,
                QString::fromLatin1("The module dump file object was already initialized."));
        }

        const QFileInfo targetInformation(targetPath);
        const QDir targetDirectory = targetInformation.dir();
        m_targetPath = QDir::toNativeSeparators(
            targetInformation.absoluteFilePath());
        if (!targetInformation.isAbsolute() ||
            !targetDirectory.exists() ||
            m_targetPath.isEmpty())
        {
            return fail(
                DriverModuleDumpFileError::Create,
                ERROR_PATH_NOT_FOUND,
                QString::fromLatin1("The module dump destination directory is unavailable."));
        }

        // DELETE 权限一直保留到提交；后来打开临时文件的扫描器必须共享删除，
        // 因而不会再在关闭 QTemporaryFile 后抢占重命名窗口并造成 Win32 32。
        const unsigned long processId = ::GetCurrentProcessId();
        const unsigned long threadId = ::GetCurrentThreadId();
        const unsigned long long tickCount = ::GetTickCount64();
        for (unsigned int attempt = 0U;
             attempt < kTemporaryFileCreateAttempts;
             ++attempt)
        {
            const QString temporaryFileName = QString::fromLatin1(
                ".ksword-module-dump-%1-%2-%3-%4.tmp")
                .arg(processId)
                .arg(threadId)
                .arg(tickCount)
                .arg(attempt);
            m_temporaryPath = targetDirectory.filePath(temporaryFileName);
            const QString temporaryExtendedPath =
                extendedWin32Path(m_temporaryPath);
            m_fileHandle = ::CreateFileW(
                reinterpret_cast<LPCWSTR>(temporaryExtendedPath.utf16()),
                GENERIC_WRITE | DELETE,
                FILE_SHARE_READ | FILE_SHARE_DELETE,
                nullptr,
                CREATE_NEW,
                FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN,
                nullptr);
            if (m_fileHandle != INVALID_HANDLE_VALUE)
            {
                m_error = DriverModuleDumpFileError::None;
                m_win32Error = ERROR_SUCCESS;
                m_technicalDetail.clear();
                return true;
            }

            const unsigned long createError = ::GetLastError();
            if (createError != ERROR_FILE_EXISTS &&
                createError != ERROR_ALREADY_EXISTS)
            {
                m_temporaryPath.clear();
                return fail(
                    DriverModuleDumpFileError::Create,
                    createError,
                    QString::fromLatin1("Creating the protected sibling temporary file failed."));
            }
        }

        m_temporaryPath.clear();
        return fail(
            DriverModuleDumpFileError::Create,
            ERROR_FILE_EXISTS,
            QString::fromLatin1("All protected temporary file names were already in use."));
    }

    bool DriverModuleDumpFile::write(
        const std::uint8_t* dataPointer,
        const std::size_t byteCount)
    {
        if (m_fileHandle == INVALID_HANDLE_VALUE ||
            (dataPointer == nullptr && byteCount != 0U))
        {
            return fail(
                DriverModuleDumpFileError::Write,
                ERROR_INVALID_HANDLE,
                QString::fromLatin1("The protected module dump file handle is invalid."));
        }

        // WriteFile 使用 DWORD 长度；循环同时处理大缓冲区和合法的部分写入。
        std::size_t writtenTotal = 0U;
        const std::size_t maximumWriteBytes =
            static_cast<std::size_t>((std::numeric_limits<unsigned long>::max)());
        while (writtenTotal < byteCount)
        {
            const unsigned long requestedBytes = static_cast<unsigned long>(
                (std::min)(byteCount - writtenTotal, maximumWriteBytes));
            unsigned long writtenBytes = 0U;
            const bool writeSucceeded = ::WriteFile(
                m_fileHandle,
                dataPointer + writtenTotal,
                requestedBytes,
                &writtenBytes,
                nullptr) != FALSE;
            if (!writeSucceeded || writtenBytes == 0U)
            {
                const unsigned long writeError =
                    writeSucceeded ? ERROR_WRITE_FAULT : ::GetLastError();
                return fail(
                    DriverModuleDumpFileError::Write,
                    writeError,
                    QString::fromLatin1("Writing the protected module dump temporary file failed."));
            }
            writtenTotal += writtenBytes;
        }
        return true;
    }

    bool DriverModuleDumpFile::commit(const std::uint64_t expectedFileBytes)
    {
        if (m_fileHandle == INVALID_HANDLE_VALUE)
        {
            return fail(
                DriverModuleDumpFileError::Commit,
                ERROR_INVALID_HANDLE,
                QString::fromLatin1("The protected module dump commit handles are invalid."));
        }

        // 在重命名前按同一句柄复核长度并刷新数据，任何失败都保留无目标文件语义。
        LARGE_INTEGER actualFileBytes{};
        if (!::GetFileSizeEx(m_fileHandle, &actualFileBytes))
        {
            return fail(
                DriverModuleDumpFileError::Flush,
                ::GetLastError(),
                QString::fromLatin1("Querying the protected module dump temporary file size failed."));
        }
        if (actualFileBytes.QuadPart < 0 ||
            static_cast<std::uint64_t>(actualFileBytes.QuadPart) != expectedFileBytes)
        {
            return fail(
                DriverModuleDumpFileError::Flush,
                ERROR_WRITE_FAULT,
                QString::fromLatin1("The protected module dump temporary file size is incomplete."));
        }
        if (!::FlushFileBuffers(m_fileHandle))
        {
            return fail(
                DriverModuleDumpFileError::Flush,
                ::GetLastError(),
                QString::fromLatin1("FlushFileBuffers failed before the handle-based atomic commit."));
        }

        // FileRenameInfo 使用完整绝对路径；RootDirectory=nullptr 是 Win32 文档的常见兼容形式。
        const std::size_t targetNameBytes =
            static_cast<std::size_t>(m_targetPath.size()) * sizeof(wchar_t);
        // Windows 要求缓冲区至少为结构体本体再加完整文件名，不能只按 FileName 偏移分配。
        const std::size_t renameInformationBytes =
            sizeof(FILE_RENAME_INFO) + targetNameBytes;
        if (targetNameBytes == 0U ||
            targetNameBytes > (std::numeric_limits<unsigned long>::max)() ||
            renameInformationBytes > (std::numeric_limits<unsigned long>::max)())
        {
            return fail(
                DriverModuleDumpFileError::Commit,
                ERROR_FILENAME_EXCED_RANGE,
                QString::fromLatin1("The module dump destination file name is too long."));
        }

        std::vector<std::uint8_t> renameBuffer(renameInformationBytes, 0U);
        auto* renameInformation =
            reinterpret_cast<FILE_RENAME_INFO*>(renameBuffer.data());
        renameInformation->ReplaceIfExists = FALSE;
        renameInformation->RootDirectory = nullptr;
        renameInformation->FileNameLength =
            static_cast<unsigned long>(targetNameBytes);
        std::memcpy(
            renameInformation->FileName,
            m_targetPath.utf16(),
            targetNameBytes);
        if (!::SetFileInformationByHandle(
                m_fileHandle,
                FileRenameInfo,
                renameInformation,
                static_cast<unsigned long>(renameInformationBytes)))
        {
            const unsigned long renameError = ::GetLastError();
            return fail(
                renameError == ERROR_FILE_EXISTS ||
                    renameError == ERROR_ALREADY_EXISTS
                    ? DriverModuleDumpFileError::TargetExists
                    : DriverModuleDumpFileError::Commit,
                renameError,
                QString::fromLatin1("The handle-based atomic no-replace commit failed."));
        }

        m_committed = true;
        closeHandle(m_fileHandle);
        m_temporaryPath.clear();
        m_error = DriverModuleDumpFileError::None;
        m_win32Error = ERROR_SUCCESS;
        m_technicalDetail.clear();
        return true;
    }

    DriverModuleDumpFileError DriverModuleDumpFile::error() const noexcept
    {
        return m_error;
    }

    unsigned long DriverModuleDumpFile::win32Error() const noexcept
    {
        return m_win32Error;
    }

    QString DriverModuleDumpFile::technicalDetail() const
    {
        return m_technicalDetail;
    }

    bool DriverModuleDumpFile::fail(
        const DriverModuleDumpFileError errorValue,
        const unsigned long win32ErrorValue,
        const QString& technicalDetailValue)
    {
        m_error = errorValue;
        m_win32Error = win32ErrorValue;
        m_technicalDetail = technicalDetailValue;
        return false;
    }

    void DriverModuleDumpFile::discard() noexcept
    {
        if (m_fileHandle != INVALID_HANDLE_VALUE)
        {
            // DELETE 权限来自创建时的同一句柄；即使扫描器正在读取，也能先标记删除。
            if (!m_committed)
            {
                FILE_DISPOSITION_INFO dispositionInformation{};
                dispositionInformation.DeleteFile = TRUE;
                ::SetFileInformationByHandle(
                    m_fileHandle,
                    FileDispositionInfo,
                    &dispositionInformation,
                    sizeof(dispositionInformation));
            }
            closeHandle(m_fileHandle);
        }

        if (!m_committed && !m_temporaryPath.isEmpty())
        {
            const QString temporaryExtendedPath =
                extendedWin32Path(m_temporaryPath);
            ::DeleteFileW(
                reinterpret_cast<LPCWSTR>(temporaryExtendedPath.utf16()));
        }
        m_temporaryPath.clear();
    }
}
