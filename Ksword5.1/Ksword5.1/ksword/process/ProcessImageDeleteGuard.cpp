#include "ProcessImageDeleteGuard.h"

#include "process.h"

#include <array>
#include <iomanip>
#include <sstream>
#include <utility>

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>

namespace
{
    // formatWin32Error：把 Win32 错误码整理成稳定日志文本。
    std::string formatWin32Error(const DWORD errorCode)
    {
        std::array<wchar_t, 512> messageBuffer{};
        const DWORD messageLength = ::FormatMessageW(
            FORMAT_MESSAGE_FROM_SYSTEM |
                FORMAT_MESSAGE_IGNORE_INSERTS |
                FORMAT_MESSAGE_MAX_WIDTH_MASK,
            nullptr,
            errorCode,
            0,
            messageBuffer.data(),
            static_cast<DWORD>(messageBuffer.size()),
            nullptr);

        std::ostringstream stream;
        stream << "Win32Error=" << errorCode;
        if (messageLength != 0U)
        {
            const int utf8Bytes = ::WideCharToMultiByte(
                CP_UTF8,
                0,
                messageBuffer.data(),
                static_cast<int>(messageLength),
                nullptr,
                0,
                nullptr,
                nullptr);
            if (utf8Bytes > 0)
            {
                std::string utf8Text(static_cast<std::size_t>(utf8Bytes), '\0');
                (void)::WideCharToMultiByte(
                    CP_UTF8,
                    0,
                    messageBuffer.data(),
                    static_cast<int>(messageLength),
                    utf8Text.data(),
                    utf8Bytes,
                    nullptr,
                    nullptr);
                stream << " (" << utf8Text << ")";
            }
        }
        return stream.str();
    }

    // utf8ToWide：ProcessRecord 使用 UTF-8 std::string，本函数只用于实时路径转换。
    bool utf8ToWide(const std::string& sourceText, std::wstring& wideTextOut)
    {
        wideTextOut.clear();
        if (sourceText.empty())
        {
            return false;
        }

        const int requiredChars = ::MultiByteToWideChar(
            CP_UTF8,
            MB_ERR_INVALID_CHARS,
            sourceText.data(),
            static_cast<int>(sourceText.size()),
            nullptr,
            0);
        if (requiredChars <= 0)
        {
            return false;
        }

        wideTextOut.resize(static_cast<std::size_t>(requiredChars));
        const int convertedChars = ::MultiByteToWideChar(
            CP_UTF8,
            MB_ERR_INVALID_CHARS,
            sourceText.data(),
            static_cast<int>(sourceText.size()),
            wideTextOut.data(),
            requiredChars);
        if (convertedChars != requiredChars)
        {
            wideTextOut.clear();
            return false;
        }
        return true;
    }

    // queryFileIdentity：读取稳定卷序列号和 64 位文件索引。
    bool queryFileIdentity(
        const HANDLE fileHandle,
        std::uint32_t& volumeSerialOut,
        std::uint64_t& fileIdentityOut,
        bool& directoryOut,
        DWORD& errorOut)
    {
        BY_HANDLE_FILE_INFORMATION fileInformation{};
        if (::GetFileInformationByHandle(fileHandle, &fileInformation) == FALSE)
        {
            errorOut = ::GetLastError();
            return false;
        }

        volumeSerialOut = fileInformation.dwVolumeSerialNumber;
        fileIdentityOut =
            (static_cast<std::uint64_t>(fileInformation.nFileIndexHigh) << 32U) |
            static_cast<std::uint64_t>(fileInformation.nFileIndexLow);
        directoryOut = (fileInformation.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0U;
        errorOut = ERROR_SUCCESS;
        return true;
    }

    // queryFinalPath：从已打开句柄取得规范路径；失败时保持空值但不影响文件身份锁定。
    std::wstring queryFinalPath(const HANDLE fileHandle)
    {
        const DWORD requiredChars = ::GetFinalPathNameByHandleW(
            fileHandle,
            nullptr,
            0,
            FILE_NAME_NORMALIZED | VOLUME_NAME_DOS);
        if (requiredChars == 0U)
        {
            return std::wstring();
        }

        std::wstring pathBuffer(static_cast<std::size_t>(requiredChars), L'\0');
        const DWORD copiedChars = ::GetFinalPathNameByHandleW(
            fileHandle,
            pathBuffer.data(),
            requiredChars,
            FILE_NAME_NORMALIZED | VOLUME_NAME_DOS);
        if (copiedChars == 0U || copiedChars >= requiredChars)
        {
            return std::wstring();
        }
        pathBuffer.resize(static_cast<std::size_t>(copiedChars));
        return pathBuffer;
    }

    // sameFileObject：用卷序列号和文件索引比较两个路径是否指向同一文件对象。
    bool sameFileObject(
        const HANDLE leftHandle,
        const HANDLE rightHandle,
        DWORD& errorOut)
    {
        std::uint32_t leftVolume = 0;
        std::uint32_t rightVolume = 0;
        std::uint64_t leftIdentity = 0;
        std::uint64_t rightIdentity = 0;
        bool leftDirectory = false;
        bool rightDirectory = false;
        if (!queryFileIdentity(
                leftHandle,
                leftVolume,
                leftIdentity,
                leftDirectory,
                errorOut))
        {
            return false;
        }
        if (!queryFileIdentity(
                rightHandle,
                rightVolume,
                rightIdentity,
                rightDirectory,
                errorOut))
        {
            return false;
        }
        errorOut = ERROR_SUCCESS;
        return !leftDirectory && !rightDirectory &&
            leftVolume == rightVolume && leftIdentity == rightIdentity;
    }

    // setDeleteDispositionOnce：优先使用可忽略只读属性的现代接口，再回退经典接口。
    bool setDeleteDispositionOnce(
        const HANDLE fileHandle,
        DWORD& extendedErrorOut,
        DWORD& legacyErrorOut)
    {
        FILE_DISPOSITION_INFO_EX extendedDisposition{};
        extendedDisposition.Flags =
            FILE_DISPOSITION_FLAG_DELETE |
            FILE_DISPOSITION_FLAG_POSIX_SEMANTICS |
            FILE_DISPOSITION_FLAG_IGNORE_READONLY_ATTRIBUTE;
        if (::SetFileInformationByHandle(
                fileHandle,
                FileDispositionInfoEx,
                &extendedDisposition,
                sizeof(extendedDisposition)) != FALSE)
        {
            extendedErrorOut = ERROR_SUCCESS;
            legacyErrorOut = ERROR_SUCCESS;
            return true;
        }
        extendedErrorOut = ::GetLastError();

        FILE_DISPOSITION_INFO legacyDisposition{};
        legacyDisposition.DeleteFile = TRUE;
        if (::SetFileInformationByHandle(
                fileHandle,
                FileDispositionInfo,
                &legacyDisposition,
                sizeof(legacyDisposition)) != FALSE)
        {
            legacyErrorOut = ERROR_SUCCESS;
            return true;
        }
        legacyErrorOut = ::GetLastError();
        return false;
    }
}

ks::process::CapturedProcessImageDeleteTarget::~CapturedProcessImageDeleteTarget()
{
    close();
}

ks::process::CapturedProcessImageDeleteTarget::CapturedProcessImageDeleteTarget(
    CapturedProcessImageDeleteTarget&& other) noexcept
    : m_fileHandle(std::exchange(other.m_fileHandle, nullptr)),
      m_finalPath(std::move(other.m_finalPath)),
      m_fileIdentity(std::exchange(other.m_fileIdentity, 0U)),
      m_volumeSerialNumber(std::exchange(other.m_volumeSerialNumber, 0U))
{
}

ks::process::CapturedProcessImageDeleteTarget&
ks::process::CapturedProcessImageDeleteTarget::operator=(
    CapturedProcessImageDeleteTarget&& other) noexcept
{
    if (this != &other)
    {
        close();
        m_fileHandle = std::exchange(other.m_fileHandle, nullptr);
        m_finalPath = std::move(other.m_finalPath);
        m_fileIdentity = std::exchange(other.m_fileIdentity, 0U);
        m_volumeSerialNumber = std::exchange(other.m_volumeSerialNumber, 0U);
    }
    return *this;
}

bool ks::process::CapturedProcessImageDeleteTarget::valid() const noexcept
{
    return m_fileHandle != nullptr && m_fileHandle != INVALID_HANDLE_VALUE;
}

const std::wstring& ks::process::CapturedProcessImageDeleteTarget::finalPath() const noexcept
{
    return m_finalPath;
}

std::uint64_t ks::process::CapturedProcessImageDeleteTarget::fileIdentity() const noexcept
{
    return m_fileIdentity;
}

std::uint32_t ks::process::CapturedProcessImageDeleteTarget::volumeSerialNumber() const noexcept
{
    return m_volumeSerialNumber;
}

void ks::process::CapturedProcessImageDeleteTarget::close() noexcept
{
    if (valid())
    {
        (void)::CloseHandle(static_cast<HANDLE>(m_fileHandle));
    }
    m_fileHandle = nullptr;
    m_finalPath.clear();
    m_fileIdentity = 0U;
    m_volumeSerialNumber = 0U;
}

bool ks::process::CaptureProcessImageDeleteTarget(
    const std::uint32_t processId,
    const std::uint64_t expectedCreationTime100ns,
    const std::wstring& expectedImagePath,
    CapturedProcessImageDeleteTarget* const targetOut,
    std::string* const detailTextOut)
{
    if (detailTextOut != nullptr)
    {
        detailTextOut->clear();
    }
    if (targetOut == nullptr || processId == 0U || expectedCreationTime100ns == 0U || expectedImagePath.empty())
    {
        if (detailTextOut != nullptr)
        {
            *detailTextOut = "invalid process image deletion target";
        }
        return false;
    }
    targetOut->close();

    std::uint64_t currentCreationTime100ns = 0U;
    std::string identityDetail;
    if (!QueryProcessCreationTimeByPid(processId, &currentCreationTime100ns, &identityDetail) ||
        currentCreationTime100ns != expectedCreationTime100ns)
    {
        if (detailTextOut != nullptr)
        {
            *detailTextOut = currentCreationTime100ns != 0U
                ? "PID creation time changed; refusing to target a reused PID"
                : (identityDetail.empty() ? "process identity is unavailable" : identityDetail);
        }
        return false;
    }

    const std::string liveImagePathUtf8 = QueryProcessPathByPid(processId);
    std::wstring liveImagePath;
    if (!utf8ToWide(liveImagePathUtf8, liveImagePath) || liveImagePath.empty())
    {
        if (detailTextOut != nullptr)
        {
            *detailTextOut = "live process image path is unavailable or is not valid UTF-8";
        }
        return false;
    }

    const HANDLE liveFileHandle = ::CreateFileW(
        liveImagePath.c_str(),
        DELETE | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        nullptr);
    if (liveFileHandle == INVALID_HANDLE_VALUE)
    {
        if (detailTextOut != nullptr)
        {
            *detailTextOut = "open live process image with DELETE access failed: " +
                formatWin32Error(::GetLastError());
        }
        return false;
    }

    const HANDLE expectedFileHandle = ::CreateFileW(
        expectedImagePath.c_str(),
        FILE_READ_ATTRIBUTES,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        nullptr);
    if (expectedFileHandle == INVALID_HANDLE_VALUE)
    {
        const DWORD openError = ::GetLastError();
        (void)::CloseHandle(liveFileHandle);
        if (detailTextOut != nullptr)
        {
            *detailTextOut = "open selected snapshot image failed: " + formatWin32Error(openError);
        }
        return false;
    }

    DWORD compareError = ERROR_SUCCESS;
    const bool identitiesMatch = sameFileObject(liveFileHandle, expectedFileHandle, compareError);
    (void)::CloseHandle(expectedFileHandle);
    if (!identitiesMatch)
    {
        (void)::CloseHandle(liveFileHandle);
        if (detailTextOut != nullptr)
        {
            *detailTextOut = compareError == ERROR_SUCCESS
                ? "selected image path no longer identifies the live process image"
                : "file identity comparison failed: " + formatWin32Error(compareError);
        }
        return false;
    }

    std::uint32_t volumeSerialNumber = 0U;
    std::uint64_t fileIdentity = 0U;
    bool isDirectory = false;
    DWORD identityError = ERROR_SUCCESS;
    if (!queryFileIdentity(
            liveFileHandle,
            volumeSerialNumber,
            fileIdentity,
            isDirectory,
            identityError) ||
        isDirectory)
    {
        (void)::CloseHandle(liveFileHandle);
        if (detailTextOut != nullptr)
        {
            *detailTextOut = isDirectory
                ? "process image target unexpectedly resolves to a directory"
                : "query process image file identity failed: " + formatWin32Error(identityError);
        }
        return false;
    }

    targetOut->m_fileHandle = liveFileHandle;
    targetOut->m_finalPath = queryFinalPath(liveFileHandle);
    if (targetOut->m_finalPath.empty())
    {
        targetOut->m_finalPath = liveImagePath;
    }
    targetOut->m_fileIdentity = fileIdentity;
    targetOut->m_volumeSerialNumber = volumeSerialNumber;

    if (detailTextOut != nullptr)
    {
        std::ostringstream stream;
        stream << "captured image handle; volume=0x" << std::hex << volumeSerialNumber
            << ", fileId=0x" << fileIdentity;
        *detailTextOut = stream.str();
    }
    return true;
}

bool ks::process::DeleteCapturedProcessImage(
    CapturedProcessImageDeleteTarget* const target,
    std::string* const detailTextOut)
{
    if (detailTextOut != nullptr)
    {
        detailTextOut->clear();
    }
    if (target == nullptr || !target->valid())
    {
        if (detailTextOut != nullptr)
        {
            *detailTextOut = "captured image handle is invalid";
        }
        return false;
    }

    DWORD extendedError = ERROR_SUCCESS;
    DWORD legacyError = ERROR_SUCCESS;
    bool deletionMarked = false;
    constexpr int kDeleteRetryCount = 20;
    constexpr DWORD kDeleteRetryDelayMilliseconds = 50U;
    for (int attemptIndex = 0; attemptIndex < kDeleteRetryCount; ++attemptIndex)
    {
        deletionMarked = setDeleteDispositionOnce(
            static_cast<HANDLE>(target->m_fileHandle),
            extendedError,
            legacyError);
        if (deletionMarked)
        {
            break;
        }
        if (attemptIndex + 1 < kDeleteRetryCount)
        {
            ::Sleep(kDeleteRetryDelayMilliseconds);
        }
    }

    std::ostringstream stream;
    stream << "volume=0x" << std::hex << target->m_volumeSerialNumber
        << ", fileId=0x" << target->m_fileIdentity;
    if (deletionMarked)
    {
        FILE_STANDARD_INFO standardInformation{};
        const bool deletePending = ::GetFileInformationByHandleEx(
            static_cast<HANDLE>(target->m_fileHandle),
            FileStandardInfo,
            &standardInformation,
            sizeof(standardInformation)) != FALSE &&
            standardInformation.DeletePending != FALSE;
        stream << ", deleteDisposition=set, deletePending=" << (deletePending ? "true" : "unknown");
        if (detailTextOut != nullptr)
        {
            *detailTextOut = stream.str();
        }
        return true;
    }

    stream << ", FileDispositionInfoEx=" << formatWin32Error(extendedError)
        << ", FileDispositionInfo=" << formatWin32Error(legacyError);
    if (detailTextOut != nullptr)
    {
        *detailTextOut = stream.str();
    }
    return false;
}
