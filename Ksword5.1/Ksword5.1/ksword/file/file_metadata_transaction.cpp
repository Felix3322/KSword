#include "file_metadata_transaction.h"

#include <QDateTime>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QSaveFile>
#include <QStandardPaths>
#include <QTimeZone>

#include <Aclapi.h>
#include <Bcrypt.h>
#include <ImageHlp.h>
#include <PropVarUtil.h>
#include <PropKey.h>
#include <Sddl.h>
#include <ShObjIdl_core.h>
#include <SoftPub.h>
#include <WinCrypt.h>
#include <WinIoCtl.h>
#include <WinTrust.h>
#include <mscat.h>
#include <winternl.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstring>
#include <functional>
#include <limits>
#include <memory>
#include <vector>

#pragma comment(lib, "Crypt32.lib")
#pragma comment(lib, "ImageHlp.lib")
#pragma comment(lib, "Propsys.lib")
#pragma comment(lib, "Wintrust.lib")

namespace
{
    using ks::file::metadata::BinaryPatchAction;
    using ks::file::metadata::ChangeState;
    using ks::file::metadata::ExtendedAttributeEntry;
    using ks::file::metadata::FileIdentity;
    using ks::file::metadata::FileSnapshot;
    using ks::file::metadata::NamedBinaryPatch;
    using ks::file::metadata::OperationResult;
    using ks::file::metadata::PeResourcePatch;
    using ks::file::metadata::SecurityAceRemoval;
    using ks::file::metadata::SecurityPatch;
    using ks::file::metadata::SignatureInspection;
    using ks::file::metadata::StreamEntry;
    using ks::file::metadata::TargetPatch;
    using ks::file::metadata::TargetResult;

    class Handle final
    {
    public:
        Handle(HANDLE value = INVALID_HANDLE_VALUE) noexcept
            : m_value(value)
        {
        }

        ~Handle()
        {
            reset();
        }

        Handle(const Handle&) = delete;
        Handle& operator=(const Handle&) = delete;

        Handle(Handle&& other) noexcept
            : m_value(other.release())
        {
        }

        Handle& operator=(Handle&& other) noexcept
        {
            if (this != &other)
            {
                reset(other.release());
            }
            return *this;
        }

        [[nodiscard]] HANDLE get() const noexcept { return m_value; }
        [[nodiscard]] bool valid() const noexcept
        {
            return m_value != nullptr && m_value != INVALID_HANDLE_VALUE;
        }

        HANDLE release() noexcept
        {
            const HANDLE value = m_value;
            m_value = INVALID_HANDLE_VALUE;
            return value;
        }

        void reset(HANDLE value = INVALID_HANDLE_VALUE) noexcept
        {
            if (valid())
            {
                ::CloseHandle(m_value);
            }
            m_value = value;
        }

    private:
        HANDLE m_value = INVALID_HANDLE_VALUE;
    };

    class LocalMemory final
    {
    public:
        explicit LocalMemory(void* value = nullptr) noexcept : m_value(value) {}
        ~LocalMemory() { if (m_value != nullptr) ::LocalFree(m_value); }
        LocalMemory(const LocalMemory&) = delete;
        LocalMemory& operator=(const LocalMemory&) = delete;
        [[nodiscard]] void* get() const noexcept { return m_value; }
    private:
        void* m_value = nullptr;
    };

    class FindHandle final
    {
    public:
        explicit FindHandle(HANDLE value = INVALID_HANDLE_VALUE) noexcept : m_value(value) {}
        ~FindHandle() { if (valid()) ::FindClose(m_value); }
        FindHandle(const FindHandle&) = delete;
        FindHandle& operator=(const FindHandle&) = delete;
        [[nodiscard]] HANDLE get() const noexcept { return m_value; }
        [[nodiscard]] bool valid() const noexcept
        {
            return m_value != nullptr && m_value != INVALID_HANDLE_VALUE;
        }
    private:
        HANDLE m_value = INVALID_HANDLE_VALUE;
    };

    class ComInitialization final
    {
    public:
        ComInitialization()
            : m_result(::CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE))
        {
        }
        ~ComInitialization()
        {
            if (SUCCEEDED(m_result))
            {
                ::CoUninitialize();
            }
        }
        [[nodiscard]] HRESULT result() const noexcept { return m_result; }
    private:
        HRESULT m_result = E_FAIL;
    };

    constexpr DWORD kMetadataOpenFlags = FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT;
    constexpr UCHAR kFileNeedEa = 0x80U;
    constexpr int kReparseHeaderSize = 8;
    constexpr int kReparseGuidHeaderSize = 24;

    struct FileFullEaInformation
    {
        ULONG nextEntryOffset;
        UCHAR flags;
        UCHAR eaNameLength;
        USHORT eaValueLength;
        CHAR eaName[1];
    };

    struct GenericReparseDataBuffer
    {
        ULONG reparseTag;
        USHORT reparseDataLength;
        USHORT reserved;
        UCHAR dataBuffer[1];
    };

    struct GenericReparseGuidDataBuffer
    {
        ULONG reparseTag;
        USHORT reparseDataLength;
        USHORT reserved;
        GUID reparseGuid;
        UCHAR dataBuffer[1];
    };

    [[nodiscard]] std::wstring nativePath(const QString& path)
    {
        return QDir::toNativeSeparators(path).toStdWString();
    }

    [[nodiscard]] Handle openPath(
        const QString& filePath,
        const DWORD desiredAccess,
        DWORD* errorOut,
        const DWORD flags = kMetadataOpenFlags)
    {
        const std::wstring path = nativePath(filePath);
        if (path.empty())
        {
            if (errorOut != nullptr) *errorOut = ERROR_INVALID_PARAMETER;
            return {};
        }

        Handle handle(::CreateFileW(
            path.c_str(),
            desiredAccess,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            nullptr,
            OPEN_EXISTING,
            flags,
            nullptr));
        if (errorOut != nullptr)
        {
            *errorOut = handle.valid() ? ERROR_SUCCESS : ::GetLastError();
        }
        return handle;
    }

    [[nodiscard]] FileIdentity queryIdentity(const HANDLE handle)
    {
        FileIdentity identity;
        BY_HANDLE_FILE_INFORMATION info{};
        if (::GetFileInformationByHandle(handle, &info) == FALSE)
        {
            return identity;
        }
        identity.available = true;
        identity.volumeSerialNumber = info.dwVolumeSerialNumber;
        identity.fileIndex =
            (static_cast<std::uint64_t>(info.nFileIndexHigh) << 32U) |
            static_cast<std::uint64_t>(info.nFileIndexLow);
        return identity;
    }

    [[nodiscard]] bool identityMatches(const FileIdentity& expected, const FileIdentity& current)
    {
        if (!expected.available)
        {
            return true;
        }
        return current.available &&
            expected.volumeSerialNumber == current.volumeSerialNumber &&
            expected.fileIndex == current.fileIndex;
    }

    [[nodiscard]] DWORD win32FromHresult(const HRESULT result)
    {
        if (SUCCEEDED(result)) return ERROR_SUCCESS;
        if (HRESULT_FACILITY(result) == FACILITY_WIN32)
        {
            return HRESULT_CODE(result);
        }
        return static_cast<DWORD>(result);
    }

    [[nodiscard]] QString normalizedStreamName(QString name)
    {
        name = name.trimmed();
        if (name.startsWith(QLatin1Char(':')))
        {
            name.remove(0, 1);
        }
        if (name.endsWith(QStringLiteral(":$DATA"), Qt::CaseInsensitive))
        {
            name.chop(6);
        }
        return name;
    }

    [[nodiscard]] QString streamPath(const QString& filePath, const QString& streamName)
    {
        return QDir::toNativeSeparators(filePath) + QLatin1Char(':') + normalizedStreamName(streamName);
    }

    [[nodiscard]] DWORD writeNamedStream(const QString& filePath, const NamedBinaryPatch& patch)
    {
        const QString name = normalizedStreamName(patch.name);
        if (name.isEmpty() || name.compare(QStringLiteral("$DATA"), Qt::CaseInsensitive) == 0)
        {
            return ERROR_INVALID_NAME;
        }
        const std::wstring path = streamPath(filePath, name).toStdWString();
        if (patch.action == BinaryPatchAction::Remove)
        {
            if (::DeleteFileW(path.c_str()) != FALSE)
            {
                return ERROR_SUCCESS;
            }
            return ::GetLastError();
        }

        Handle streamHandle(::CreateFileW(
            path.c_str(),
            GENERIC_WRITE | GENERIC_READ,
            FILE_SHARE_READ,
            nullptr,
            CREATE_ALWAYS,
            FILE_ATTRIBUTE_NORMAL,
            nullptr));
        if (!streamHandle.valid())
        {
            return ::GetLastError();
        }
        DWORD bytesWritten = 0U;
        if (!patch.data.isEmpty() &&
            ::WriteFile(
                streamHandle.get(),
                patch.data.constData(),
                static_cast<DWORD>(patch.data.size()),
                &bytesWritten,
                nullptr) == FALSE)
        {
            return ::GetLastError();
        }
        return bytesWritten == static_cast<DWORD>(patch.data.size())
            ? ERROR_SUCCESS
            : ERROR_WRITE_FAULT;
    }

    using NtQueryEaFileFn = NTSTATUS(NTAPI*)(
        HANDLE,
        PIO_STATUS_BLOCK,
        PVOID,
        ULONG,
        BOOLEAN,
        PVOID,
        ULONG,
        PULONG,
        BOOLEAN);
    using NtSetEaFileFn = NTSTATUS(NTAPI*)(HANDLE, PIO_STATUS_BLOCK, PVOID, ULONG);
    using RtlNtStatusToDosErrorFn = ULONG(NTAPI*)(NTSTATUS);

    struct NativeEaApis
    {
        NtQueryEaFileFn query = nullptr;
        NtSetEaFileFn set = nullptr;
        RtlNtStatusToDosErrorFn toDosError = nullptr;
    };

    [[nodiscard]] const NativeEaApis& nativeEaApis()
    {
        static const NativeEaApis apis = []()
            {
                NativeEaApis result;
                HMODULE ntdll = ::GetModuleHandleW(L"ntdll.dll");
                if (ntdll == nullptr) return result;
                result.query = reinterpret_cast<NtQueryEaFileFn>(
                    ::GetProcAddress(ntdll, "NtQueryEaFile"));
                result.set = reinterpret_cast<NtSetEaFileFn>(
                    ::GetProcAddress(ntdll, "NtSetEaFile"));
                result.toDosError = reinterpret_cast<RtlNtStatusToDosErrorFn>(
                    ::GetProcAddress(ntdll, "RtlNtStatusToDosError"));
                return result;
            }();
        return apis;
    }

    [[nodiscard]] DWORD ntStatusToWin32(const NTSTATUS status)
    {
        const NativeEaApis& apis = nativeEaApis();
        return apis.toDosError != nullptr
            ? apis.toDosError(status)
            : ERROR_GEN_FAILURE;
    }

    [[nodiscard]] DWORD writeExtendedAttribute(const QString& filePath, const NamedBinaryPatch& patch)
    {
        const QByteArray nameUtf8 = patch.name.trimmed().toUtf8();
        if (nameUtf8.isEmpty() || nameUtf8.size() > 255 || patch.data.size() > 65535)
        {
            return ERROR_INVALID_PARAMETER;
        }
        const NativeEaApis& apis = nativeEaApis();
        if (apis.set == nullptr)
        {
            return ERROR_PROC_NOT_FOUND;
        }

        DWORD openError = ERROR_SUCCESS;
        Handle handle = openPath(filePath, FILE_READ_EA | FILE_WRITE_EA, &openError);
        if (!handle.valid()) return openError;

        const QByteArray value = patch.action == BinaryPatchAction::Remove
            ? QByteArray()
            : patch.data;
        const qsizetype allocationSize =
            static_cast<qsizetype>(sizeof(FileFullEaInformation)) + nameUtf8.size() + value.size();
        QByteArray buffer(allocationSize, '\0');
        auto* ea = reinterpret_cast<FileFullEaInformation*>(buffer.data());
        ea->nextEntryOffset = 0U;
        ea->flags = patch.needEa ? kFileNeedEa : 0U;
        ea->eaNameLength = static_cast<UCHAR>(nameUtf8.size());
        ea->eaValueLength = static_cast<USHORT>(value.size());
        std::memcpy(ea->eaName, nameUtf8.constData(), static_cast<std::size_t>(nameUtf8.size()));
        ea->eaName[nameUtf8.size()] = '\0';
        if (!value.isEmpty())
        {
            std::memcpy(
                ea->eaName + nameUtf8.size() + 1,
                value.constData(),
                static_cast<std::size_t>(value.size()));
        }

        IO_STATUS_BLOCK ioStatus{};
        const NTSTATUS status = apis.set(
            handle.get(),
            &ioStatus,
            ea,
            static_cast<ULONG>(buffer.size()));
        return status >= 0 ? ERROR_SUCCESS : ntStatusToWin32(status);
    }

    [[nodiscard]] DWORD setBasicInformation(
        const QString& filePath,
        const TargetPatch& patch,
        FileSnapshot* snapshotOut)
    {
        DWORD openError = ERROR_SUCCESS;
        Handle handle = openPath(
            filePath,
            FILE_READ_ATTRIBUTES | FILE_WRITE_ATTRIBUTES,
            &openError);
        if (!handle.valid()) return openError;

        if (!identityMatches(patch.snapshot.identity, queryIdentity(handle.get())))
        {
            return ERROR_FILE_INVALID;
        }

        FILE_BASIC_INFO currentInfo{};
        if (::GetFileInformationByHandleEx(
            handle.get(), FileBasicInfo, &currentInfo, sizeof(currentInfo)) == FALSE)
        {
            return ::GetLastError();
        }

        FILE_BASIC_INFO updateInfo{};
        if (patch.basic.updateTime[0]) updateInfo.CreationTime = patch.basic.timeValue[0];
        if (patch.basic.updateTime[1]) updateInfo.LastAccessTime = patch.basic.timeValue[1];
        if (patch.basic.updateTime[2]) updateInfo.LastWriteTime = patch.basic.timeValue[2];
        if (patch.basic.updateTime[3]) updateInfo.ChangeTime = patch.basic.timeValue[3];
        if (patch.basic.updateAttributes)
        {
            updateInfo.FileAttributes = currentInfo.FileAttributes;
            updateInfo.FileAttributes &= ~ks::file::metadata::editableFileAttributeMask();
            updateInfo.FileAttributes &= ~FILE_ATTRIBUTE_NORMAL;
            updateInfo.FileAttributes |=
                patch.basic.editableAttributes & ks::file::metadata::editableFileAttributeMask();
            if (updateInfo.FileAttributes == 0U)
            {
                updateInfo.FileAttributes = FILE_ATTRIBUTE_NORMAL;
            }
        }

        if (::SetFileInformationByHandle(
            handle.get(), FileBasicInfo, &updateInfo, sizeof(updateInfo)) == FALSE)
        {
            return ::GetLastError();
        }
        if (snapshotOut != nullptr)
        {
            *snapshotOut = ks::file::metadata::readFileSnapshot(filePath);
        }
        return ERROR_SUCCESS;
    }

    [[nodiscard]] DWORD renamePath(
        const QString& currentPath,
        const QString& newName,
        QString* finalPathOut)
    {
        const QFileInfo info(currentPath);
        const QString trimmedName = newName.trimmed();
        if (trimmedName.isEmpty() ||
            trimmedName.contains(QLatin1Char('\\')) ||
            trimmedName.contains(QLatin1Char('/')))
        {
            return ERROR_INVALID_NAME;
        }
        const QString destination = QDir(info.absolutePath()).filePath(trimmedName);
        const std::wstring destinationWide = nativePath(destination);
        const std::size_t allocationSize = sizeof(FILE_RENAME_INFO) +
            destinationWide.size() * sizeof(wchar_t);
        std::vector<std::byte> buffer(allocationSize);
        auto* renameInfo = reinterpret_cast<FILE_RENAME_INFO*>(buffer.data());
        renameInfo->ReplaceIfExists = FALSE;
        renameInfo->RootDirectory = nullptr;
        renameInfo->FileNameLength = static_cast<DWORD>(destinationWide.size() * sizeof(wchar_t));
        std::memcpy(
            renameInfo->FileName,
            destinationWide.data(),
            destinationWide.size() * sizeof(wchar_t));

        DWORD openError = ERROR_SUCCESS;
        Handle handle = openPath(currentPath, DELETE | SYNCHRONIZE, &openError);
        if (!handle.valid()) return openError;
        if (::SetFileInformationByHandle(
            handle.get(), FileRenameInfo, renameInfo, static_cast<DWORD>(allocationSize)) == FALSE)
        {
            return ::GetLastError();
        }
        if (finalPathOut != nullptr) *finalPathOut = destination;
        return ERROR_SUCCESS;
    }

    [[nodiscard]] DWORD setShortName(const QString& filePath, const QString& shortName)
    {
        DWORD openError = ERROR_SUCCESS;
        Handle handle = openPath(filePath, FILE_WRITE_ATTRIBUTES, &openError);
        if (!handle.valid()) return openError;
        const std::wstring shortNameWide = shortName.trimmed().toStdWString();
        if (::SetFileShortNameW(handle.get(), shortNameWide.c_str()) == FALSE)
        {
            return ::GetLastError();
        }
        return ERROR_SUCCESS;
    }

    [[nodiscard]] DWORD setCaseSensitive(const QString& filePath, const bool enabled)
    {
        DWORD openError = ERROR_SUCCESS;
        Handle handle = openPath(filePath, FILE_WRITE_ATTRIBUTES, &openError);
        if (!handle.valid()) return openError;
        FILE_CASE_SENSITIVE_INFO info{};
        info.Flags = enabled ? FILE_CS_FLAG_CASE_SENSITIVE_DIR : 0U;
        if (::SetFileInformationByHandle(
            handle.get(), FileCaseSensitiveInfo, &info, sizeof(info)) == FALSE)
        {
            return ::GetLastError();
        }
        return ERROR_SUCCESS;
    }

    [[nodiscard]] DWORD setCompression(const QString& filePath, const bool enabled)
    {
        DWORD openError = ERROR_SUCCESS;
        Handle handle = openPath(filePath, GENERIC_READ | GENERIC_WRITE, &openError);
        if (!handle.valid()) return openError;
        USHORT format = enabled ? COMPRESSION_FORMAT_DEFAULT : COMPRESSION_FORMAT_NONE;
        DWORD returned = 0U;
        if (::DeviceIoControl(
            handle.get(), FSCTL_SET_COMPRESSION, &format, sizeof(format),
            nullptr, 0U, &returned, nullptr) == FALSE)
        {
            return ::GetLastError();
        }
        return ERROR_SUCCESS;
    }

    [[nodiscard]] DWORD setSparse(const QString& filePath, const bool enabled)
    {
        DWORD openError = ERROR_SUCCESS;
        Handle handle = openPath(filePath, GENERIC_WRITE, &openError);
        if (!handle.valid()) return openError;
        FILE_SET_SPARSE_BUFFER sparseInfo{};
        sparseInfo.SetSparse = enabled ? TRUE : FALSE;
        DWORD returned = 0U;
        if (::DeviceIoControl(
            handle.get(), FSCTL_SET_SPARSE, &sparseInfo, sizeof(sparseInfo),
            nullptr, 0U, &returned, nullptr) == FALSE)
        {
            return ::GetLastError();
        }
        return ERROR_SUCCESS;
    }

    [[nodiscard]] DWORD setEncrypted(const QString& filePath, const bool enabled)
    {
        const std::wstring path = nativePath(filePath);
        const BOOL result = enabled
            ? ::EncryptFileW(path.c_str())
            : ::DecryptFileW(path.c_str(), 0U);
        return result != FALSE ? ERROR_SUCCESS : ::GetLastError();
    }

    [[nodiscard]] DWORD setIntegrityStream(const QString& filePath, const bool enabled)
    {
        DWORD openError = ERROR_SUCCESS;
        Handle handle = openPath(filePath, GENERIC_READ | GENERIC_WRITE, &openError);
        if (!handle.valid()) return openError;
        FSCTL_SET_INTEGRITY_INFORMATION_BUFFER info{};
        info.ChecksumAlgorithm = enabled ? CHECKSUM_TYPE_CRC64 : CHECKSUM_TYPE_NONE;
        info.Flags = 0U;
        DWORD returned = 0U;
        if (::DeviceIoControl(
            handle.get(), FSCTL_SET_INTEGRITY_INFORMATION, &info, sizeof(info),
            nullptr, 0U, &returned, nullptr) == FALSE)
        {
            return ::GetLastError();
        }
        return ERROR_SUCCESS;
    }

    [[nodiscard]] DWORD setObjectId(
        const QString& filePath,
        const bool remove,
        const QByteArray& objectId)
    {
        DWORD openError = ERROR_SUCCESS;
        Handle handle = openPath(filePath, GENERIC_READ | GENERIC_WRITE, &openError);
        if (!handle.valid()) return openError;
        DWORD returned = 0U;
        if (remove)
        {
            if (::DeviceIoControl(
                handle.get(), FSCTL_DELETE_OBJECT_ID,
                nullptr, 0U, nullptr, 0U, &returned, nullptr) == FALSE)
            {
                return ::GetLastError();
            }
            return ERROR_SUCCESS;
        }
        if (objectId.size() != 16 && objectId.size() != static_cast<int>(sizeof(FILE_OBJECTID_BUFFER)))
        {
            return ERROR_INVALID_DATA;
        }
        FILE_OBJECTID_BUFFER buffer{};
        std::memcpy(
            buffer.ObjectId,
            objectId.constData(),
            static_cast<std::size_t>(std::min<qsizetype>(objectId.size(), 16)));
        if (objectId.size() == static_cast<int>(sizeof(FILE_OBJECTID_BUFFER)))
        {
            std::memcpy(&buffer, objectId.constData(), sizeof(buffer));
        }
        if (::DeviceIoControl(
            handle.get(), FSCTL_SET_OBJECT_ID,
            &buffer, sizeof(buffer), nullptr, 0U, &returned, nullptr) == FALSE)
        {
            const DWORD setError = ::GetLastError();
            if (setError != ERROR_OBJECT_ALREADY_EXISTS)
            {
                return setError;
            }
            if (::DeviceIoControl(
                handle.get(), FSCTL_DELETE_OBJECT_ID,
                nullptr, 0U, nullptr, 0U, &returned, nullptr) == FALSE)
            {
                return ::GetLastError();
            }
            if (::DeviceIoControl(
                handle.get(), FSCTL_SET_OBJECT_ID,
                &buffer, sizeof(buffer), nullptr, 0U, &returned, nullptr) == FALSE)
            {
                return ::GetLastError();
            }
        }
        return ERROR_SUCCESS;
    }

    [[nodiscard]] DWORD setRawReparseData(
        const QString& filePath,
        const bool remove,
        const QByteArray& rawBuffer)
    {
        DWORD openError = ERROR_SUCCESS;
        Handle handle = openPath(filePath, GENERIC_READ | GENERIC_WRITE, &openError);
        if (!handle.valid()) return openError;
        DWORD returned = 0U;
        if (remove)
        {
            if (rawBuffer.size() < kReparseHeaderSize)
            {
                return ERROR_INVALID_REPARSE_DATA;
            }
            const auto* existing = reinterpret_cast<const GenericReparseDataBuffer*>(rawBuffer.constData());
            QByteArray deleteBuffer;
            if (IsReparseTagMicrosoft(existing->reparseTag))
            {
                deleteBuffer.resize(kReparseHeaderSize);
                auto* data = reinterpret_cast<GenericReparseDataBuffer*>(deleteBuffer.data());
                data->reparseTag = existing->reparseTag;
                data->reparseDataLength = 0U;
                data->reserved = 0U;
            }
            else
            {
                deleteBuffer.resize(kReparseGuidHeaderSize);
                auto* data = reinterpret_cast<GenericReparseGuidDataBuffer*>(deleteBuffer.data());
                data->reparseTag = existing->reparseTag;
                data->reparseDataLength = 0U;
                data->reserved = 0U;
                if (rawBuffer.size() >= kReparseGuidHeaderSize)
                {
                    const auto* source =
                        reinterpret_cast<const GenericReparseGuidDataBuffer*>(rawBuffer.constData());
                    data->reparseGuid = source->reparseGuid;
                }
            }
            if (::DeviceIoControl(
                handle.get(), FSCTL_DELETE_REPARSE_POINT,
                deleteBuffer.data(), static_cast<DWORD>(deleteBuffer.size()),
                nullptr, 0U, &returned, nullptr) == FALSE)
            {
                return ::GetLastError();
            }
            return ERROR_SUCCESS;
        }

        if (rawBuffer.size() < kReparseHeaderSize ||
            rawBuffer.size() > MAXIMUM_REPARSE_DATA_BUFFER_SIZE)
        {
            return ERROR_INVALID_REPARSE_DATA;
        }
        if (::DeviceIoControl(
            handle.get(), FSCTL_SET_REPARSE_POINT,
            const_cast<char*>(rawBuffer.constData()), static_cast<DWORD>(rawBuffer.size()),
            nullptr, 0U, &returned, nullptr) == FALSE)
        {
            return ::GetLastError();
        }
        return ERROR_SUCCESS;
    }

    [[nodiscard]] DWORD createHardLink(const QString& existingPath, const QString& linkPath)
    {
        const std::wstring link = nativePath(linkPath);
        const std::wstring existing = nativePath(existingPath);
        if (::CreateHardLinkW(link.c_str(), existing.c_str(), nullptr) == FALSE)
        {
            return ::GetLastError();
        }
        return ERROR_SUCCESS;
    }

    [[nodiscard]] DWORD applySecuritySddl(const QString& filePath, const SecurityPatch& patch)
    {
        PSECURITY_DESCRIPTOR descriptor = nullptr;
        if (::ConvertStringSecurityDescriptorToSecurityDescriptorW(
            patch.sddl.toStdWString().c_str(),
            SDDL_REVISION_1,
            &descriptor,
            nullptr) == FALSE)
        {
            return ::GetLastError();
        }
        LocalMemory descriptorGuard(descriptor);
        PSID owner = nullptr;
        PSID group = nullptr;
        PACL dacl = nullptr;
        PACL sacl = nullptr;
        BOOL defaulted = FALSE;
        BOOL present = FALSE;
        if ((patch.securityInformation & OWNER_SECURITY_INFORMATION) != 0U &&
            ::GetSecurityDescriptorOwner(descriptor, &owner, &defaulted) == FALSE)
        {
            return ::GetLastError();
        }
        if ((patch.securityInformation & GROUP_SECURITY_INFORMATION) != 0U &&
            ::GetSecurityDescriptorGroup(descriptor, &group, &defaulted) == FALSE)
        {
            return ::GetLastError();
        }
        if ((patch.securityInformation & DACL_SECURITY_INFORMATION) != 0U &&
            ::GetSecurityDescriptorDacl(descriptor, &present, &dacl, &defaulted) == FALSE)
        {
            return ::GetLastError();
        }
        if ((patch.securityInformation & SACL_SECURITY_INFORMATION) != 0U &&
            ::GetSecurityDescriptorSacl(descriptor, &present, &sacl, &defaulted) == FALSE)
        {
            return ::GetLastError();
        }

        const std::wstring normalizedPath = nativePath(filePath);
        std::vector<wchar_t> pathBuffer(normalizedPath.begin(), normalizedPath.end());
        pathBuffer.push_back(L'\0');
        return ::SetNamedSecurityInfoW(
            pathBuffer.data(),
            SE_FILE_OBJECT,
            patch.securityInformation,
            owner,
            group,
            dacl,
            sacl);
    }

    [[nodiscard]] DWORD applyAceChanges(const QString& filePath, const SecurityPatch& patch)
    {
        if (patch.aceChanges.isEmpty()) return ERROR_SUCCESS;
        PACL currentDacl = nullptr;
        PSECURITY_DESCRIPTOR descriptor = nullptr;
        const std::wstring path = nativePath(filePath);
        DWORD result = ::GetNamedSecurityInfoW(
            const_cast<wchar_t*>(path.c_str()),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            nullptr,
            nullptr,
            &currentDacl,
            nullptr,
            &descriptor);
        if (result != ERROR_SUCCESS) return result;
        LocalMemory descriptorGuard(descriptor);

        std::vector<std::wstring> trusteeNames;
        trusteeNames.reserve(static_cast<std::size_t>(patch.aceChanges.size()));
        std::vector<EXPLICIT_ACCESSW> entries(static_cast<std::size_t>(patch.aceChanges.size()));
        for (qsizetype index = 0; index < patch.aceChanges.size(); ++index)
        {
            const auto& patchEntry = patch.aceChanges.at(index);
            trusteeNames.push_back(patchEntry.trustee.toStdWString());
            EXPLICIT_ACCESSW& entry = entries[static_cast<std::size_t>(index)];
            entry.grfAccessPermissions = patchEntry.accessMask;
            entry.grfAccessMode = static_cast<ACCESS_MODE>(patchEntry.accessMode);
            entry.grfInheritance = patchEntry.inheritance;
            entry.Trustee.TrusteeForm = TRUSTEE_IS_NAME;
            entry.Trustee.TrusteeType = TRUSTEE_IS_UNKNOWN;
            entry.Trustee.ptstrName = trusteeNames.back().data();
        }
        PACL updatedDacl = nullptr;
        result = ::SetEntriesInAclW(
            static_cast<ULONG>(entries.size()),
            entries.data(),
            currentDacl,
            &updatedDacl);
        if (result != ERROR_SUCCESS) return result;
        LocalMemory daclGuard(updatedDacl);
        return ::SetNamedSecurityInfoW(
            const_cast<wchar_t*>(path.c_str()),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            nullptr,
            nullptr,
            updatedDacl,
            nullptr);
    }

    [[nodiscard]] bool removalMatches(const void* acePointer, const SecurityAceRemoval& removal)
    {
        if (acePointer == nullptr) return false;
        const auto* header = static_cast<const ACE_HEADER*>(acePointer);
        if (header->AceType != removal.aceType || header->AceFlags != removal.aceFlags)
        {
            return false;
        }
        DWORD mask = 0U;
        PSID sid = nullptr;
        switch (header->AceType)
        {
        case ACCESS_ALLOWED_ACE_TYPE:
        {
            const auto* ace = static_cast<const ACCESS_ALLOWED_ACE*>(acePointer);
            mask = ace->Mask;
            sid = const_cast<DWORD*>(&ace->SidStart);
            break;
        }
        case ACCESS_DENIED_ACE_TYPE:
        {
            const auto* ace = static_cast<const ACCESS_DENIED_ACE*>(acePointer);
            mask = ace->Mask;
            sid = const_cast<DWORD*>(&ace->SidStart);
            break;
        }
        default:
            return false;
        }
        if (mask != removal.accessMask || sid == nullptr || ::IsValidSid(sid) == FALSE)
        {
            return false;
        }
        PSID expectedSid = nullptr;
        if (::ConvertStringSidToSidW(removal.sid.toStdWString().c_str(), &expectedSid) == FALSE)
        {
            return false;
        }
        LocalMemory sidGuard(expectedSid);
        return ::EqualSid(sid, expectedSid) != FALSE;
    }

    [[nodiscard]] DWORD applyAceRemovals(const QString& filePath, const SecurityPatch& patch)
    {
        if (patch.aceRemovals.isEmpty()) return ERROR_SUCCESS;
        PACL currentDacl = nullptr;
        PSECURITY_DESCRIPTOR descriptor = nullptr;
        const std::wstring path = nativePath(filePath);
        DWORD result = ::GetNamedSecurityInfoW(
            const_cast<wchar_t*>(path.c_str()),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            nullptr,
            nullptr,
            &currentDacl,
            nullptr,
            &descriptor);
        if (result != ERROR_SUCCESS) return result;
        LocalMemory descriptorGuard(descriptor);
        if (currentDacl == nullptr) return ERROR_INVALID_ACL;

        ACL_SIZE_INFORMATION sizeInfo{};
        if (::GetAclInformation(currentDacl, &sizeInfo, sizeof(sizeInfo), AclSizeInformation) == FALSE)
        {
            return ::GetLastError();
        }
        std::vector<std::byte> aclBuffer(sizeInfo.AclBytesInUse + 64U);
        PACL newDacl = reinterpret_cast<PACL>(aclBuffer.data());
        if (::InitializeAcl(newDacl, static_cast<DWORD>(aclBuffer.size()), ACL_REVISION) == FALSE)
        {
            return ::GetLastError();
        }
        for (DWORD index = 0U; index < sizeInfo.AceCount; ++index)
        {
            void* ace = nullptr;
            if (::GetAce(currentDacl, index, &ace) == FALSE) return ::GetLastError();
            const bool remove = std::any_of(
                patch.aceRemovals.cbegin(),
                patch.aceRemovals.cend(),
                [ace](const SecurityAceRemoval& item) { return removalMatches(ace, item); });
            if (!remove)
            {
                const auto* header = static_cast<const ACE_HEADER*>(ace);
                if (::AddAce(newDacl, ACL_REVISION, MAXDWORD, ace, header->AceSize) == FALSE)
                {
                    return ::GetLastError();
                }
            }
        }
        return ::SetNamedSecurityInfoW(
            const_cast<wchar_t*>(path.c_str()),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            nullptr,
            nullptr,
            newDacl,
            nullptr);
    }

    [[nodiscard]] PROPVARIANT stringVariant(const QString& text, HRESULT* resultOut)
    {
        PROPVARIANT value;
        ::PropVariantInit(&value);
        *resultOut = ::InitPropVariantFromString(text.toStdWString().c_str(), &value);
        return value;
    }

    [[nodiscard]] PROPVARIANT stringListVariant(const QStringList& texts, HRESULT* resultOut)
    {
        std::vector<std::wstring> values;
        std::vector<PCWSTR> pointers;
        values.reserve(static_cast<std::size_t>(texts.size()));
        pointers.reserve(static_cast<std::size_t>(texts.size()));
        for (const QString& text : texts) values.push_back(text.toStdWString());
        for (const std::wstring& value : values) pointers.push_back(value.c_str());
        PROPVARIANT result;
        ::PropVariantInit(&result);
        *resultOut = ::InitPropVariantFromStringVector(
            pointers.data(), static_cast<ULONG>(pointers.size()), &result);
        return result;
    }

    [[nodiscard]] DWORD applyShellProperties(
        const QString& filePath,
        const ks::file::metadata::ShellPropertyPatch& patch)
    {
        ComInitialization com;
        if (FAILED(com.result()) && com.result() != RPC_E_CHANGED_MODE)
        {
            return win32FromHresult(com.result());
        }
        IPropertyStore* store = nullptr;
        const HRESULT openResult = ::SHGetPropertyStoreFromParsingName(
            nativePath(filePath).c_str(),
            nullptr,
            GPS_READWRITE,
            IID_PPV_ARGS(&store));
        if (FAILED(openResult)) return win32FromHresult(openResult);

        const auto setValue = [store](const PROPERTYKEY& key, PROPVARIANT& value) -> HRESULT
            {
                const HRESULT result = store->SetValue(key, value);
                ::PropVariantClear(&value);
                return result;
            };
        HRESULT result = S_OK;
        if (patch.updateTitle)
        {
            PROPVARIANT value = stringVariant(patch.title, &result);
            if (SUCCEEDED(result)) result = setValue(PKEY_Title, value);
        }
        if (SUCCEEDED(result) && patch.updateSubject)
        {
            PROPVARIANT value = stringVariant(patch.subject, &result);
            if (SUCCEEDED(result)) result = setValue(PKEY_Subject, value);
        }
        if (SUCCEEDED(result) && patch.updateAuthors)
        {
            PROPVARIANT value = stringListVariant(patch.authors, &result);
            if (SUCCEEDED(result)) result = setValue(PKEY_Author, value);
        }
        if (SUCCEEDED(result) && patch.updateKeywords)
        {
            PROPVARIANT value = stringListVariant(patch.keywords, &result);
            if (SUCCEEDED(result)) result = setValue(PKEY_Keywords, value);
        }
        if (SUCCEEDED(result) && patch.updateComment)
        {
            PROPVARIANT value = stringVariant(patch.comment, &result);
            if (SUCCEEDED(result)) result = setValue(PKEY_Comment, value);
        }
        if (SUCCEEDED(result) && patch.updateCopyright)
        {
            PROPVARIANT value = stringVariant(patch.copyright, &result);
            if (SUCCEEDED(result)) result = setValue(PKEY_Copyright, value);
        }
        if (SUCCEEDED(result) && patch.updateRating)
        {
            PROPVARIANT value;
            ::PropVariantInit(&value);
            result = ::InitPropVariantFromUInt32(patch.rating, &value);
            if (SUCCEEDED(result)) result = setValue(PKEY_Rating, value);
        }
        if (SUCCEEDED(result)) result = store->Commit();
        store->Release();
        return win32FromHresult(result);
    }

    struct ResourceIdentifier
    {
        bool integer = false;
        WORD id = 0U;
        std::wstring text;

        [[nodiscard]] LPCWSTR pointer() const
        {
            return integer ? MAKEINTRESOURCEW(id) : text.c_str();
        }
    };

    [[nodiscard]] bool parseResourceIdentifier(const QString& value, ResourceIdentifier* output)
    {
        if (output == nullptr) return false;
        const QString trimmed = value.trimmed();
        bool ok = false;
        const uint numeric = trimmed.startsWith(QLatin1Char('#'))
            ? trimmed.mid(1).toUInt(&ok, 0)
            : trimmed.toUInt(&ok, 0);
        if (ok && numeric <= std::numeric_limits<WORD>::max())
        {
            output->integer = true;
            output->id = static_cast<WORD>(numeric);
            return true;
        }
        if (trimmed.isEmpty()) return false;
        output->integer = false;
        output->text = trimmed.toStdWString();
        return true;
    }

    [[nodiscard]] DWORD applyPeResources(const QString& filePath, const QList<PeResourcePatch>& patches)
    {
        const std::wstring path = nativePath(filePath);
        HANDLE updateHandle = ::BeginUpdateResourceW(path.c_str(), FALSE);
        if (updateHandle == nullptr) return ::GetLastError();
        for (const PeResourcePatch& patch : patches)
        {
            ResourceIdentifier type;
            ResourceIdentifier name;
            if (!parseResourceIdentifier(patch.type, &type) ||
                !parseResourceIdentifier(patch.name, &name))
            {
                ::EndUpdateResourceW(updateHandle, TRUE);
                return ERROR_INVALID_PARAMETER;
            }
            LPVOID data = patch.action == BinaryPatchAction::Remove
                ? nullptr
                : const_cast<char*>(patch.data.constData());
            const DWORD size = patch.action == BinaryPatchAction::Remove
                ? 0U
                : static_cast<DWORD>(patch.data.size());
            if (::UpdateResourceW(
                updateHandle,
                type.pointer(),
                name.pointer(),
                patch.language,
                data,
                size) == FALSE)
            {
                const DWORD error = ::GetLastError();
                ::EndUpdateResourceW(updateHandle, TRUE);
                return error;
            }
        }
        if (::EndUpdateResourceW(updateHandle, FALSE) == FALSE)
        {
            return ::GetLastError();
        }
        return ERROR_SUCCESS;
    }

    [[nodiscard]] DWORD removeEmbeddedCertificates(const QString& filePath)
    {
        DWORD openError = ERROR_SUCCESS;
        Handle handle = openPath(
            filePath,
            GENERIC_READ | GENERIC_WRITE,
            &openError,
            FILE_ATTRIBUTE_NORMAL);
        if (!handle.valid()) return openError;
        DWORD count = 0U;
        if (::ImageEnumerateCertificates(
            handle.get(), CERT_SECTION_TYPE_ANY, &count, nullptr, 0U) == FALSE)
        {
            return ::GetLastError();
        }
        for (DWORD index = count; index > 0U; --index)
        {
            if (::ImageRemoveCertificate(handle.get(), index - 1U) == FALSE)
            {
                return ::GetLastError();
            }
        }
        return ERROR_SUCCESS;
    }

    [[nodiscard]] bool hasEmbeddedCertificate(const QString& filePath)
    {
        DWORD openError = ERROR_SUCCESS;
        Handle handle = openPath(filePath, GENERIC_READ, &openError, FILE_ATTRIBUTE_NORMAL);
        if (!handle.valid()) return false;
        DWORD count = 0U;
        return ::ImageEnumerateCertificates(
            handle.get(), CERT_SECTION_TYPE_ANY, &count, nullptr, 0U) != FALSE && count > 0U;
    }

    [[nodiscard]] QString certificateName(
        PCCERT_CONTEXT certificate,
        const DWORD type,
        const DWORD flags = 0U)
    {
        if (certificate == nullptr) return {};
        const DWORD length = ::CertGetNameStringW(
            certificate, type, flags, nullptr, nullptr, 0U);
        if (length <= 1U) return {};
        std::wstring text(length, L'\0');
        ::CertGetNameStringW(certificate, type, flags, nullptr, text.data(), length);
        text.resize(length - 1U);
        return QString::fromStdWString(text);
    }

    [[nodiscard]] QString fileTimeText(const FILETIME& fileTime)
    {
        ULARGE_INTEGER value{};
        value.LowPart = fileTime.dwLowDateTime;
        value.HighPart = fileTime.dwHighDateTime;
        constexpr quint64 epoch = 116444736000000000ULL;
        if (value.QuadPart < epoch) return {};
        const qint64 milliseconds = static_cast<qint64>((value.QuadPart - epoch) / 10000ULL);
        return QDateTime::fromMSecsSinceEpoch(milliseconds, QTimeZone::UTC)
            .toLocalTime()
            .toString(QStringLiteral("yyyy-MM-dd HH:mm:ss"));
    }

    [[nodiscard]] QString certificateFingerprint(PCCERT_CONTEXT certificate)
    {
        if (certificate == nullptr) return {};
        DWORD hashSize = 0U;
        if (::CryptHashCertificate2(
            BCRYPT_SHA256_ALGORITHM,
            0U,
            nullptr,
            certificate->pbCertEncoded,
            certificate->cbCertEncoded,
            nullptr,
            &hashSize) == FALSE || hashSize == 0U)
        {
            return {};
        }
        QByteArray hash(static_cast<int>(hashSize), '\0');
        if (::CryptHashCertificate2(
            BCRYPT_SHA256_ALGORITHM,
            0U,
            nullptr,
            certificate->pbCertEncoded,
            certificate->cbCertEncoded,
            reinterpret_cast<BYTE*>(hash.data()),
            &hashSize) == FALSE)
        {
            return {};
        }
        return QString::fromLatin1(hash.toHex(' ').toUpper());
    }

    [[nodiscard]] QString findCatalogPath(const QString& filePath)
    {
        DWORD openError = ERROR_SUCCESS;
        Handle fileHandle = openPath(filePath, GENERIC_READ, &openError, FILE_ATTRIBUTE_NORMAL);
        if (!fileHandle.valid()) return {};
        HCATADMIN admin = nullptr;
        if (::CryptCATAdminAcquireContext2(
            &admin, nullptr, BCRYPT_SHA256_ALGORITHM, nullptr, 0U) == FALSE)
        {
            return {};
        }
        DWORD hashSize = 0U;
        if (::CryptCATAdminCalcHashFromFileHandle2(
            admin, fileHandle.get(), &hashSize, nullptr, 0U) == FALSE || hashSize == 0U)
        {
            ::CryptCATAdminReleaseContext(admin, 0U);
            return {};
        }
        QByteArray hash(static_cast<int>(hashSize), '\0');
        if (::CryptCATAdminCalcHashFromFileHandle2(
            admin,
            fileHandle.get(),
            &hashSize,
            reinterpret_cast<BYTE*>(hash.data()),
            0U) == FALSE)
        {
            ::CryptCATAdminReleaseContext(admin, 0U);
            return {};
        }
        HCATINFO catalog = ::CryptCATAdminEnumCatalogFromHash(
            admin,
            reinterpret_cast<BYTE*>(hash.data()),
            hashSize,
            0U,
            nullptr);
        QString path;
        if (catalog != nullptr)
        {
            CATALOG_INFO info{};
            info.cbStruct = sizeof(info);
            if (::CryptCATCatalogInfoFromContext(catalog, &info, 0U) != FALSE)
            {
                path = QString::fromWCharArray(info.wszCatalogFile);
            }
            ::CryptCATAdminReleaseCatalogContext(admin, catalog, 0U);
        }
        ::CryptCATAdminReleaseContext(admin, 0U);
        return path;
    }

    [[nodiscard]] QString readSecuritySddl(
        const QString& filePath,
        SECURITY_INFORMATION* informationOut)
    {
        const std::wstring path = nativePath(filePath);
        SECURITY_INFORMATION information =
            OWNER_SECURITY_INFORMATION |
            GROUP_SECURITY_INFORMATION |
            DACL_SECURITY_INFORMATION |
            SACL_SECURITY_INFORMATION |
            LABEL_SECURITY_INFORMATION;
        PSECURITY_DESCRIPTOR descriptor = nullptr;
        DWORD result = ::GetNamedSecurityInfoW(
            const_cast<wchar_t*>(path.c_str()),
            SE_FILE_OBJECT,
            information,
            nullptr,
            nullptr,
            nullptr,
            nullptr,
            &descriptor);
        if (result != ERROR_SUCCESS)
        {
            information = OWNER_SECURITY_INFORMATION |
                GROUP_SECURITY_INFORMATION |
                DACL_SECURITY_INFORMATION;
            result = ::GetNamedSecurityInfoW(
                const_cast<wchar_t*>(path.c_str()),
                SE_FILE_OBJECT,
                information,
                nullptr,
                nullptr,
                nullptr,
                nullptr,
                &descriptor);
        }
        if (result != ERROR_SUCCESS) return {};
        LocalMemory descriptorGuard(descriptor);
        LPWSTR sddl = nullptr;
        if (::ConvertSecurityDescriptorToStringSecurityDescriptorW(
            descriptor, SDDL_REVISION_1, information, &sddl, nullptr) == FALSE)
        {
            return {};
        }
        LocalMemory sddlGuard(sddl);
        if (informationOut != nullptr) *informationOut = information;
        return QString::fromWCharArray(sddl);
    }

    struct BackupState
    {
        FileSnapshot snapshot;
        QByteArray rawReparse;
        QByteArray objectId;
        QString securitySddl;
        SECURITY_INFORMATION securityInformation = 0U;
        QList<QPair<QString, QByteArray>> streams;
        QList<ExtendedAttributeEntry> extendedAttributes;
    };

    [[nodiscard]] QString safeBackupName(const QString& path, const int index)
    {
        QString name = QFileInfo(path).fileName();
        if (name.isEmpty()) name = QStringLiteral("target");
        static const QString invalidCharacters = QStringLiteral("<>:\\/|?*");
        for (const QChar character : invalidCharacters)
        {
            name.replace(character, QLatin1Char('_'));
        }
        return QStringLiteral("%1-%2").arg(index + 1, 4, 10, QLatin1Char('0')).arg(name);
    }

    [[nodiscard]] QString ensureBackupRoot(const QString& requestedRoot)
    {
        QString root = requestedRoot.trimmed();
        if (root.isEmpty())
        {
            root = QDir(QStandardPaths::writableLocation(QStandardPaths::TempLocation))
                .filePath(QStringLiteral("KSword/MetadataBackups/%1")
                    .arg(QDateTime::currentDateTime().toString(QStringLiteral("yyyyMMdd-HHmmss-zzz"))));
        }
        return QDir().mkpath(root) ? QDir::cleanPath(root) : QString();
    }

    [[nodiscard]] DWORD createBackup(
        const QString& backupRoot,
        const QString& originalPath,
        const int index,
        const BackupState& state,
        QString* backupPathOut)
    {
        const QFileInfo info(originalPath);
        const QString baseName = safeBackupName(originalPath, index);
        if (info.isFile())
        {
            const QString backupPath = QDir(backupRoot).filePath(
                baseName + QStringLiteral(".file-backup"));
            if (!QFile::copy(originalPath, backupPath))
            {
                return ERROR_WRITE_FAULT;
            }
            if (backupPathOut != nullptr) *backupPathOut = backupPath;
            return ERROR_SUCCESS;
        }

        const QString manifestPath = QDir(backupRoot).filePath(baseName + QStringLiteral(".metadata.txt"));
        QSaveFile manifest(manifestPath);
        if (!manifest.open(QIODevice::WriteOnly | QIODevice::Text))
        {
            return ERROR_WRITE_FAULT;
        }
        QByteArray content;
        content += QByteArrayLiteral("path=") + QDir::toNativeSeparators(originalPath).toUtf8() + '\n';
        content += QByteArrayLiteral("attributes=") + QByteArray::number(state.snapshot.basicInfo.FileAttributes, 16) + '\n';
        content += QByteArrayLiteral("creation=") + QByteArray::number(state.snapshot.basicInfo.CreationTime.QuadPart) + '\n';
        content += QByteArrayLiteral("access=") + QByteArray::number(state.snapshot.basicInfo.LastAccessTime.QuadPart) + '\n';
        content += QByteArrayLiteral("write=") + QByteArray::number(state.snapshot.basicInfo.LastWriteTime.QuadPart) + '\n';
        content += QByteArrayLiteral("change=") + QByteArray::number(state.snapshot.basicInfo.ChangeTime.QuadPart) + '\n';
        content += QByteArrayLiteral("reparse=") + state.rawReparse.toHex() + '\n';
        content += QByteArrayLiteral("object_id=") + state.objectId.toHex() + '\n';
        content += QByteArrayLiteral("sddl=") + state.securitySddl.toUtf8() + '\n';
        if (manifest.write(content) != content.size() || !manifest.commit())
        {
            return ERROR_WRITE_FAULT;
        }
        if (backupPathOut != nullptr) *backupPathOut = manifestPath;
        return ERROR_SUCCESS;
    }

    [[nodiscard]] bool rollbackTarget(
        const QString& originalPath,
        const QString& currentPath,
        const QString& backupPath,
        const BackupState& state,
        const QStringList& createdHardLinks)
    {
        for (const QString& hardLinkPath : createdHardLinks)
        {
            const std::wstring hardLink = nativePath(hardLinkPath);
            if (::DeleteFileW(hardLink.c_str()) == FALSE && ::GetLastError() != ERROR_FILE_NOT_FOUND)
            {
                return false;
            }
        }
        QString restorePath = currentPath;
        if (QFileInfo(backupPath).isFile() && !backupPath.endsWith(QStringLiteral(".metadata.txt")))
        {
            if (QDir::cleanPath(currentPath).compare(QDir::cleanPath(originalPath), Qt::CaseInsensitive) != 0)
            {
                const std::wstring current = nativePath(currentPath);
                const std::wstring original = nativePath(originalPath);
                if (::MoveFileExW(current.c_str(), original.c_str(), MOVEFILE_REPLACE_EXISTING) == FALSE)
                {
                    return false;
                }
                restorePath = originalPath;
            }
            const std::wstring backup = nativePath(backupPath);
            const std::wstring restore = nativePath(restorePath);
            if (::CopyFileW(backup.c_str(), restore.c_str(), FALSE) == FALSE)
            {
                return false;
            }
        }

        TargetPatch restorePatch;
        restorePatch.originalPath = originalPath;
        restorePatch.snapshot = ks::file::metadata::readFileSnapshot(restorePath);
        restorePatch.basic.updateTime.fill(true);
        restorePatch.basic.timeValue = {
            state.snapshot.basicInfo.CreationTime,
            state.snapshot.basicInfo.LastAccessTime,
            state.snapshot.basicInfo.LastWriteTime,
            state.snapshot.basicInfo.ChangeTime };
        restorePatch.basic.updateAttributes = true;
        restorePatch.basic.editableAttributes =
            state.snapshot.basicInfo.FileAttributes & ks::file::metadata::editableFileAttributeMask();
        if (setBasicInformation(restorePath, restorePatch, nullptr) != ERROR_SUCCESS)
        {
            return false;
        }
        const DWORD originalAttributes = state.snapshot.basicInfo.FileAttributes;
        const FileSnapshot structuralSnapshot =
            ks::file::metadata::readFileSnapshot(restorePath);
        if (!structuralSnapshot.ok)
        {
            return false;
        }
        const DWORD currentAttributes = structuralSnapshot.basicInfo.FileAttributes;
        if (((originalAttributes ^ currentAttributes) & FILE_ATTRIBUTE_COMPRESSED) != 0U &&
            setCompression(restorePath,
                (originalAttributes & FILE_ATTRIBUTE_COMPRESSED) != 0U) != ERROR_SUCCESS)
        {
            return false;
        }
        if (!state.snapshot.directory &&
            ((originalAttributes ^ currentAttributes) & FILE_ATTRIBUTE_SPARSE_FILE) != 0U &&
            setSparse(restorePath,
                (originalAttributes & FILE_ATTRIBUTE_SPARSE_FILE) != 0U) != ERROR_SUCCESS)
        {
            return false;
        }
        if (((originalAttributes ^ currentAttributes) & FILE_ATTRIBUTE_ENCRYPTED) != 0U &&
            setEncrypted(restorePath,
                (originalAttributes & FILE_ATTRIBUTE_ENCRYPTED) != 0U) != ERROR_SUCCESS)
        {
            return false;
        }
        if (((originalAttributes ^ currentAttributes) & FILE_ATTRIBUTE_INTEGRITY_STREAM) != 0U &&
            setIntegrityStream(restorePath,
                (originalAttributes & FILE_ATTRIBUTE_INTEGRITY_STREAM) != 0U) != ERROR_SUCCESS)
        {
            return false;
        }

        DWORD currentReparseError = ERROR_SUCCESS;
        const QByteArray currentReparse =
            ks::file::metadata::readRawReparseData(restorePath, &currentReparseError);
        if (!state.rawReparse.isEmpty())
        {
            if (setRawReparseData(restorePath, false, state.rawReparse) != ERROR_SUCCESS)
                return false;
        }
        else if (currentReparseError == ERROR_SUCCESS && !currentReparse.isEmpty())
        {
            if (setRawReparseData(restorePath, true, currentReparse) != ERROR_SUCCESS)
                return false;
        }

        DWORD currentObjectIdError = ERROR_SUCCESS;
        const QByteArray currentObjectId =
            ks::file::metadata::readObjectId(restorePath, &currentObjectIdError);
        if (!state.objectId.isEmpty())
        {
            if (setObjectId(restorePath, false, state.objectId) != ERROR_SUCCESS)
                return false;
        }
        else if (currentObjectIdError == ERROR_SUCCESS && !currentObjectId.isEmpty())
        {
            if (setObjectId(restorePath, true, {}) != ERROR_SUCCESS)
                return false;
        }

        DWORD currentStreamError = ERROR_SUCCESS;
        const QList<StreamEntry> currentStreams =
            ks::file::metadata::enumerateStreams(restorePath, &currentStreamError);
        if (currentStreamError == ERROR_SUCCESS)
        {
            for (const StreamEntry& currentStream : currentStreams)
            {
                const bool existed = std::any_of(
                    state.streams.cbegin(), state.streams.cend(),
                    [&currentStream](const QPair<QString, QByteArray>& item)
                    {
                        return item.first.compare(currentStream.name, Qt::CaseInsensitive) == 0;
                    });
                if (!existed)
                {
                    NamedBinaryPatch remove;
                    remove.name = currentStream.name;
                    remove.action = BinaryPatchAction::Remove;
                    if (writeNamedStream(restorePath, remove) != ERROR_SUCCESS) return false;
                }
            }
        }
        for (const QPair<QString, QByteArray>& stream : state.streams)
        {
            NamedBinaryPatch replace;
            replace.name = stream.first;
            replace.data = stream.second;
            if (writeNamedStream(restorePath, replace) != ERROR_SUCCESS) return false;
        }

        DWORD currentEaError = ERROR_SUCCESS;
        const QList<ExtendedAttributeEntry> currentEas =
            ks::file::metadata::enumerateExtendedAttributes(restorePath, &currentEaError);
        if (currentEaError == ERROR_SUCCESS)
        {
            for (const ExtendedAttributeEntry& currentEa : currentEas)
            {
                const bool existed = std::any_of(
                    state.extendedAttributes.cbegin(), state.extendedAttributes.cend(),
                    [&currentEa](const ExtendedAttributeEntry& item)
                    {
                        return item.name.compare(currentEa.name, Qt::CaseInsensitive) == 0;
                    });
                if (!existed)
                {
                    NamedBinaryPatch remove;
                    remove.name = currentEa.name;
                    remove.action = BinaryPatchAction::Remove;
                    if (writeExtendedAttribute(restorePath, remove) != ERROR_SUCCESS) return false;
                }
            }
        }
        for (const ExtendedAttributeEntry& ea : state.extendedAttributes)
        {
            NamedBinaryPatch replace;
            replace.name = ea.name;
            replace.data = ea.value;
            replace.needEa = ea.needEa;
            if (writeExtendedAttribute(restorePath, replace) != ERROR_SUCCESS) return false;
        }

        if (!state.securitySddl.isEmpty())
        {
            SECURITY_INFORMATION currentSecurityInformation = 0U;
            const QString currentSecuritySddl =
                readSecuritySddl(restorePath, &currentSecurityInformation);
            if (currentSecuritySddl != state.securitySddl)
            {
                SecurityPatch security;
                security.replaceSddl = true;
                security.sddl = state.securitySddl;
                security.securityInformation = state.securityInformation;
                if (applySecuritySddl(restorePath, security) != ERROR_SUCCESS)
                {
                    return false;
                }
            }
        }
        return true;
    }

    void appendOperation(
        TargetResult* target,
        const QString& operation,
        const DWORD error,
        const bool verified = true,
        const QString& detail = {})
    {
        OperationResult result;
        result.operation = operation;
        result.ok = error == ERROR_SUCCESS;
        result.verified = result.ok && verified;
        result.win32Error = error;
        result.detail = detail;
        target->operations.push_back(result);
    }

    [[nodiscard]] bool hasBasicChanges(const TargetPatch& patch)
    {
        return patch.basic.updateAttributes ||
            std::any_of(
                patch.basic.updateTime.cbegin(),
                patch.basic.updateTime.cend(),
                [](const bool value) { return value; });
    }
}

bool ks::file::metadata::ShellPropertyPatch::empty() const
{
    return !updateTitle && !updateSubject && !updateAuthors && !updateKeywords &&
        !updateComment && !updateCopyright && !updateRating;
}

bool ks::file::metadata::SecurityPatch::empty() const
{
    return !replaceSddl && aceChanges.isEmpty() && aceRemovals.isEmpty();
}

bool ks::file::metadata::TargetPatch::empty() const
{
    return !hasBasicChanges(*this) && !rename && !setShortName &&
        caseSensitive == ChangeState::Unchanged && shellProperties.empty() &&
        streams.isEmpty() && extendedAttributes.isEmpty() && security.empty() &&
        compression == ChangeState::Unchanged && sparse == ChangeState::Unchanged &&
        encryption == ChangeState::Unchanged && integrityStream == ChangeState::Unchanged &&
        !objectId.update && hardLinkPaths.isEmpty() && !reparse.update &&
        peResources.isEmpty() && signatureDisposition == SignatureDisposition::Preserve;
}

bool ks::file::metadata::TargetPatch::highRisk() const
{
    return !extendedAttributes.isEmpty() || objectId.update || reparse.update ||
        !peResources.isEmpty() || signatureDisposition == SignatureDisposition::RemoveEmbedded;
}

bool ks::file::metadata::TargetPatch::invalidatesAuthenticode() const
{
    return !shellProperties.empty() || !streams.isEmpty() || !extendedAttributes.isEmpty() ||
        compression != ChangeState::Unchanged || sparse != ChangeState::Unchanged ||
        encryption != ChangeState::Unchanged || integrityStream != ChangeState::Unchanged ||
        objectId.update || !hardLinkPaths.isEmpty() || reparse.update || !peResources.isEmpty();
}

const std::array<DWORD, 6>& ks::file::metadata::editableFileAttributeMasks()
{
    static const std::array<DWORD, 6> masks{
        FILE_ATTRIBUTE_READONLY,
        FILE_ATTRIBUTE_HIDDEN,
        FILE_ATTRIBUTE_SYSTEM,
        FILE_ATTRIBUTE_ARCHIVE,
        FILE_ATTRIBUTE_TEMPORARY,
        FILE_ATTRIBUTE_NOT_CONTENT_INDEXED };
    return masks;
}

DWORD ks::file::metadata::editableFileAttributeMask()
{
    DWORD mask = 0U;
    for (const DWORD value : editableFileAttributeMasks()) mask |= value;
    return mask;
}

FileSnapshot ks::file::metadata::readFileSnapshot(const QString& filePath)
{
    FileSnapshot snapshot;
    DWORD openError = ERROR_SUCCESS;
    Handle handle = openPath(filePath, FILE_READ_ATTRIBUTES, &openError);
    if (!handle.valid())
    {
        snapshot.win32Error = openError;
        return snapshot;
    }
    if (::GetFileInformationByHandleEx(
        handle.get(), FileBasicInfo, &snapshot.basicInfo, sizeof(snapshot.basicInfo)) == FALSE)
    {
        snapshot.win32Error = ::GetLastError();
        return snapshot;
    }
    snapshot.ok = true;
    snapshot.win32Error = ERROR_SUCCESS;
    snapshot.identity = queryIdentity(handle.get());
    snapshot.directory = (snapshot.basicInfo.FileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0U;
    snapshot.embeddedSignature = !snapshot.directory && hasEmbeddedCertificate(filePath);
    return snapshot;
}

QList<StreamEntry> ks::file::metadata::enumerateStreams(const QString& filePath, DWORD* errorOut)
{
    QList<StreamEntry> result;
    WIN32_FIND_STREAM_DATA streamData{};
    const std::wstring path = nativePath(filePath);
    FindHandle findHandle(::FindFirstStreamW(path.c_str(), FindStreamInfoStandard, &streamData, 0U));
    if (!findHandle.valid())
    {
        const DWORD error = ::GetLastError();
        if (errorOut != nullptr) *errorOut = error == ERROR_HANDLE_EOF ? ERROR_SUCCESS : error;
        return result;
    }
    do
    {
        const QString rawName = QString::fromWCharArray(streamData.cStreamName);
        const QString name = normalizedStreamName(rawName);
        if (!name.isEmpty() && name.compare(QStringLiteral("$DATA"), Qt::CaseInsensitive) != 0)
        {
            StreamEntry entry;
            entry.name = name;
            entry.size = static_cast<quint64>(streamData.StreamSize.QuadPart);
            result.push_back(entry);
        }
    } while (::FindNextStreamW(findHandle.get(), &streamData) != FALSE);
    const DWORD finalError = ::GetLastError();
    if (errorOut != nullptr)
    {
        *errorOut = finalError == ERROR_HANDLE_EOF ? ERROR_SUCCESS : finalError;
    }
    return result;
}

QByteArray ks::file::metadata::readStream(
    const QString& filePath,
    const QString& streamName,
    DWORD* errorOut)
{
    const std::wstring path = streamPath(filePath, streamName).toStdWString();
    Handle handle(::CreateFileW(
        path.c_str(), GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr));
    if (!handle.valid())
    {
        if (errorOut != nullptr) *errorOut = ::GetLastError();
        return {};
    }
    LARGE_INTEGER size{};
    if (::GetFileSizeEx(handle.get(), &size) == FALSE || size.QuadPart > 16LL * 1024LL * 1024LL)
    {
        if (errorOut != nullptr) *errorOut = size.QuadPart > 16LL * 1024LL * 1024LL
            ? ERROR_FILE_TOO_LARGE
            : ::GetLastError();
        return {};
    }
    QByteArray data(static_cast<int>(size.QuadPart), '\0');
    DWORD bytesRead = 0U;
    if (!data.isEmpty() && ::ReadFile(
        handle.get(), data.data(), static_cast<DWORD>(data.size()), &bytesRead, nullptr) == FALSE)
    {
        if (errorOut != nullptr) *errorOut = ::GetLastError();
        return {};
    }
    data.resize(static_cast<int>(bytesRead));
    if (errorOut != nullptr) *errorOut = ERROR_SUCCESS;
    return data;
}

QList<ExtendedAttributeEntry> ks::file::metadata::enumerateExtendedAttributes(
    const QString& filePath,
    DWORD* errorOut)
{
    QList<ExtendedAttributeEntry> result;
    const NativeEaApis& apis = nativeEaApis();
    if (apis.query == nullptr)
    {
        if (errorOut != nullptr) *errorOut = ERROR_PROC_NOT_FOUND;
        return result;
    }
    DWORD openError = ERROR_SUCCESS;
    Handle handle = openPath(filePath, FILE_READ_EA, &openError);
    if (!handle.valid())
    {
        if (errorOut != nullptr) *errorOut = openError;
        return result;
    }
    QByteArray buffer(64 * 1024, '\0');
    IO_STATUS_BLOCK ioStatus{};
    const NTSTATUS status = apis.query(
        handle.get(), &ioStatus, buffer.data(), static_cast<ULONG>(buffer.size()),
        FALSE, nullptr, 0U, nullptr, TRUE);
    constexpr NTSTATUS noEaStatus = static_cast<NTSTATUS>(0xC0000052L);
    if (status == noEaStatus)
    {
        if (errorOut != nullptr) *errorOut = ERROR_SUCCESS;
        return result;
    }
    if (status < 0)
    {
        if (errorOut != nullptr) *errorOut = ntStatusToWin32(status);
        return result;
    }
    ULONG offset = 0U;
    const ULONG validBytes = static_cast<ULONG>(ioStatus.Information);
    while (offset + sizeof(FileFullEaInformation) <= validBytes)
    {
        const auto* ea = reinterpret_cast<const FileFullEaInformation*>(buffer.constData() + offset);
        const ULONG required = static_cast<ULONG>(sizeof(FileFullEaInformation)) +
            ea->eaNameLength + 1U + ea->eaValueLength;
        if (offset + required > validBytes) break;
        ExtendedAttributeEntry entry;
        entry.name = QString::fromUtf8(ea->eaName, ea->eaNameLength);
        entry.value = QByteArray(
            ea->eaName + ea->eaNameLength + 1,
            ea->eaValueLength);
        entry.needEa = (ea->flags & kFileNeedEa) != 0U;
        result.push_back(entry);
        if (ea->nextEntryOffset == 0U) break;
        offset += ea->nextEntryOffset;
    }
    if (errorOut != nullptr) *errorOut = ERROR_SUCCESS;
    return result;
}

ks::file::metadata::ShellProperties ks::file::metadata::readShellProperties(const QString& filePath)
{
    ShellProperties result;
    ComInitialization com;
    if (FAILED(com.result()) && com.result() != RPC_E_CHANGED_MODE)
    {
        result.win32Error = win32FromHresult(com.result());
        return result;
    }
    IPropertyStore* store = nullptr;
    const HRESULT openResult = ::SHGetPropertyStoreFromParsingName(
        nativePath(filePath).c_str(), nullptr, GPS_DEFAULT, IID_PPV_ARGS(&store));
    if (FAILED(openResult))
    {
        result.win32Error = win32FromHresult(openResult);
        return result;
    }
    const auto readString = [store](const PROPERTYKEY& key) -> QString
        {
            PROPVARIANT value;
            ::PropVariantInit(&value);
            QString text;
            if (SUCCEEDED(store->GetValue(key, &value)))
            {
                PWSTR allocated = nullptr;
                if (SUCCEEDED(::PropVariantToStringAlloc(value, &allocated)) && allocated != nullptr)
                {
                    text = QString::fromWCharArray(allocated);
                    ::CoTaskMemFree(allocated);
                }
            }
            ::PropVariantClear(&value);
            return text;
        };
    const auto readStringList = [store](const PROPERTYKEY& key) -> QStringList
        {
            PROPVARIANT value;
            ::PropVariantInit(&value);
            QStringList texts;
            if (SUCCEEDED(store->GetValue(key, &value)))
            {
                const ULONG count = ::PropVariantGetElementCount(value);
                for (ULONG index = 0U; index < count; ++index)
                {
                    PWSTR allocated = nullptr;
                    if (SUCCEEDED(::PropVariantGetStringElem(value, index, &allocated)) && allocated != nullptr)
                    {
                        texts.push_back(QString::fromWCharArray(allocated));
                        ::CoTaskMemFree(allocated);
                    }
                }
            }
            ::PropVariantClear(&value);
            return texts;
        };
    result.title = readString(PKEY_Title);
    result.subject = readString(PKEY_Subject);
    result.authors = readStringList(PKEY_Author);
    result.keywords = readStringList(PKEY_Keywords);
    result.comment = readString(PKEY_Comment);
    result.copyright = readString(PKEY_Copyright);
    PROPVARIANT rating;
    ::PropVariantInit(&rating);
    if (SUCCEEDED(store->GetValue(PKEY_Rating, &rating)))
    {
        ULONG value = 0U;
        if (SUCCEEDED(::PropVariantToUInt32(rating, &value))) result.rating = value;
    }
    ::PropVariantClear(&rating);
    store->Release();
    result.ok = true;
    result.win32Error = ERROR_SUCCESS;
    return result;
}

QString ks::file::metadata::readSecurityDescriptorSddl(const QString& filePath, DWORD* errorOut)
{
    PSECURITY_DESCRIPTOR descriptor = nullptr;
    const std::wstring path = nativePath(filePath);
    SECURITY_INFORMATION information =
        OWNER_SECURITY_INFORMATION |
        GROUP_SECURITY_INFORMATION |
        DACL_SECURITY_INFORMATION;
    DWORD result = ::GetNamedSecurityInfoW(
        const_cast<wchar_t*>(path.c_str()),
        SE_FILE_OBJECT,
        information,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        &descriptor);
    if (result != ERROR_SUCCESS)
    {
        if (errorOut != nullptr) *errorOut = result;
        return {};
    }
    LocalMemory descriptorGuard(descriptor);
    LPWSTR sddl = nullptr;
    if (::ConvertSecurityDescriptorToStringSecurityDescriptorW(
        descriptor, SDDL_REVISION_1, information, &sddl, nullptr) == FALSE)
    {
        if (errorOut != nullptr) *errorOut = ::GetLastError();
        return {};
    }
    LocalMemory sddlGuard(sddl);
    if (errorOut != nullptr) *errorOut = ERROR_SUCCESS;
    return QString::fromWCharArray(sddl);
}

DWORD ks::file::metadata::queryEffectiveAccessMask(
    const QString& filePath,
    const QString& trustee,
    DWORD* accessMaskOut)
{
    if (accessMaskOut == nullptr || trustee.trimmed().isEmpty())
    {
        return ERROR_INVALID_PARAMETER;
    }
    *accessMaskOut = 0U;
    PACL dacl = nullptr;
    PSECURITY_DESCRIPTOR descriptor = nullptr;
    const std::wstring path = nativePath(filePath);
    DWORD result = ::GetNamedSecurityInfoW(
        const_cast<wchar_t*>(path.c_str()),
        SE_FILE_OBJECT,
        DACL_SECURITY_INFORMATION,
        nullptr,
        nullptr,
        &dacl,
        nullptr,
        &descriptor);
    if (result != ERROR_SUCCESS) return result;
    LocalMemory descriptorGuard(descriptor);
    std::wstring trusteeName = trustee.trimmed().toStdWString();
    TRUSTEEW trusteeInfo{};
    ::BuildTrusteeWithNameW(&trusteeInfo, trusteeName.data());
    return ::GetEffectiveRightsFromAclW(dacl, &trusteeInfo, accessMaskOut);
}

QByteArray ks::file::metadata::readRawReparseData(const QString& filePath, DWORD* errorOut)
{
    DWORD openError = ERROR_SUCCESS;
    Handle handle = openPath(filePath, GENERIC_READ, &openError);
    if (!handle.valid())
    {
        if (errorOut != nullptr) *errorOut = openError;
        return {};
    }
    QByteArray buffer(MAXIMUM_REPARSE_DATA_BUFFER_SIZE, '\0');
    DWORD returned = 0U;
    if (::DeviceIoControl(
        handle.get(), FSCTL_GET_REPARSE_POINT,
        nullptr, 0U, buffer.data(), static_cast<DWORD>(buffer.size()),
        &returned, nullptr) == FALSE)
    {
        if (errorOut != nullptr) *errorOut = ::GetLastError();
        return {};
    }
    buffer.resize(static_cast<int>(returned));
    if (errorOut != nullptr) *errorOut = ERROR_SUCCESS;
    return buffer;
}

QByteArray ks::file::metadata::readObjectId(const QString& filePath, DWORD* errorOut)
{
    DWORD openError = ERROR_SUCCESS;
    Handle handle = openPath(filePath, GENERIC_READ, &openError);
    if (!handle.valid())
    {
        if (errorOut != nullptr) *errorOut = openError;
        return {};
    }
    FILE_OBJECTID_BUFFER buffer{};
    DWORD returned = 0U;
    if (::DeviceIoControl(
        handle.get(), FSCTL_GET_OBJECT_ID,
        nullptr, 0U, &buffer, sizeof(buffer), &returned, nullptr) == FALSE)
    {
        if (errorOut != nullptr) *errorOut = ::GetLastError();
        return {};
    }
    if (errorOut != nullptr) *errorOut = ERROR_SUCCESS;
    return QByteArray(reinterpret_cast<const char*>(&buffer), sizeof(buffer));
}

QStringList ks::file::metadata::enumerateHardLinks(const QString& filePath, DWORD* errorOut)
{
    QStringList links;
    DWORD length = 1024U;
    std::vector<wchar_t> buffer(length);
    const std::wstring path = nativePath(filePath);
    HANDLE findHandle = ::FindFirstFileNameW(path.c_str(), 0U, &length, buffer.data());
    if (findHandle == INVALID_HANDLE_VALUE && ::GetLastError() == ERROR_MORE_DATA)
    {
        buffer.resize(length);
        findHandle = ::FindFirstFileNameW(path.c_str(), 0U, &length, buffer.data());
    }
    if (findHandle == INVALID_HANDLE_VALUE)
    {
        if (errorOut != nullptr) *errorOut = ::GetLastError();
        return links;
    }
    links.push_back(QString::fromWCharArray(buffer.data()));
    for (;;)
    {
        length = static_cast<DWORD>(buffer.size());
        if (::FindNextFileNameW(findHandle, &length, buffer.data()) != FALSE)
        {
            links.push_back(QString::fromWCharArray(buffer.data()));
            continue;
        }
        const DWORD error = ::GetLastError();
        if (error == ERROR_MORE_DATA)
        {
            buffer.resize(length);
            if (::FindNextFileNameW(findHandle, &length, buffer.data()) != FALSE)
            {
                links.push_back(QString::fromWCharArray(buffer.data()));
                continue;
            }
        }
        if (errorOut != nullptr) *errorOut = error == ERROR_HANDLE_EOF ? ERROR_SUCCESS : error;
        break;
    }
    ::FindClose(findHandle);
    return links;
}

QByteArray ks::file::metadata::readPeResource(
    const QString& filePath,
    const QString& typeText,
    const QString& nameText,
    const WORD language,
    DWORD* errorOut)
{
    ResourceIdentifier type;
    ResourceIdentifier name;
    if (!parseResourceIdentifier(typeText, &type) ||
        !parseResourceIdentifier(nameText, &name))
    {
        if (errorOut != nullptr) *errorOut = ERROR_INVALID_PARAMETER;
        return {};
    }
    HMODULE module = ::LoadLibraryExW(
        nativePath(filePath).c_str(),
        nullptr,
        LOAD_LIBRARY_AS_DATAFILE_EXCLUSIVE | LOAD_LIBRARY_AS_IMAGE_RESOURCE);
    if (module == nullptr)
    {
        if (errorOut != nullptr) *errorOut = ::GetLastError();
        return {};
    }
    HRSRC resource = ::FindResourceExW(module, type.pointer(), name.pointer(), language);
    if (resource == nullptr && language != 0U)
    {
        resource = ::FindResourceW(module, name.pointer(), type.pointer());
    }
    if (resource == nullptr)
    {
        const DWORD error = ::GetLastError();
        ::FreeLibrary(module);
        if (errorOut != nullptr) *errorOut = error;
        return {};
    }
    const DWORD size = ::SizeofResource(module, resource);
    HGLOBAL loaded = ::LoadResource(module, resource);
    const void* data = loaded != nullptr ? ::LockResource(loaded) : nullptr;
    QByteArray result;
    if (data != nullptr && size > 0U)
    {
        result = QByteArray(static_cast<const char*>(data), static_cast<int>(size));
    }
    ::FreeLibrary(module);
    if (errorOut != nullptr) *errorOut = data != nullptr ? ERROR_SUCCESS : ERROR_RESOURCE_DATA_NOT_FOUND;
    return result;
}

SignatureInspection ks::file::metadata::inspectSignature(const QString& filePath)
{
    SignatureInspection result;
    result.embedded = hasEmbeddedCertificate(filePath);
    result.catalogPath = findCatalogPath(filePath);
    result.catalog = !result.catalogPath.isEmpty();

    WINTRUST_FILE_INFO fileInfo{};
    fileInfo.cbStruct = sizeof(fileInfo);
    const std::wstring path = nativePath(filePath);
    fileInfo.pcwszFilePath = path.c_str();

    WINTRUST_DATA trustData{};
    trustData.cbStruct = sizeof(trustData);
    trustData.dwUIChoice = WTD_UI_NONE;
    trustData.fdwRevocationChecks = WTD_REVOKE_WHOLECHAIN;
    trustData.dwUnionChoice = WTD_CHOICE_FILE;
    trustData.pFile = &fileInfo;
    trustData.dwStateAction = WTD_STATEACTION_VERIFY;
    trustData.dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL | WTD_REVOCATION_CHECK_CHAIN;
    GUID action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    result.trustStatus = ::WinVerifyTrust(nullptr, &action, &trustData);

    CRYPT_PROVIDER_DATA* providerData = ::WTHelperProvDataFromStateData(trustData.hWVTStateData);
    if (providerData != nullptr)
    {
        CRYPT_PROVIDER_SGNR* signer = ::WTHelperGetProvSignerFromChain(providerData, 0U, FALSE, 0U);
        if (signer != nullptr && signer->csCertChain > 0U)
        {
            PCCERT_CONTEXT certificate = signer->pasCertChain[0].pCert;
            result.signer = certificateName(certificate, CERT_NAME_SIMPLE_DISPLAY_TYPE);
            result.issuer = certificateName(
                certificate,
                CERT_NAME_SIMPLE_DISPLAY_TYPE,
                CERT_NAME_ISSUER_FLAG);
            result.sha256Fingerprint = certificateFingerprint(certificate);
            result.validFrom = fileTimeText(certificate->pCertInfo->NotBefore);
            result.validUntil = fileTimeText(certificate->pCertInfo->NotAfter);
            result.chainStatus = QStringLiteral("0x%1")
                .arg(signer->dwError, 8, 16, QLatin1Char('0'));
        }
        CRYPT_PROVIDER_SGNR* counterSigner =
            ::WTHelperGetProvSignerFromChain(providerData, 0U, TRUE, 0U);
        if (counterSigner != nullptr && counterSigner->csCertChain > 0U)
        {
            result.timestampSigner = certificateName(
                counterSigner->pasCertChain[0].pCert,
                CERT_NAME_SIMPLE_DISPLAY_TYPE);
        }
    }
    trustData.dwStateAction = WTD_STATEACTION_CLOSE;
    ::WinVerifyTrust(nullptr, &action, &trustData);
    return result;
}

ks::file::metadata::TransactionResult ks::file::metadata::executeTransaction(
    const QList<TargetPatch>& patches,
    const TransactionOptions& options)
{
    TransactionResult transaction;
    if (patches.isEmpty())
    {
        transaction.ok = true;
        return transaction;
    }
    if (options.createBackup)
    {
        transaction.backupRoot = ensureBackupRoot(options.backupRoot);
        if (transaction.backupRoot.isEmpty())
        {
            return transaction;
        }
    }

    bool allSucceeded = true;
    for (qsizetype patchIndex = 0; patchIndex < patches.size(); ++patchIndex)
    {
        const TargetPatch& patch = patches.at(patchIndex);
        TargetResult target;
        target.originalPath = patch.originalPath;
        target.finalPath = patch.originalPath;

        BackupState backupState;
        backupState.snapshot = readFileSnapshot(patch.originalPath);
        if (!backupState.snapshot.ok)
        {
            appendOperation(&target, QStringLiteral("identity"), backupState.snapshot.win32Error, false);
            target.ok = false;
            transaction.targets.push_back(target);
            allSucceeded = false;
            continue;
        }
        if (!identityMatches(patch.snapshot.identity, backupState.snapshot.identity))
        {
            appendOperation(&target, QStringLiteral("identity"), ERROR_FILE_INVALID, false);
            target.ok = false;
            transaction.targets.push_back(target);
            allSucceeded = false;
            continue;
        }
        appendOperation(&target, QStringLiteral("identity"), ERROR_SUCCESS, true);

        DWORD reparseError = ERROR_SUCCESS;
        backupState.rawReparse = readRawReparseData(patch.originalPath, &reparseError);
        DWORD objectIdError = ERROR_SUCCESS;
        backupState.objectId = readObjectId(patch.originalPath, &objectIdError);
        backupState.securitySddl = readSecuritySddl(
            patch.originalPath,
            &backupState.securityInformation);
        DWORD backupStreamError = ERROR_SUCCESS;
        const QList<StreamEntry> backupStreams =
            enumerateStreams(patch.originalPath, &backupStreamError);
        if (backupStreamError == ERROR_SUCCESS)
        {
            for (const StreamEntry& stream : backupStreams)
            {
                DWORD readError = ERROR_SUCCESS;
                const QByteArray data = readStream(patch.originalPath, stream.name, &readError);
                if (readError == ERROR_SUCCESS)
                    backupState.streams.push_back(qMakePair(stream.name, data));
            }
        }
        DWORD backupEaError = ERROR_SUCCESS;
        backupState.extendedAttributes =
            enumerateExtendedAttributes(patch.originalPath, &backupEaError);

        if (patch.highRisk() && !options.createBackup)
        {
            appendOperation(&target, QStringLiteral("backup-required"), ERROR_CANCELLED, false);
            target.ok = false;
            transaction.targets.push_back(target);
            allSucceeded = false;
            continue;
        }
        if (options.createBackup)
        {
            const DWORD backupError = createBackup(
                transaction.backupRoot,
                patch.originalPath,
                static_cast<int>(patchIndex),
                backupState,
                &target.backupPath);
            appendOperation(&target, QStringLiteral("backup"), backupError, backupError == ERROR_SUCCESS);
            if (backupError != ERROR_SUCCESS)
            {
                target.ok = false;
                transaction.targets.push_back(target);
                allSucceeded = false;
                continue;
            }
        }

        DWORD firstError = ERROR_SUCCESS;
        QStringList createdHardLinks;
        const auto execute = [&target, &firstError](
            const QString& operation,
            const std::function<DWORD()>& callback,
            const bool verified = true)
            {
                if (firstError != ERROR_SUCCESS) return;
                const DWORD error = callback();
                appendOperation(&target, operation, error, verified);
                if (error != ERROR_SUCCESS) firstError = error;
            };

        if (hasBasicChanges(patch))
        {
            execute(QStringLiteral("basic"), [&]()
                {
                    return setBasicInformation(target.finalPath, patch, &target.finalSnapshot);
                });
        }
        if (patch.rename)
        {
            execute(QStringLiteral("rename"), [&]()
                {
                    return renamePath(target.finalPath, patch.newName, &target.finalPath);
                });
        }
        if (patch.setShortName)
        {
            execute(QStringLiteral("short-name"), [&]()
                {
                    return setShortName(target.finalPath, patch.shortName);
                });
        }
        if (patch.caseSensitive != ChangeState::Unchanged)
        {
            execute(QStringLiteral("case-sensitive"), [&]()
                {
                    return setCaseSensitive(target.finalPath, patch.caseSensitive == ChangeState::Enabled);
                });
        }
        if (!patch.shellProperties.empty())
        {
            execute(QStringLiteral("shell-properties"), [&]()
                {
                    return applyShellProperties(target.finalPath, patch.shellProperties);
                });
        }
        for (const NamedBinaryPatch& stream : patch.streams)
        {
            execute(QStringLiteral("ads:%1").arg(stream.name), [&]()
                {
                    return writeNamedStream(target.finalPath, stream);
                });
        }
        for (const NamedBinaryPatch& ea : patch.extendedAttributes)
        {
            execute(QStringLiteral("ea:%1").arg(ea.name), [&]()
                {
                    return writeExtendedAttribute(target.finalPath, ea);
                });
        }
        if (!patch.security.empty())
        {
            if (patch.security.replaceSddl)
            {
                execute(QStringLiteral("security-sddl"), [&]()
                    {
                        return applySecuritySddl(target.finalPath, patch.security);
                    });
            }
            execute(QStringLiteral("security-ace"), [&]()
                {
                    return applyAceChanges(target.finalPath, patch.security);
                });
            execute(QStringLiteral("security-remove-ace"), [&]()
                {
                    return applyAceRemovals(target.finalPath, patch.security);
                });
        }
        if (patch.compression != ChangeState::Unchanged)
        {
            execute(QStringLiteral("compression"), [&]()
                {
                    return setCompression(target.finalPath, patch.compression == ChangeState::Enabled);
                });
        }
        if (patch.sparse != ChangeState::Unchanged)
        {
            execute(QStringLiteral("sparse"), [&]()
                {
                    return setSparse(target.finalPath, patch.sparse == ChangeState::Enabled);
                });
        }
        if (patch.encryption != ChangeState::Unchanged)
        {
            execute(QStringLiteral("encryption"), [&]()
                {
                    return setEncrypted(target.finalPath, patch.encryption == ChangeState::Enabled);
                });
        }
        if (patch.integrityStream != ChangeState::Unchanged)
        {
            execute(QStringLiteral("integrity-stream"), [&]()
                {
                    return setIntegrityStream(target.finalPath, patch.integrityStream == ChangeState::Enabled);
                });
        }
        if (patch.objectId.update)
        {
            execute(QStringLiteral("object-id"), [&]()
                {
                    return setObjectId(target.finalPath, patch.objectId.remove, patch.objectId.objectId);
                });
        }
        for (const QString& hardLinkPath : patch.hardLinkPaths)
        {
            execute(QStringLiteral("hard-link:%1").arg(hardLinkPath), [&]()
                {
                    const DWORD error = createHardLink(target.finalPath, hardLinkPath);
                    if (error == ERROR_SUCCESS) createdHardLinks.push_back(hardLinkPath);
                    return error;
                });
        }
        if (patch.reparse.update)
        {
            const QByteArray rawData = patch.reparse.remove
                ? backupState.rawReparse
                : patch.reparse.rawBuffer;
            execute(QStringLiteral("reparse"), [&]()
                {
                    return setRawReparseData(target.finalPath, patch.reparse.remove, rawData);
                });
        }
        if (!patch.peResources.isEmpty())
        {
            execute(QStringLiteral("pe-resources"), [&]()
                {
                    return applyPeResources(target.finalPath, patch.peResources);
                });
        }
        if (patch.signatureDisposition == SignatureDisposition::RemoveEmbedded)
        {
            execute(QStringLiteral("signature-remove"), [&]()
                {
                    return removeEmbeddedCertificates(target.finalPath);
                });
        }

        if (firstError != ERROR_SUCCESS)
        {
            target.rollbackAttempted = options.createBackup;
            target.rollbackOk = options.createBackup && rollbackTarget(
                target.originalPath,
                target.finalPath,
                target.backupPath,
                backupState,
                createdHardLinks);
            appendOperation(
                &target,
                QStringLiteral("rollback"),
                target.rollbackOk ? ERROR_SUCCESS : firstError,
                target.rollbackOk);
            target.ok = false;
            allSucceeded = false;
        }
        else
        {
            target.finalSnapshot = readFileSnapshot(target.finalPath);
            const bool identityVerified = target.finalSnapshot.ok &&
                identityMatches(backupState.snapshot.identity, target.finalSnapshot.identity);
            appendOperation(
                &target,
                QStringLiteral("readback"),
                target.finalSnapshot.ok ? ERROR_SUCCESS : target.finalSnapshot.win32Error,
                identityVerified);
            target.ok = target.finalSnapshot.ok && identityVerified;
            if (!target.ok)
            {
                target.rollbackAttempted = options.createBackup;
                target.rollbackOk = options.createBackup && rollbackTarget(
                    target.originalPath,
                    target.finalPath,
                    target.backupPath,
                    backupState,
                    createdHardLinks);
                appendOperation(
                    &target,
                    QStringLiteral("rollback"),
                    target.rollbackOk ? ERROR_SUCCESS : ERROR_READ_FAULT,
                    target.rollbackOk);
                allSucceeded = false;
            }
        }
        transaction.targets.push_back(target);
    }
    transaction.ok = allSucceeded;
    return transaction;
}
