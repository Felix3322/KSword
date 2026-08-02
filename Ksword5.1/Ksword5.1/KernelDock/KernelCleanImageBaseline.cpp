#include "KernelCleanImageBaseline.h"

#include "../ArkDriverClient/ArkDriverClient.h"
#include "../Internationalization/LanguageManager.h"

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#include <bcrypt.h>
#include <wincrypt.h>
#include <mscat.h>
#include <Softpub.h>
#include <WinTrust.h>
#include <winternl.h>

#include <QByteArray>
#include <QCoreApplication>
#include <QFile>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonParseError>
#include <QSet>
#include <QStringList>
#include <QCryptographicHash>
#include <QDir>
#include <QFileInfo>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstring>
#include <iterator>
#include <limits>
#include <optional>
#include <utility>
#include <vector>

#pragma comment(lib, "Wintrust.lib")

namespace
{
    constexpr unsigned long kSystemModuleInformationClass = 11UL;

    QString baselineText(const QString& sourceText)
    {
        return ks::i18n::sourceText(sourceText);
    }

    struct KernelModuleRow
    {
        HANDLE section;
        PVOID mappedBase;
        PVOID imageBase;
        ULONG imageSize;
        ULONG flags;
        USHORT loadOrderIndex;
        USHORT initOrderIndex;
        USHORT loadCount;
        USHORT fileNameOffset;
        UCHAR fullPathName[256];
    };

    struct KernelModuleList
    {
        ULONG count;
        KernelModuleRow rows[1];
    };

    struct LoadedModule
    {
        std::uint64_t base = 0;
        std::uint32_t size = 0;
        QString ntPath;
        QString filePath;
        QString name;
    };

    using NtQuerySystemInformationFunction =
        NTSTATUS(NTAPI*)(ULONG, PVOID, ULONG, PULONG);

    class ReadOnlyTrustFile final
    {
    public:
        explicit ReadOnlyTrustFile(const QString& path)
            : handle(::CreateFileW(
                  reinterpret_cast<LPCWSTR>(path.utf16()),
                  GENERIC_READ,
                  FILE_SHARE_READ,
                  nullptr,
                  OPEN_EXISTING,
                  FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN,
                  nullptr))
        {
        }

        ~ReadOnlyTrustFile()
        {
            if (handle != INVALID_HANDLE_VALUE)
            {
                ::CloseHandle(handle);
            }
        }

        ReadOnlyTrustFile(const ReadOnlyTrustFile&) = delete;
        ReadOnlyTrustFile& operator=(const ReadOnlyTrustFile&) = delete;

        HANDLE handle = INVALID_HANDLE_VALUE;
    };

    class CatalogAdminContext final
    {
    public:
        ~CatalogAdminContext()
        {
            if (handle != nullptr)
            {
                ::CryptCATAdminReleaseContext(handle, 0);
            }
        }

        CatalogAdminContext(const CatalogAdminContext&) = delete;
        CatalogAdminContext& operator=(const CatalogAdminContext&) = delete;
        CatalogAdminContext() = default;

        HCATADMIN handle = nullptr;
    };

    void initializeStrictTrustData(WINTRUST_DATA& trustData)
    {
        trustData = WINTRUST_DATA{};
        trustData.cbStruct = sizeof(trustData);
        trustData.dwUIChoice = WTD_UI_NONE;
        trustData.fdwRevocationChecks = WTD_REVOKE_WHOLECHAIN;
        trustData.dwProvFlags =
            WTD_SAFER_FLAG |
            WTD_CACHE_ONLY_URL_RETRIEVAL |
            WTD_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT |
            WTD_DISABLE_MD2_MD4;
    }

    LONG runWinTrustAndClose(WINTRUST_DATA& trustData)
    {
        GUID policyGuid = WINTRUST_ACTION_GENERIC_VERIFY_V2;
        trustData.dwStateAction = WTD_STATEACTION_VERIFY;
        const LONG status =
            ::WinVerifyTrust(nullptr, &policyGuid, &trustData);
        trustData.dwStateAction = WTD_STATEACTION_CLOSE;
        ::WinVerifyTrust(nullptr, &policyGuid, &trustData);
        trustData.hWVTStateData = nullptr;
        return status;
    }

    bool calculateCatalogHash(
        const HCATADMIN catalogAdmin,
        const HANDLE fileHandle,
        std::vector<BYTE>& hashOut)
    {
        LARGE_INTEGER fileStart{};
        hashOut.clear();
        ::SetFilePointerEx(fileHandle, fileStart, nullptr, FILE_BEGIN);
        DWORD hashBytes = 0U;
        if (!::CryptCATAdminCalcHashFromFileHandle2(
                catalogAdmin,
                fileHandle,
                &hashBytes,
                nullptr,
                0) ||
            hashBytes == 0U)
        {
            return false;
        }
        hashOut.resize(hashBytes);
        ::SetFilePointerEx(fileHandle, fileStart, nullptr, FILE_BEGIN);
        if (!::CryptCATAdminCalcHashFromFileHandle2(
                catalogAdmin,
                fileHandle,
                &hashBytes,
                hashOut.data(),
                0))
        {
            hashOut.clear();
            return false;
        }
        hashOut.resize(hashBytes);
        return true;
    }

    bool verifyCatalogTrust(
        const QString& path,
        const HANDLE fileHandle)
    {
        CatalogAdminContext catalogAdmin;
        GUID driverActionVerify = DRIVER_ACTION_VERIFY;
        if (!::CryptCATAdminAcquireContext2(
                &catalogAdmin.handle,
                &driverActionVerify,
                BCRYPT_SHA256_ALGORITHM,
                nullptr,
                0))
        {
            return false;
        }

        std::vector<BYTE> hash;
        if (!calculateCatalogHash(
                catalogAdmin.handle,
                fileHandle,
                hash))
        {
            return false;
        }
        const QByteArray fileHashBytes(
            reinterpret_cast<const char*>(hash.data()),
            static_cast<qsizetype>(hash.size()));
        const QByteArray memberTagBytes =
            fileHashBytes.toHex().toUpper();
        const QString memberTag = QString::fromLatin1(
            memberTagBytes.constData(),
            memberTagBytes.size());

        HCATINFO previousCatalog = nullptr;
        for (;;)
        {
            HCATINFO currentCatalog =
                ::CryptCATAdminEnumCatalogFromHash(
                    catalogAdmin.handle,
                    hash.data(),
                    static_cast<DWORD>(hash.size()),
                    0,
                    &previousCatalog);
            if (currentCatalog == nullptr)
            {
                // Enum consumes/releases the previous context when advancing.
                // Natural exhaustion therefore leaves no caller-owned HCATINFO.
                return false;
            }
            previousCatalog = currentCatalog;

            CATALOG_INFO catalogInfo{};
            catalogInfo.cbStruct = sizeof(catalogInfo);
            if (!::CryptCATCatalogInfoFromContext(
                    currentCatalog,
                    &catalogInfo,
                    0))
            {
                continue;
            }

            WINTRUST_CATALOG_INFO trustCatalogInfo{};
            trustCatalogInfo.cbStruct = sizeof(trustCatalogInfo);
            trustCatalogInfo.pcwszCatalogFilePath =
                catalogInfo.wszCatalogFile;
            trustCatalogInfo.pcwszMemberTag =
                reinterpret_cast<LPCWSTR>(memberTag.utf16());
            trustCatalogInfo.pcwszMemberFilePath =
                reinterpret_cast<LPCWSTR>(path.utf16());
            trustCatalogInfo.hMemberFile = fileHandle;
            trustCatalogInfo.pbCalculatedFileHash = hash.data();
            trustCatalogInfo.cbCalculatedFileHash =
                static_cast<DWORD>(hash.size());
            trustCatalogInfo.hCatAdmin = catalogAdmin.handle;

            LARGE_INTEGER fileStart{};
            ::SetFilePointerEx(
                fileHandle,
                fileStart,
                nullptr,
                FILE_BEGIN);
            WINTRUST_DATA trustData{};
            initializeStrictTrustData(trustData);
            trustData.dwUnionChoice = WTD_CHOICE_CATALOG;
            trustData.pCatalog = &trustCatalogInfo;
            if (runWinTrustAndClose(trustData) == ERROR_SUCCESS)
            {
                ::CryptCATAdminReleaseCatalogContext(
                    catalogAdmin.handle,
                    currentCatalog,
                    0);
                previousCatalog = nullptr;
                return true;
            }
        }
    }

    bool readDiskImage(
        const HANDLE fileHandle,
        QByteArray& bytesOut)
    {
        bytesOut.clear();
        if (fileHandle == INVALID_HANDLE_VALUE)
        {
            return false;
        }

        LARGE_INTEGER fileSize{};
        constexpr LONGLONG maximumImageBytes =
            512LL * 1024LL * 1024LL;
        if (!::GetFileSizeEx(fileHandle, &fileSize) ||
            fileSize.QuadPart < 0 ||
            fileSize.QuadPart > maximumImageBytes ||
            fileSize.QuadPart >
                static_cast<LONGLONG>(
                    std::numeric_limits<qsizetype>::max()))
        {
            return false;
        }
        LARGE_INTEGER fileStart{};
        if (!::SetFilePointerEx(
                fileHandle,
                fileStart,
                nullptr,
                FILE_BEGIN))
        {
            return false;
        }

        bytesOut.resize(static_cast<qsizetype>(fileSize.QuadPart));
        qsizetype offset = 0;
        while (offset < bytesOut.size())
        {
            const qsizetype remaining = bytesOut.size() - offset;
            const DWORD requestBytes = static_cast<DWORD>(
                std::min<qsizetype>(remaining, MAXDWORD));
            DWORD bytesRead = 0U;
            if (!::ReadFile(
                    fileHandle,
                    bytesOut.data() + offset,
                    requestBytes,
                    &bytesRead,
                    nullptr) ||
                bytesRead == 0U)
            {
                bytesOut.clear();
                return false;
            }
            offset += static_cast<qsizetype>(bytesRead);
        }
        return true;
    }

    bool readTrustedDiskImage(
        const QString& path,
        const HANDLE fileHandle,
        QByteArray& bytesOut)
    {
        bytesOut.clear();
        if (fileHandle == INVALID_HANDLE_VALUE)
        {
            return false;
        }

        WINTRUST_FILE_INFO fileInfo{};
        fileInfo.cbStruct = sizeof(fileInfo);
        fileInfo.pcwszFilePath =
            reinterpret_cast<LPCWSTR>(path.utf16());
        fileInfo.hFile = fileHandle;

        WINTRUST_DATA trustData{};
        initializeStrictTrustData(trustData);
        trustData.dwUnionChoice = WTD_CHOICE_FILE;
        trustData.pFile = &fileInfo;
        const bool trusted =
            runWinTrustAndClose(trustData) == ERROR_SUCCESS ||
            verifyCatalogTrust(path, fileHandle);
        return trusted &&
            readDiskImage(fileHandle, bytesOut);
    }

    QString normalizeKernelPath(const QString& input)
    {
        QString path = input.trimmed();
        if (path.isEmpty())
        {
            return {};
        }
        path.replace(QLatin1Char('/'), QLatin1Char('\\'));
        if (path.startsWith(QStringLiteral("\\SystemRoot\\"),
                Qt::CaseInsensitive))
        {
            wchar_t windowsDirectory[MAX_PATH] = {};
            const UINT length = ::GetWindowsDirectoryW(
                windowsDirectory,
                static_cast<UINT>(std::size(windowsDirectory)));
            if (length != 0U
                && length < static_cast<UINT>(std::size(windowsDirectory)))
            {
                return QDir::cleanPath(
                    QString::fromWCharArray(windowsDirectory)
                    + path.mid(11));
            }
        }
        if (path.startsWith(QStringLiteral("\\??\\")))
        {
            return QDir::cleanPath(path.mid(4));
        }
        if (path.size() >= 3
            && path.at(1) == QLatin1Char(':')
            && path.at(2) == QLatin1Char('\\'))
        {
            return QDir::cleanPath(path);
        }
        if (path.startsWith(QStringLiteral("\\Device\\"),
                Qt::CaseInsensitive))
        {
            for (wchar_t drive = L'A'; drive <= L'Z'; ++drive)
            {
                wchar_t driveName[3] = { drive, L':', L'\0' };
                std::vector<wchar_t> target(32768U, L'\0');
                const DWORD chars = ::QueryDosDeviceW(
                    driveName,
                    target.data(),
                    static_cast<DWORD>(target.size()));
                if (chars == 0U)
                {
                    continue;
                }
                const QString devicePrefix =
                    QString::fromWCharArray(target.data());
                if (path.startsWith(devicePrefix, Qt::CaseInsensitive))
                {
                    return QDir::cleanPath(
                        QString::fromWCharArray(driveName)
                        + path.mid(devicePrefix.size()));
                }
            }
        }
        return QDir::cleanPath(path);
    }

    bool enumerateLoadedModules(
        std::vector<LoadedModule>& modulesOut,
        QString& errorTextOut)
    {
        modulesOut.clear();
        errorTextOut.clear();
        const HMODULE ntdll = ::GetModuleHandleW(L"ntdll.dll");
        if (ntdll == nullptr)
        {
            errorTextOut = QStringLiteral("无法获取 ntdll 模块句柄。");
            return false;
        }
        const auto query = reinterpret_cast<NtQuerySystemInformationFunction>(
            ::GetProcAddress(ntdll, "NtQuerySystemInformation"));
        if (query == nullptr)
        {
            errorTextOut =
                QStringLiteral("无法解析系统模块枚举入口。");
            return false;
        }

        ULONG required = 0U;
        NTSTATUS status = query(
            kSystemModuleInformationClass,
            nullptr,
            0U,
            &required);
        if (required < sizeof(KernelModuleList))
        {
            required = 1024U * 1024U;
        }
        for (int attempt = 0; attempt < 4; ++attempt)
        {
            std::vector<std::uint8_t> buffer(
                static_cast<std::size_t>(required) + 64U * 1024U,
                0U);
            ULONG returned = 0U;
            status = query(
                kSystemModuleInformationClass,
                buffer.data(),
                static_cast<ULONG>(buffer.size()),
                &returned);
            if (status == static_cast<NTSTATUS>(0xC0000004L))
            {
                required = std::max<ULONG>(
                    returned,
                    static_cast<ULONG>(buffer.size() * 2U));
                continue;
            }
            if (status < 0)
            {
                errorTextOut = QStringLiteral(
                    "系统模块枚举失败，NTSTATUS=0x%1。")
                    .arg(static_cast<unsigned long>(status),
                        8,
                        16,
                        QChar('0'));
                return false;
            }

            const auto* list =
                reinterpret_cast<const KernelModuleList*>(buffer.data());
            const std::size_t maximumRows =
                (buffer.size() - offsetof(KernelModuleList, rows))
                / sizeof(KernelModuleRow);
            const std::size_t rows = std::min<std::size_t>(
                list->count,
                maximumRows);
            modulesOut.reserve(rows);
            for (std::size_t index = 0; index < rows; ++index)
            {
                const KernelModuleRow& source = list->rows[index];
                LoadedModule module;
                module.base = reinterpret_cast<std::uintptr_t>(
                    source.imageBase);
                module.size = source.imageSize;
                module.ntPath = QString::fromLocal8Bit(
                    reinterpret_cast<const char*>(source.fullPathName),
                    static_cast<int>(strnlen_s(
                        reinterpret_cast<const char*>(
                            source.fullPathName),
                        sizeof(source.fullPathName))));
                module.filePath = normalizeKernelPath(module.ntPath);
                const int nameOffset = std::min<int>(
                    source.fileNameOffset,
                    module.ntPath.size());
                module.name = module.ntPath.mid(nameOffset);
                modulesOut.push_back(std::move(module));
            }
            return true;
        }
        errorTextOut = QStringLiteral("系统模块列表在重试后仍持续变化。");
        return false;
    }

    const LoadedModule* moduleForAddress(
        const std::vector<LoadedModule>& modules,
        const std::uint64_t address)
    {
        for (const LoadedModule& module : modules)
        {
            if (address >= module.base
                && address - module.base < module.size)
            {
                return &module;
            }
        }
        return nullptr;
    }

    template <typename T>
    bool copyStructure(
        const QByteArray& bytes,
        const std::uint64_t offset,
        T& valueOut)
    {
        if (offset > static_cast<std::uint64_t>(bytes.size())
            || sizeof(T)
                > static_cast<std::uint64_t>(bytes.size()) - offset)
        {
            return false;
        }
        std::memcpy(
            &valueOut,
            bytes.constData() + static_cast<qsizetype>(offset),
            sizeof(T));
        return true;
    }

    struct PeIdentity
    {
        bool valid = false;
        std::uint16_t machine = 0;
        std::uint32_t timestamp = 0;
        std::uint32_t sizeOfImage = 0;
        std::uint32_t checkSum = 0;
        std::uint32_t sizeOfHeaders = 0;
        std::uint32_t relocationRva = 0;
        std::uint32_t relocationSize = 0;
        std::uint64_t preferredImageBase = 0;
        std::uint64_t sectionTableOffset = 0;
        std::uint16_t sectionCount = 0;
    };

    bool parsePeIdentity(
        const QByteArray& bytes,
        PeIdentity& identityOut,
        QString& errorTextOut)
    {
        identityOut = {};
        IMAGE_DOS_HEADER dos = {};
        if (!copyStructure(bytes, 0U, dos)
            || dos.e_magic != IMAGE_DOS_SIGNATURE
            || dos.e_lfanew <= 0)
        {
            errorTextOut = QStringLiteral("映像 DOS 头无效。");
            return false;
        }

        const std::uint64_t ntOffset =
            static_cast<std::uint32_t>(dos.e_lfanew);
        DWORD signature = 0U;
        IMAGE_FILE_HEADER fileHeader = {};
        if (!copyStructure(bytes, ntOffset, signature)
            || signature != IMAGE_NT_SIGNATURE
            || !copyStructure(
                bytes,
                ntOffset + sizeof(signature),
                fileHeader))
        {
            errorTextOut = QStringLiteral("映像 PE 头无效。");
            return false;
        }

        const std::uint64_t optionalOffset =
            ntOffset + sizeof(signature) + sizeof(fileHeader);
        WORD magic = 0U;
        if (!copyStructure(bytes, optionalOffset, magic))
        {
            errorTextOut = QStringLiteral("映像可选头缺失。");
            return false;
        }
        if (magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
        {
            IMAGE_OPTIONAL_HEADER64 optional = {};
            if (!copyStructure(bytes, optionalOffset, optional))
            {
                errorTextOut = QStringLiteral("PE32+ 可选头不完整。");
                return false;
            }
            identityOut.sizeOfImage = optional.SizeOfImage;
            identityOut.checkSum = optional.CheckSum;
            identityOut.sizeOfHeaders = optional.SizeOfHeaders;
            identityOut.preferredImageBase = optional.ImageBase;
            if (optional.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_BASERELOC)
            {
                identityOut.relocationRva =
                    optional.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC]
                        .VirtualAddress;
                identityOut.relocationSize =
                    optional.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC]
                        .Size;
            }
        }
        else if (magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
        {
            IMAGE_OPTIONAL_HEADER32 optional = {};
            if (!copyStructure(bytes, optionalOffset, optional))
            {
                errorTextOut = QStringLiteral("PE32 可选头不完整。");
                return false;
            }
            identityOut.sizeOfImage = optional.SizeOfImage;
            identityOut.checkSum = optional.CheckSum;
            identityOut.sizeOfHeaders = optional.SizeOfHeaders;
            identityOut.preferredImageBase = optional.ImageBase;
            if (optional.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_BASERELOC)
            {
                identityOut.relocationRva =
                    optional.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC]
                        .VirtualAddress;
                identityOut.relocationSize =
                    optional.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC]
                        .Size;
            }
        }
        else
        {
            errorTextOut = QStringLiteral("映像可选头类型未知。");
            return false;
        }

        if (fileHeader.NumberOfSections == 0U
            || fileHeader.NumberOfSections > 128U)
        {
            errorTextOut = QStringLiteral("映像区段数量异常。");
            return false;
        }
        identityOut.timestamp = fileHeader.TimeDateStamp;
        identityOut.machine = fileHeader.Machine;
        identityOut.sectionCount = fileHeader.NumberOfSections;
        identityOut.sectionTableOffset =
            optionalOffset + fileHeader.SizeOfOptionalHeader;
        identityOut.valid = true;
        return true;
    }

    std::vector<std::uint8_t> loadedHeaderBytes(
        std::uint64_t moduleBase,
        QString& errorTextOut);

    bool mapPeImage(
        const QByteArray& diskImage,
        const PeIdentity& identity,
        const std::uint64_t loadedBase,
        std::vector<std::uint8_t>& mappedImageOut,
        bool& relocationAppliedOut,
        QString& errorTextOut)
    {
        constexpr std::uint32_t maximumMappedImageBytes =
            512U * 1024U * 1024U;
        mappedImageOut.clear();
        relocationAppliedOut = false;
        if (!identity.valid
            || identity.sizeOfImage == 0U
            || identity.sizeOfImage > maximumMappedImageBytes)
        {
            errorTextOut =
                baselineText(QStringLiteral("映像 SizeOfImage 无效或超过取证上限。"));
            return false;
        }

        mappedImageOut.assign(identity.sizeOfImage, 0U);
        const std::size_t headerBytes = std::min<std::size_t>(
            {
                mappedImageOut.size(),
                static_cast<std::size_t>(diskImage.size()),
                static_cast<std::size_t>(identity.sizeOfHeaders)
            });
        if (headerBytes == 0U)
        {
            errorTextOut = baselineText(QStringLiteral("映像头范围为空。"));
            return false;
        }
        std::memcpy(
            mappedImageOut.data(),
            diskImage.constData(),
            headerBytes);

        for (std::uint16_t index = 0;
             index < identity.sectionCount;
             ++index)
        {
            IMAGE_SECTION_HEADER section = {};
            const std::uint64_t sectionOffset =
                identity.sectionTableOffset
                + static_cast<std::uint64_t>(index)
                    * sizeof(IMAGE_SECTION_HEADER);
            if (!copyStructure(diskImage, sectionOffset, section))
            {
                errorTextOut =
                    baselineText(QStringLiteral("映像区段表读取失败。"));
                return false;
            }
            if (section.SizeOfRawData == 0U)
            {
                continue;
            }
            if (section.VirtualAddress >= mappedImageOut.size()
                || section.PointerToRawData
                    >= static_cast<std::uint32_t>(diskImage.size()))
            {
                errorTextOut =
                    baselineText(QStringLiteral("映像区段范围越界。"));
                return false;
            }
            const std::size_t mappedRemaining =
                mappedImageOut.size() - section.VirtualAddress;
            const std::size_t fileRemaining =
                static_cast<std::size_t>(diskImage.size())
                - section.PointerToRawData;
            const std::size_t copyBytes = std::min<std::size_t>(
                {
                    static_cast<std::size_t>(section.SizeOfRawData),
                    mappedRemaining,
                    fileRemaining
                });
            if (copyBytes != section.SizeOfRawData)
            {
                errorTextOut =
                    baselineText(QStringLiteral("映像区段原始数据被截断。"));
                return false;
            }
            std::memcpy(
                mappedImageOut.data() + section.VirtualAddress,
                diskImage.constData() + section.PointerToRawData,
                copyBytes);
        }

        const std::uint64_t relocationDelta =
            loadedBase - identity.preferredImageBase;
        if (relocationDelta == 0U)
        {
            return true;
        }
        if (identity.relocationRva == 0U
            || identity.relocationSize < sizeof(IMAGE_BASE_RELOCATION)
            || identity.relocationRva >= mappedImageOut.size()
            || identity.relocationSize
                > mappedImageOut.size() - identity.relocationRva)
        {
            errorTextOut = baselineText(QStringLiteral("映像发生基址变化，但重定位目录不可用。"));
            return false;
        }

        std::uint32_t consumed = 0U;
        while (consumed < identity.relocationSize)
        {
            if (identity.relocationSize - consumed
                    < sizeof(IMAGE_BASE_RELOCATION))
            {
                errorTextOut =
                    baselineText(QStringLiteral("PE 重定位块头被截断。"));
                return false;
            }
            const std::size_t blockOffset =
                static_cast<std::size_t>(identity.relocationRva)
                + consumed;
            IMAGE_BASE_RELOCATION block = {};
            std::memcpy(
                &block,
                mappedImageOut.data() + blockOffset,
                sizeof(block));
            if (block.SizeOfBlock < sizeof(block)
                || block.SizeOfBlock
                    > identity.relocationSize - consumed)
            {
                errorTextOut =
                    baselineText(QStringLiteral("PE 重定位块长度无效。"));
                return false;
            }
            const std::uint32_t entryBytes =
                block.SizeOfBlock - sizeof(block);
            if ((entryBytes % sizeof(WORD)) != 0U)
            {
                errorTextOut =
                    baselineText(QStringLiteral("PE 重定位项未按 WORD 对齐。"));
                return false;
            }
            const std::uint32_t entryCount =
                entryBytes / sizeof(WORD);
            for (std::uint32_t entryIndex = 0U;
                 entryIndex < entryCount;
                 ++entryIndex)
            {
                WORD entry = 0U;
                std::memcpy(
                    &entry,
                    mappedImageOut.data()
                        + blockOffset + sizeof(block)
                        + entryIndex * sizeof(WORD),
                    sizeof(entry));
                const WORD type = static_cast<WORD>(entry >> 12);
                const std::uint64_t targetRva =
                    static_cast<std::uint64_t>(block.VirtualAddress)
                    + (entry & 0x0FFFU);
                if (type == IMAGE_REL_BASED_ABSOLUTE)
                {
                    continue;
                }
                if (type == IMAGE_REL_BASED_DIR64)
                {
                    if (targetRva > mappedImageOut.size()
                        || sizeof(std::uint64_t)
                            > mappedImageOut.size()
                                - static_cast<std::size_t>(targetRva))
                    {
                        errorTextOut =
                            baselineText(QStringLiteral("DIR64 重定位目标越界。"));
                        return false;
                    }
                    std::uint64_t value = 0U;
                    std::memcpy(
                        &value,
                        mappedImageOut.data()
                            + static_cast<std::size_t>(targetRva),
                        sizeof(value));
                    value += relocationDelta;
                    std::memcpy(
                        mappedImageOut.data()
                            + static_cast<std::size_t>(targetRva),
                        &value,
                        sizeof(value));
                    relocationAppliedOut = true;
                    continue;
                }
                if (type == IMAGE_REL_BASED_HIGHLOW)
                {
                    if (targetRva > mappedImageOut.size()
                        || sizeof(std::uint32_t)
                            > mappedImageOut.size()
                                - static_cast<std::size_t>(targetRva))
                    {
                        errorTextOut =
                            baselineText(QStringLiteral("HIGHLOW 重定位目标越界。"));
                        return false;
                    }
                    std::uint32_t value = 0U;
                    std::memcpy(
                        &value,
                        mappedImageOut.data()
                            + static_cast<std::size_t>(targetRva),
                        sizeof(value));
                    value += static_cast<std::uint32_t>(
                        relocationDelta);
                    std::memcpy(
                        mappedImageOut.data()
                            + static_cast<std::size_t>(targetRva),
                        &value,
                        sizeof(value));
                    relocationAppliedOut = true;
                    continue;
                }
                errorTextOut = baselineText(QStringLiteral("PE 含有当前取证器不支持的重定位类型 %1。"))
                    .arg(type);
                return false;
            }
            consumed += block.SizeOfBlock;
        }
        return true;
    }

    QString thumbprintText(
        const KSWORD_ARK_QUERY_IMAGE_SIGNATURE_RESPONSE& response)
    {
        const std::uint32_t byteCount = std::min<std::uint32_t>(
            response.thumbprintSize,
            KSWORD_ARK_TRUST_THUMBPRINT_MAX_BYTES);
        return QString::fromLatin1(
            QByteArray(
                reinterpret_cast<const char*>(response.thumbprint),
                static_cast<qsizetype>(byteCount))
                .toHex());
    }

    struct PreparedTrustedImage
    {
        LoadedModule module;
        PeIdentity identity;
        QByteArray diskImage;
        std::vector<std::uint8_t> mappedImage;
        QString sha256;
        QString signingThumbprint;
        std::uint32_t signingLevel = 0;
        bool diskTrustVerified = false;
        bool relocationApplied = false;
    };

    bool prepareTrustedImage(
        const LoadedModule& module,
        const bool requireTrustedDiskImage,
        PreparedTrustedImage& preparedOut,
        QString& errorTextOut)
    {
        preparedOut = {};
        preparedOut.module = module;
        if (module.filePath.isEmpty()
            || !QFileInfo::exists(module.filePath))
        {
            errorTextOut = baselineText(QStringLiteral("模块磁盘路径不可用：%1")).arg(module.ntPath);
            return false;
        }

        ReadOnlyTrustFile imageFile(module.filePath);
        if (imageFile.handle == INVALID_HANDLE_VALUE)
        {
            errorTextOut = baselineText(QStringLiteral("无法读取模块磁盘映像：%1"))
                .arg(QDir::toNativeSeparators(module.filePath));
            return false;
        }
        if (requireTrustedDiskImage)
        {
            if (!readTrustedDiskImage(
                    module.filePath,
                    imageFile.handle,
                    preparedOut.diskImage))
            {
                errorTextOut = baselineText(QStringLiteral(
                    "磁盘映像未通过 embedded/catalog 完整链信任验证，拒绝建立安全基线。"));
                return false;
            }
            preparedOut.diskTrustVerified = true;
        }
        else
        {
            if (!readDiskImage(
                    imageFile.handle,
                    preparedOut.diskImage))
            {
                errorTextOut = baselineText(QStringLiteral("无法读取模块磁盘映像：%1"))
                    .arg(QDir::toNativeSeparators(module.filePath));
                return false;
            }
        }
        if (preparedOut.diskImage.isEmpty())
        {
            errorTextOut = baselineText(QStringLiteral("模块磁盘映像为空。"));
            return false;
        }
        preparedOut.sha256 = QString::fromLatin1(
            QCryptographicHash::hash(
                preparedOut.diskImage,
                QCryptographicHash::Sha256)
                .toHex());
        if (!parsePeIdentity(
            preparedOut.diskImage,
            preparedOut.identity,
            errorTextOut))
        {
            return false;
        }

        const std::vector<std::uint8_t> memoryHeader =
            loadedHeaderBytes(module.base, errorTextOut);
        if (memoryHeader.empty())
        {
            return false;
        }
        const QByteArray memoryHeaderArray(
            reinterpret_cast<const char*>(memoryHeader.data()),
            static_cast<qsizetype>(memoryHeader.size()));
        PeIdentity memoryIdentity;
        if (!parsePeIdentity(
            memoryHeaderArray,
            memoryIdentity,
            errorTextOut))
        {
            errorTextOut = baselineText(QStringLiteral("已加载映像身份读取失败：%1")).arg(errorTextOut);
            return false;
        }
        if (preparedOut.identity.machine != memoryIdentity.machine
            || preparedOut.identity.timestamp != memoryIdentity.timestamp
            || preparedOut.identity.sizeOfImage != memoryIdentity.sizeOfImage
            || preparedOut.identity.checkSum != memoryIdentity.checkSum
            || preparedOut.identity.sizeOfImage != module.size)
        {
            errorTextOut = baselineText(QStringLiteral("磁盘映像与已加载模块的机器类型、时间戳、映像大小或校验和不一致。"));
            return false;
        }

        const ksword::ark::DriverClient client;
        const ksword::ark::ImageSignatureQueryResult signature =
            client.queryImageSignature(
                module.ntPath.toStdWString(),
                module.base,
                KSWORD_ARK_IMAGE_SIGNATURE_QUERY_FLAG_DEFAULT
                    | KSWORD_ARK_IMAGE_SIGNATURE_QUERY_FLAG_MATCH_LOADED_MODULE);
        const std::uint32_t requiredFields =
            KSWORD_ARK_IMAGE_SIGNATURE_FIELD_SIGNING_LEVEL
            | KSWORD_ARK_IMAGE_SIGNATURE_FIELD_LOADED_MODULE
            | KSWORD_ARK_IMAGE_SIGNATURE_FIELD_LOADED_MODULE_NAME_MATCH;
        if (!signature.io.ok
            || (signature.response.fieldFlags & requiredFields)
                != requiredFields
            || signature.response.signingLevelStatus < 0
            || signature.response.loadedModuleStatus < 0
            || signature.response.matchedModuleBase != module.base
            || signature.response.signingLevel
                < KSWORD_ARK_SIGNING_LEVEL_AUTHENTICODE
            || (signature.response.structuralFlags
                & KSWORD_ARK_IMAGE_SIGNATURE_STRUCT_LOADED_NAME_MISMATCH)
                != 0U)
        {
            errorTextOut = baselineText(QStringLiteral("内核 Code Integrity 签名级别或已加载模块身份证据不足，拒绝建立可信基线。"));
            return false;
        }
        preparedOut.signingLevel = signature.response.signingLevel;
        preparedOut.signingThumbprint =
            thumbprintText(signature.response);

        return mapPeImage(
            preparedOut.diskImage,
            preparedOut.identity,
            module.base,
            preparedOut.mappedImage,
            preparedOut.relocationApplied,
            errorTextOut);
    }

    const PreparedTrustedImage* cachedTrustedImage(
        const LoadedModule& module,
        QString& errorTextOut)
    {
        thread_local std::vector<PreparedTrustedImage> cache;
        const auto existing = std::find_if(
            cache.cbegin(),
            cache.cend(),
            [&module](const PreparedTrustedImage& candidate)
            {
                return candidate.module.base == module.base
                    && candidate.module.size == module.size
                    && candidate.module.filePath.compare(
                        module.filePath,
                        Qt::CaseInsensitive) == 0;
            });
        if (existing != cache.cend())
        {
            return &(*existing);
        }

        PreparedTrustedImage prepared;
        if (!prepareTrustedImage(
                module,
                false,
                prepared,
                errorTextOut))
        {
            return nullptr;
        }
        cache.push_back(std::move(prepared));
        return &cache.back();
    }

    struct IdtBaselineProfile
    {
        std::uint32_t tableRva = 0;
        std::array<std::vector<std::uint64_t>, 256>
            handlerAddresses;
        QString sourceSymbol;
        QString profilePath;
    };

    std::optional<std::uint32_t> jsonUInt32(
        const QJsonValue& value)
    {
        if (value.isDouble())
        {
            const double number = value.toDouble(-1.0);
            if (number < 0.0
                || number
                    > static_cast<double>(
                        std::numeric_limits<std::uint32_t>::max())
                || number != static_cast<double>(
                    static_cast<std::uint32_t>(number)))
            {
                return std::nullopt;
            }
            return static_cast<std::uint32_t>(number);
        }
        if (!value.isString())
        {
            return std::nullopt;
        }
        QString text = value.toString().trimmed();
        int base = 10;
        if (text.startsWith(QStringLiteral("0x"),
                Qt::CaseInsensitive))
        {
            text = text.mid(2);
            base = 16;
        }
        bool converted = false;
        const qulonglong parsed = text.toULongLong(
            &converted,
            base);
        if (!converted
            || parsed
                > std::numeric_limits<std::uint32_t>::max())
        {
            return std::nullopt;
        }
        return static_cast<std::uint32_t>(parsed);
    }

    QStringList idtProfileCandidatePaths()
    {
        QStringList paths;
        const QStringList roots = {
            QDir(QCoreApplication::applicationDirPath())
                .filePath(QStringLiteral("profiles")),
            QDir::current().filePath(QStringLiteral("profiles"))
        };
        QSet<QString> seen;
        for (const QString& root : roots)
        {
            const QDir directory(root);
            const QStringList packNames = {
                QStringLiteral("ark_dyndata_pack_v4.json"),
                QStringLiteral("ark_dyndata_pack_v3.json"),
                QStringLiteral("ark_dyndata_pack_v2.json"),
                QStringLiteral("ark_dyndata_pack_v1.json")
            };
            for (const QString& packName : packNames)
            {
                const QString path =
                    QFileInfo(directory.filePath(packName))
                        .absoluteFilePath();
                const QString key =
                    QDir::cleanPath(path).toLower();
                if (!seen.contains(key) && QFileInfo::exists(path))
                {
                    seen.insert(key);
                    paths.push_back(path);
                }
            }
            const QDir scattered(
                directory.filePath(QStringLiteral("ark_dyndata")));
            const QStringList profileFiles = scattered.entryList(
                { QStringLiteral("*.json") },
                QDir::Files,
                QDir::Name);
            for (const QString& profileName : profileFiles)
            {
                const QString path =
                    QFileInfo(scattered.filePath(profileName))
                        .absoluteFilePath();
                const QString key =
                    QDir::cleanPath(path).toLower();
                if (!seen.contains(key))
                {
                    seen.insert(key);
                    paths.push_back(path);
                }
            }
        }
        return paths;
    }

    bool idtProfileEntryMatches(
        const QJsonObject& profile,
        const PreparedTrustedImage& image,
        const bool compactPack)
    {
        const QJsonObject identity = compactPack
            ? profile
            : profile.value(QStringLiteral("module")).toObject();
        const std::optional<std::uint32_t> machine =
            jsonUInt32(identity.value(QStringLiteral("machine")));
        const std::optional<std::uint32_t> timestamp =
            jsonUInt32(identity.value(QStringLiteral("timeDateStamp")));
        const std::optional<std::uint32_t> size =
            jsonUInt32(identity.value(QStringLiteral("sizeOfImage")));
        return machine.has_value()
            && timestamp.has_value()
            && size.has_value()
            && machine.value() == image.identity.machine
            && timestamp.value() == image.identity.timestamp
            && size.value() == image.identity.sizeOfImage;
    }

    bool loadIdtBaselineProfile(
        const PreparedTrustedImage& image,
        IdtBaselineProfile& profileOut,
        QString& errorTextOut)
    {
        profileOut = {};
        bool identitySeen = false;
        bool hashSeen = false;
        bool invalidMetadataSeen = false;
        for (const QString& path : idtProfileCandidatePaths())
        {
            QFile file(path);
            if (!file.open(QIODevice::ReadOnly))
            {
                continue;
            }
            QJsonParseError parseError = {};
            const QJsonDocument document =
                QJsonDocument::fromJson(file.readAll(), &parseError);
            file.close();
            if (parseError.error != QJsonParseError::NoError
                || !document.isObject())
            {
                continue;
            }

            const QJsonObject root = document.object();
            const bool compactPack =
                root.value(QStringLiteral("profiles")).isArray();
            QJsonArray entries;
            if (compactPack)
            {
                entries =
                    root.value(QStringLiteral("profiles")).toArray();
            }
            else
            {
                entries.append(root);
            }
            for (const QJsonValue& entryValue : entries)
            {
                if (!entryValue.isObject())
                {
                    continue;
                }
                const QJsonObject entry = entryValue.toObject();
                if (!idtProfileEntryMatches(
                    entry,
                    image,
                    compactPack))
                {
                    continue;
                }
                identitySeen = true;
                const QJsonObject identity = compactPack
                    ? entry
                    : entry.value(QStringLiteral("module")).toObject();
                const QString profileHash =
                    identity.value(QStringLiteral("sha256"))
                        .toString()
                        .trimmed()
                        .toLower();
                if (profileHash.size() != 64
                    || profileHash != image.sha256.toLower())
                {
                    continue;
                }
                hashSeen = true;
                const QJsonObject baseline =
                    entry.value(QStringLiteral("idtBaseline"))
                        .toObject();
                const std::optional<std::uint32_t> schemaVersion =
                    jsonUInt32(
                        baseline.value(QStringLiteral("schemaVersion")));
                const std::optional<std::uint32_t> tableRva =
                    jsonUInt32(
                        baseline.value(QStringLiteral("tableRva")));
                const QString sourceSymbol =
                    baseline.value(QStringLiteral("sourceSymbol"))
                        .toString()
                        .trimmed();
                const QJsonArray handlers =
                    baseline.value(QStringLiteral("handlers")).toArray();
                if (!schemaVersion.has_value()
                    || schemaVersion.value() != 2U
                    || !tableRva.has_value()
                    || tableRva.value() == 0U
                    || tableRva.value() >= image.mappedImage.size()
                    || handlers.isEmpty()
                    || sourceSymbol
                        != QStringLiteral("KiInterruptInitTable"))
                {
                    invalidMetadataSeen = true;
                    continue;
                }
                IdtBaselineProfile parsedProfile;
                parsedProfile.tableRva = tableRva.value();
                parsedProfile.sourceSymbol = sourceSymbol;
                parsedProfile.profilePath = path;
                std::size_t acceptedHandlers = 0U;
                bool invalidHandlerSeen = false;
                for (const QJsonValue& handlerValue : handlers)
                {
                    const QJsonObject handler =
                        handlerValue.toObject();
                    const std::optional<std::uint32_t> vector =
                        jsonUInt32(
                            handler.value(QStringLiteral("vector")));
                    const std::optional<std::uint32_t> handlerRva =
                        jsonUInt32(
                            handler.value(QStringLiteral("rva")));
                    const QString handlerSymbol =
                        handler.value(QStringLiteral("symbol"))
                            .toString()
                            .trimmed();
                    if (!vector.has_value()
                        || vector.value() > 0xFFU
                        || !handlerRva.has_value()
                        || handlerRva.value() == 0U
                        || handlerRva.value() >= image.module.size
                        || !handlerSymbol.startsWith(
                            QStringLiteral("Ki")))
                    {
                        invalidHandlerSeen = true;
                        break;
                    }
                    const std::uint64_t handlerAddress =
                        image.module.base + handlerRva.value();
                    std::vector<std::uint64_t>& candidates =
                        parsedProfile.handlerAddresses[vector.value()];
                    if (std::find(
                        candidates.cbegin(),
                        candidates.cend(),
                        handlerAddress) == candidates.cend())
                    {
                        candidates.push_back(handlerAddress);
                        ++acceptedHandlers;
                    }
                }
                if (invalidHandlerSeen || acceptedHandlers == 0U)
                {
                    invalidMetadataSeen = true;
                    continue;
                }
                profileOut = std::move(parsedProfile);
                return true;
            }
        }

        if (hashSeen)
        {
            errorTextOut = invalidMetadataSeen
                ? QStringLiteral(
                    "精确 SHA256 profile 的 IDT 基线元数据缺失或无效，IDT 预期处理程序 unsupported。")
                : QStringLiteral(
                    "精确 SHA256 profile 未提供 KiInterruptInitTable，IDT 预期处理程序 unsupported。");
        }
        else if (identitySeen)
        {
            errorTextOut = QStringLiteral(
                "PDB profile 的 PE 身份匹配但 SHA256 不匹配，拒绝使用。");
        }
        else
        {
            errorTextOut = QStringLiteral(
                "没有与当前 ntoskrnl 机器类型、时间戳、SizeOfImage 和 SHA256 精确匹配的 IDT profile。");
        }
        return false;
    }

    std::vector<std::uint8_t> loadedHeaderBytes(
        const std::uint64_t moduleBase,
        QString& errorTextOut)
    {
        std::vector<std::uint8_t> bytes;
        if (!ks::kernel::KernelCleanImageBaseline::readKernelBytes(
            moduleBase,
            64U * 1024U,
            bytes,
            errorTextOut))
        {
            return {};
        }
        return bytes;
    }
}

namespace ks::kernel
{
    bool KernelCleanImageBaseline::readKernelBytes(
        const std::uint64_t kernelAddress,
        const std::uint32_t byteCount,
        std::vector<std::uint8_t>& bytesOut,
        QString& errorTextOut)
    {
        bytesOut.clear();
        errorTextOut.clear();
        if (kernelAddress == 0U
            || byteCount == 0U
            || byteCount > KSWORD_ARK_MEMORY_READ_MAX_BYTES)
        {
            errorTextOut = QStringLiteral("内核读取参数无效。");
            return false;
        }

        const ksword::ark::DriverClient client;
        const ksword::ark::VirtualMemoryReadResult read =
            client.readVirtualMemory(
                0U,
                kernelAddress,
                byteCount,
                KSWORD_ARK_MEMORY_READ_FLAG_KERNEL_ADDRESS);
        if (!read.io.ok || read.bytesRead != byteCount)
        {
            errorTextOut = QStringLiteral(
                "R0 内核读取失败：Win32=%1，NT=0x%2，读取=%3/%4。")
                .arg(read.io.win32Error)
                .arg(static_cast<unsigned long>(read.copyStatus),
                    8,
                    16,
                    QChar('0'))
                .arg(read.bytesRead)
                .arg(byteCount);
            return false;
        }
        bytesOut = read.data;
        return bytesOut.size() == byteCount;
    }

    CleanImageBaselineResult KernelCleanImageBaseline::compareAddress(
        const std::uint64_t kernelAddress,
        const std::uint32_t byteCount,
        const std::vector<std::uint8_t>& observedBytes,
        const bool requireTrustedDiskImage)
    {
        CleanImageBaselineResult result;
        if (kernelAddress == 0U
            || byteCount == 0U
            || byteCount > 64U * 1024U)
        {
            result.statusText = QStringLiteral("基线请求范围无效。");
            return result;
        }

        std::vector<LoadedModule> modules;
        QString errorText;
        if (!enumerateLoadedModules(modules, errorText))
        {
            result.statusText = errorText;
            return result;
        }
        const LoadedModule* module =
            moduleForAddress(modules, kernelAddress);
        if (module == nullptr)
        {
            result.statusText =
                QStringLiteral("目标地址不属于已加载内核映像。");
            return result;
        }

        result.moduleBase = module->base;
        result.moduleSize = module->size;
        result.moduleName = module->name;
        result.imagePath = module->filePath;
        const std::uint64_t rva64 = kernelAddress - module->base;
        if (rva64 > std::numeric_limits<std::uint32_t>::max())
        {
            result.statusText = QStringLiteral("目标 RVA 超出 32 位范围。");
            return result;
        }
        result.relativeVirtualAddress =
            static_cast<std::uint32_t>(rva64);
        PreparedTrustedImage trustedDiskImage;
        const PreparedTrustedImage* prepared = nullptr;
        if (requireTrustedDiskImage)
        {
            if (!prepareTrustedImage(
                    *module,
                    true,
                    trustedDiskImage,
                    errorText))
            {
                result.statusText = errorText;
                return result;
            }
            prepared = &trustedDiskImage;
        }
        else
        {
            prepared = cachedTrustedImage(
                *module,
                errorText);
        }
        if (prepared == nullptr)
        {
            result.statusText = errorText;
            return result;
        }
        result.identityMatched = true;
        result.diskTrustVerified = prepared->diskTrustVerified;
        result.codeIntegrityTrusted = true;
        result.relocationApplied = prepared->relocationApplied;
        result.preferredImageBase =
            prepared->identity.preferredImageBase;
        result.signingLevel = prepared->signingLevel;
        result.imageSha256 = prepared->sha256;
        result.signingThumbprint = prepared->signingThumbprint;
        if (result.relativeVirtualAddress > prepared->mappedImage.size()
            || byteCount > prepared->mappedImage.size()
                - result.relativeVirtualAddress)
        {
            result.statusText =
                baselineText(QStringLiteral("目标 RVA 在已重定位映像中越界。"));
            return result;
        }
        result.cleanBytes.assign(
            prepared->mappedImage.cbegin()
                + result.relativeVirtualAddress,
            prepared->mappedImage.cbegin()
                + result.relativeVirtualAddress + byteCount);
        if (observedBytes.empty())
        {
            if (!readKernelBytes(
                kernelAddress,
                byteCount,
                result.observedBytes,
                errorText))
            {
                result.statusText = errorText;
                return result;
            }
        }
        else if (observedBytes.size() == byteCount)
        {
            result.observedBytes = observedBytes;
        }
        else
        {
            result.statusText =
                QStringLiteral("调用方提供的观察字节长度与目标范围不一致。");
            return result;
        }

        result.available = true;
        result.differs = result.cleanBytes != result.observedBytes;
        result.statusText = result.differs
            ? baselineText(QStringLiteral("当前内存与身份、SHA256、Code Integrity 签名级别绑定的重定位映像基线不一致"))
            : baselineText(QStringLiteral("当前内存与身份、SHA256、Code Integrity 签名级别绑定的重定位映像基线一致"));
        return result;
    }

    std::vector<TrustedIdtBaselineResult>
    KernelCleanImageBaseline::compareIdtHandlers(
        const std::vector<IdtHandlerObservation>& observations)
    {
        std::vector<TrustedIdtBaselineResult> results;
        results.reserve(observations.size());
        for (const IdtHandlerObservation& observation : observations)
        {
            TrustedIdtBaselineResult row;
            row.vector = observation.vector;
            row.observedHandler = observation.handler;
            results.push_back(std::move(row));
        }
        if (observations.empty())
        {
            return results;
        }

        auto failAll = [&results](const QString& message)
        {
            for (TrustedIdtBaselineResult& row : results)
            {
                row.statusText = message;
            }
        };

        std::vector<LoadedModule> modules;
        QString errorText;
        if (!enumerateLoadedModules(modules, errorText))
        {
            failAll(errorText);
            return results;
        }
        const auto ntosIterator = std::find_if(
            modules.cbegin(),
            modules.cend(),
            [](const LoadedModule& module)
            {
                const QString fileName =
                    QFileInfo(module.filePath).fileName().toLower();
                return fileName == QStringLiteral("ntoskrnl.exe")
                    || fileName == QStringLiteral("ntkrnlmp.exe")
                    || fileName == QStringLiteral("ntkrla57.exe");
            });
        if (ntosIterator == modules.cend())
        {
            failAll(QStringLiteral(
                "无法在已加载模块列表中定位 ntoskrnl，IDT 可信映像基线 unsupported。"));
            return results;
        }

        PreparedTrustedImage image;
        if (!prepareTrustedImage(*ntosIterator, true, image, errorText))
        {
            failAll(errorText);
            return results;
        }
        IdtBaselineProfile profile;
        if (!loadIdtBaselineProfile(image, profile, errorText))
        {
            failAll(errorText);
            return results;
        }

        for (TrustedIdtBaselineResult& row : results)
        {
            row.identityMatched = true;
            row.diskTrustVerified = image.diskTrustVerified;
            row.codeIntegrityTrusted = true;
            row.profileHashMatched = true;
            row.imagePath = image.module.filePath;
            row.imageSha256 = image.sha256;
            row.profilePath = profile.profilePath;
            row.sourceSymbol = profile.sourceSymbol;
            if (row.vector > 0xFFU)
            {
                row.statusText = QStringLiteral(
                    "IDT 向量超出 x64 架构范围。");
                continue;
            }
            const std::vector<std::uint64_t>& candidates =
                profile.handlerAddresses[row.vector];
            row.expectedCandidateCount =
                static_cast<std::uint32_t>(candidates.size());
            if (candidates.empty())
            {
                row.statusText = QStringLiteral(
                    "精确 PDB 未公开该向量的静态 Handler；动态设备中断或默认 thunk 明确标记 unsupported。");
                continue;
            }
            const auto matched = std::find(
                candidates.cbegin(),
                candidates.cend(),
                row.observedHandler);
            row.handlerMatches = matched != candidates.cend();
            row.expectedHandler = row.handlerMatches
                ? row.observedHandler
                : candidates.front();
            row.available = true;
            row.statusText = row.handlerMatches
                ? QStringLiteral(
                    "当前 IDT Handler 与精确 PDB/SHA256 绑定的静态向量符号一致")
                : QStringLiteral(
                    "当前 IDT Handler 偏离精确 PDB/SHA256 绑定的静态向量符号");
        }
        return results;
    }

}
