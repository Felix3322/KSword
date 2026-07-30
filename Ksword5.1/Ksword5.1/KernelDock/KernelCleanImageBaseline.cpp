#include "KernelCleanImageBaseline.h"

#include "../ArkDriverClient/ArkDriverClient.h"

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#include <bcrypt.h>
#include <mscat.h>
#include <Softpub.h>
#include <WinTrust.h>
#include <winternl.h>

#include <QByteArray>
#include <QDir>
#include <QFile>
#include <QFileInfo>

#include <algorithm>
#include <cstddef>
#include <cstring>
#include <iterator>
#include <limits>
#include <vector>

#pragma comment(lib, "Wintrust.lib")

namespace
{
    constexpr unsigned long kSystemModuleInformationClass = 11UL;

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

    bool readTrustedDiskImage(
        const QString& path,
        QByteArray& bytesOut)
    {
        bytesOut.clear();
        ReadOnlyTrustFile file(path);
        if (file.handle == INVALID_HANDLE_VALUE)
        {
            return false;
        }

        WINTRUST_FILE_INFO fileInfo{};
        fileInfo.cbStruct = sizeof(fileInfo);
        fileInfo.pcwszFilePath =
            reinterpret_cast<LPCWSTR>(path.utf16());
        fileInfo.hFile = file.handle;

        WINTRUST_DATA trustData{};
        initializeStrictTrustData(trustData);
        trustData.dwUnionChoice = WTD_CHOICE_FILE;
        trustData.pFile = &fileInfo;
        const bool trusted =
            runWinTrustAndClose(trustData) == ERROR_SUCCESS ||
            verifyCatalogTrust(path, file.handle);
        if (!trusted)
        {
            return false;
        }

        LARGE_INTEGER fileSize{};
        constexpr LONGLONG maximumTrustedImageBytes =
            512LL * 1024LL * 1024LL;
        if (!::GetFileSizeEx(file.handle, &fileSize) ||
            fileSize.QuadPart <= 0 ||
            fileSize.QuadPart > maximumTrustedImageBytes ||
            fileSize.QuadPart >
                static_cast<LONGLONG>(
                    std::numeric_limits<qsizetype>::max()))
        {
            return false;
        }
        LARGE_INTEGER fileStart{};
        if (!::SetFilePointerEx(
                file.handle,
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
                    file.handle,
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
        std::uint32_t timestamp = 0;
        std::uint64_t imageBase = 0;
        std::uint32_t sizeOfImage = 0;
        std::uint32_t checkSum = 0;
        std::uint32_t sizeOfHeaders = 0;
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
            identityOut.imageBase = optional.ImageBase;
            identityOut.checkSum = optional.CheckSum;
            identityOut.sizeOfHeaders = optional.SizeOfHeaders;
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
            identityOut.imageBase = optional.ImageBase;
            identityOut.checkSum = optional.CheckSum;
            identityOut.sizeOfHeaders = optional.SizeOfHeaders;
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
        identityOut.sectionCount = fileHeader.NumberOfSections;
        identityOut.sectionTableOffset =
            optionalOffset + fileHeader.SizeOfOptionalHeader;
        identityOut.valid = true;
        return true;
    }

    bool readPeRva(
        const QByteArray& imageBytes,
        const PeIdentity& identity,
        const std::uint32_t rva,
        const std::uint32_t byteCount,
        std::vector<std::uint8_t>& bytesOut,
        QString& errorTextOut)
    {
        bytesOut.clear();
        if (byteCount == 0U
            || rva > std::numeric_limits<std::uint32_t>::max() - byteCount)
        {
            errorTextOut = QStringLiteral("映像 RVA 范围无效。");
            return false;
        }
        std::uint64_t fileOffset = 0U;
        if (rva < identity.sizeOfHeaders)
        {
            fileOffset = rva;
        }
        else
        {
            bool found = false;
            for (std::uint16_t index = 0;
                 index < identity.sectionCount;
                 ++index)
            {
                IMAGE_SECTION_HEADER section = {};
                const std::uint64_t sectionOffset =
                    identity.sectionTableOffset
                    + static_cast<std::uint64_t>(index)
                        * sizeof(IMAGE_SECTION_HEADER);
                if (!copyStructure(imageBytes, sectionOffset, section))
                {
                    errorTextOut =
                        QStringLiteral("映像区段表读取失败。");
                    return false;
                }
                const std::uint32_t mappedSize = std::max(
                    section.Misc.VirtualSize,
                    section.SizeOfRawData);
                if (rva < section.VirtualAddress
                    || rva - section.VirtualAddress >= mappedSize)
                {
                    continue;
                }
                const std::uint32_t relative =
                    rva - section.VirtualAddress;
                if (relative > section.SizeOfRawData
                    || byteCount > section.SizeOfRawData - relative)
                {
                    errorTextOut = QStringLiteral(
                        "目标 RVA 位于零填充区或越过磁盘区段。");
                    return false;
                }
                fileOffset =
                    static_cast<std::uint64_t>(section.PointerToRawData)
                    + relative;
                found = true;
                break;
            }
            if (!found)
            {
                errorTextOut =
                    QStringLiteral("没有区段覆盖目标 RVA。");
                return false;
            }
        }

        if (fileOffset > static_cast<std::uint64_t>(imageBytes.size())
            || byteCount
                > static_cast<std::uint64_t>(imageBytes.size()) - fileOffset)
        {
            errorTextOut =
                QStringLiteral("目标 RVA 对应的磁盘字节越界。");
            return false;
        }
        const auto* begin = reinterpret_cast<const std::uint8_t*>(
            imageBytes.constData() + static_cast<qsizetype>(fileOffset));
        bytesOut.assign(begin, begin + byteCount);
        return true;
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
        if (module->filePath.isEmpty()
            || !QFileInfo::exists(module->filePath))
        {
            result.statusText = QStringLiteral(
                "模块磁盘路径不可用：%1").arg(module->ntPath);
            return result;
        }
        QByteArray diskImage;
        if (requireTrustedDiskImage)
        {
            if (!readTrustedDiskImage(
                    module->filePath,
                    diskImage))
            {
                result.statusText = QStringLiteral(
                    "磁盘映像未通过 embedded/catalog 完整链信任验证，拒绝建立安全基线。");
                return result;
            }
            result.diskTrustVerified = true;
        }
        else
        {
            QFile imageFile(module->filePath);
            if (!imageFile.open(QIODevice::ReadOnly))
            {
                result.statusText = QStringLiteral(
                    "无法读取模块磁盘映像：%1")
                    .arg(QDir::toNativeSeparators(module->filePath));
                return result;
            }
            diskImage = imageFile.readAll();
            imageFile.close();
        }
        PeIdentity diskIdentity;
        if (!parsePeIdentity(diskImage, diskIdentity, errorText))
        {
            result.statusText = errorText;
            return result;
        }
        result.preferredImageBase = diskIdentity.imageBase;

        const std::vector<std::uint8_t> memoryHeader =
            loadedHeaderBytes(module->base, errorText);
        if (memoryHeader.empty())
        {
            result.statusText = errorText;
            return result;
        }
        const QByteArray memoryHeaderArray(
            reinterpret_cast<const char*>(memoryHeader.data()),
            static_cast<qsizetype>(memoryHeader.size()));
        PeIdentity memoryIdentity;
        if (!parsePeIdentity(
            memoryHeaderArray,
            memoryIdentity,
            errorText))
        {
            result.statusText = QStringLiteral(
                "已加载映像身份读取失败：%1").arg(errorText);
            return result;
        }
        result.identityMatched =
            diskIdentity.timestamp == memoryIdentity.timestamp
            && diskIdentity.sizeOfImage == memoryIdentity.sizeOfImage
            && diskIdentity.checkSum == memoryIdentity.checkSum
            && diskIdentity.sizeOfImage == module->size;
        if (!result.identityMatched)
        {
            result.statusText = QStringLiteral(
                "磁盘映像与已加载模块的时间戳、映像大小或校验和不一致，拒绝建立恢复基线。");
            return result;
        }

        if (!readPeRva(
            diskImage,
            diskIdentity,
            result.relativeVirtualAddress,
            byteCount,
            result.cleanBytes,
            errorText))
        {
            result.statusText = errorText;
            return result;
        }
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
            ? QStringLiteral("当前内存与已验证磁盘映像基线不一致")
            : QStringLiteral("当前内存与已验证磁盘映像基线一致");
        return result;
    }
}
