#include "dll_hijack_detector.h"

#include "process.h"

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#include <WinTrust.h>
#include <Softpub.h>
#include <bcrypt.h>
#include <mscat.h>
#include <wincrypt.h>

#include <QCryptographicHash>
#include <QDir>
#include <QDirIterator>
#include <QFile>
#include <QFileInfo>
#include <QHash>
#include <QMap>
#include <QSet>
#include <QStringList>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <utility>
#include <vector>

#pragma comment(lib, "Advapi32.lib")
#pragma comment(lib, "Crypt32.lib")
#pragma comment(lib, "Version.lib")
#pragma comment(lib, "Wintrust.lib")

namespace
{
    constexpr std::uint32_t MaxApplicationDllCount = 4096U;
    constexpr std::uint32_t MaxPeHeaderOffset = 16U * 1024U * 1024U;

#ifndef IMAGE_FILE_MACHINE_ARM64EC
    constexpr std::uint16_t ImageFileMachineArm64Ec = 0xA641U;
#else
    constexpr std::uint16_t ImageFileMachineArm64Ec = IMAGE_FILE_MACHINE_ARM64EC;
#endif

#ifndef IMAGE_FILE_MACHINE_CHPE_X86
    constexpr std::uint16_t ImageFileMachineChpeX86 = 0x3A64U;
#else
    constexpr std::uint16_t ImageFileMachineChpeX86 = IMAGE_FILE_MACHINE_CHPE_X86;
#endif

    struct VersionEvidence
    {
        QString companyName;
        QString originalFilename;
        QString fileVersion;
    };

    struct CatalogTrustResult
    {
        QString signer;
        QString catalogPath;
        QString fileIdentifier;
        LONG trustStatus = 0;
        DWORD lookupError = ERROR_SUCCESS;
        bool trustStatusAvailable = false;
        bool trusted = false;
    };

    struct CandidateDll
    {
        QString path;
        bool loaded = false;
    };

    class ScopedFileHandle final
    {
    public:
        explicit ScopedFileHandle(const QString& filePath)
            : value(::CreateFileW(
                reinterpret_cast<LPCWSTR>(filePath.utf16()),
                GENERIC_READ,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                nullptr,
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN,
                nullptr))
        {
        }

        ~ScopedFileHandle()
        {
            if (value != INVALID_HANDLE_VALUE)
            {
                ::CloseHandle(value);
            }
        }

        ScopedFileHandle(const ScopedFileHandle&) = delete;
        ScopedFileHandle& operator=(const ScopedFileHandle&) = delete;

        HANDLE value = INVALID_HANDLE_VALUE;
    };

    class ScopedCatalogAdmin final
    {
    public:
        ~ScopedCatalogAdmin()
        {
            if (value != nullptr)
            {
                ::CryptCATAdminReleaseContext(value, 0);
            }
        }

        ScopedCatalogAdmin(const ScopedCatalogAdmin&) = delete;
        ScopedCatalogAdmin& operator=(const ScopedCatalogAdmin&) = delete;
        ScopedCatalogAdmin() = default;

        HCATADMIN value = nullptr;
    };

    std::uint16_t readLe16(const char* const bytes)
    {
        const auto* const data = reinterpret_cast<const unsigned char*>(bytes);
        return static_cast<std::uint16_t>(data[0]) |
            (static_cast<std::uint16_t>(data[1]) << 8U);
    }

    std::uint32_t readLe32(const char* const bytes)
    {
        const auto* const data = reinterpret_cast<const unsigned char*>(bytes);
        return static_cast<std::uint32_t>(data[0]) |
            (static_cast<std::uint32_t>(data[1]) << 8U) |
            (static_cast<std::uint32_t>(data[2]) << 16U) |
            (static_cast<std::uint32_t>(data[3]) << 24U);
    }

    QString normalizedAbsolutePath(const QString& rawPath)
    {
        const QString trimmedPath = QDir::fromNativeSeparators(rawPath.trimmed());
        if (trimmedPath.isEmpty())
        {
            return QString();
        }
        return QDir::toNativeSeparators(
            QDir::cleanPath(QFileInfo(trimmedPath).absoluteFilePath()));
    }

    QString pathKey(const QString& rawPath)
    {
        return QDir::fromNativeSeparators(normalizedAbsolutePath(rawPath)).toCaseFolded();
    }

    bool pathIsInsideDirectory(const QString& filePath, const QString& directoryPath)
    {
        QString directoryKey = pathKey(directoryPath);
        const QString fileKey = pathKey(filePath);
        if (directoryKey.isEmpty() || fileKey.isEmpty())
        {
            return false;
        }
        if (!directoryKey.endsWith(QChar('/')))
        {
            directoryKey += QChar('/');
        }
        return fileKey.startsWith(directoryKey);
    }

    QString queryNativeSystemDirectory()
    {
        std::array<wchar_t, MAX_PATH + 1U> buffer{};
        const UINT length = ::GetSystemDirectoryW(
            buffer.data(),
            static_cast<UINT>(buffer.size()));
        if (length == 0U || length >= buffer.size())
        {
            return QString();
        }
        return normalizedAbsolutePath(
            QString::fromWCharArray(buffer.data(), static_cast<int>(length)));
    }

    QString queryWow64SystemDirectory()
    {
        std::array<wchar_t, MAX_PATH + 1U> buffer{};
        const UINT length = ::GetSystemWow64DirectoryW(
            buffer.data(),
            static_cast<UINT>(buffer.size()));
        if (length == 0U || length >= buffer.size())
        {
            return QString();
        }
        return normalizedAbsolutePath(
            QString::fromWCharArray(buffer.data(), static_cast<int>(length)));
    }

    std::uint16_t readPeMachine(const QString& filePath)
    {
        QFile file(filePath);
        if (!file.open(QIODevice::ReadOnly))
        {
            return 0U;
        }

        const QByteArray dosHeader = file.read(64);
        if (dosHeader.size() < 64 ||
            static_cast<unsigned char>(dosHeader[0]) != 'M' ||
            static_cast<unsigned char>(dosHeader[1]) != 'Z')
        {
            return 0U;
        }

        const std::uint32_t ntOffset = readLe32(dosHeader.constData() + 0x3c);
        if (ntOffset > MaxPeHeaderOffset ||
            !file.seek(static_cast<qint64>(ntOffset)))
        {
            return 0U;
        }

        const QByteArray ntHeaderPrefix = file.read(6);
        if (ntHeaderPrefix.size() != 6 ||
            static_cast<unsigned char>(ntHeaderPrefix[0]) != 'P' ||
            static_cast<unsigned char>(ntHeaderPrefix[1]) != 'E' ||
            ntHeaderPrefix[2] != '\0' ||
            ntHeaderPrefix[3] != '\0')
        {
            return 0U;
        }
        return readLe16(ntHeaderPrefix.constData() + 4);
    }

    bool machinesCompatible(
        const std::uint16_t processMachine,
        const std::uint16_t imageMachine)
    {
        if (processMachine == 0U || imageMachine == 0U ||
            processMachine == imageMachine)
        {
            return true;
        }
        if (processMachine == IMAGE_FILE_MACHINE_I386 &&
            imageMachine == ImageFileMachineChpeX86)
        {
            return true;
        }
        if ((processMachine == IMAGE_FILE_MACHINE_AMD64 ||
                processMachine == IMAGE_FILE_MACHINE_ARM64) &&
            imageMachine == ImageFileMachineArm64Ec)
        {
            return true;
        }
        return false;
    }

    QString queryVersionString(
        const std::vector<BYTE>& versionBytes,
        const WORD language,
        const WORD codePage,
        const wchar_t* const fieldName)
    {
        std::array<wchar_t, 160> queryPath{};
        const int formatLength = _snwprintf_s(
            queryPath.data(),
            queryPath.size(),
            _TRUNCATE,
            L"\\StringFileInfo\\%04x%04x\\%ls",
            language,
            codePage,
            fieldName);
        if (formatLength <= 0)
        {
            return QString();
        }

        LPWSTR value = nullptr;
        UINT valueLength = 0U;
        if (!::VerQueryValueW(
                versionBytes.data(),
                queryPath.data(),
                reinterpret_cast<void**>(&value),
                &valueLength) ||
            value == nullptr || valueLength <= 1U)
        {
            return QString();
        }
        return QString::fromWCharArray(
            value,
            static_cast<int>(valueLength - 1U)).trimmed();
    }

    VersionEvidence readVersionEvidence(const QString& filePath)
    {
        VersionEvidence evidence;
        DWORD ignoredHandle = 0U;
        const DWORD byteCount = ::GetFileVersionInfoSizeW(
            reinterpret_cast<LPCWSTR>(filePath.utf16()),
            &ignoredHandle);
        if (byteCount == 0U)
        {
            return evidence;
        }

        std::vector<BYTE> versionBytes(byteCount);
        if (!::GetFileVersionInfoW(
                reinterpret_cast<LPCWSTR>(filePath.utf16()),
                0,
                byteCount,
                versionBytes.data()))
        {
            return evidence;
        }

        struct LanguageAndCodePage
        {
            WORD language = 0U;
            WORD codePage = 0U;
        };

        LanguageAndCodePage* translations = nullptr;
        UINT translationBytes = 0U;
        std::vector<LanguageAndCodePage> candidates;
        if (::VerQueryValueW(
                versionBytes.data(),
                L"\\VarFileInfo\\Translation",
                reinterpret_cast<void**>(&translations),
                &translationBytes) &&
            translations != nullptr)
        {
            const std::size_t translationCount =
                translationBytes / sizeof(LanguageAndCodePage);
            candidates.assign(translations, translations + translationCount);
        }
        candidates.push_back(LanguageAndCodePage{0x0409U, 0x04B0U});
        candidates.push_back(LanguageAndCodePage{0x0409U, 0x04E4U});

        for (const LanguageAndCodePage& candidate : candidates)
        {
            if (evidence.companyName.isEmpty())
            {
                evidence.companyName = queryVersionString(
                    versionBytes,
                    candidate.language,
                    candidate.codePage,
                    L"CompanyName");
            }
            if (evidence.originalFilename.isEmpty())
            {
                evidence.originalFilename = queryVersionString(
                    versionBytes,
                    candidate.language,
                    candidate.codePage,
                    L"OriginalFilename");
            }
            if (evidence.fileVersion.isEmpty())
            {
                evidence.fileVersion = queryVersionString(
                    versionBytes,
                    candidate.language,
                    candidate.codePage,
                    L"FileVersion");
            }
            if (!evidence.companyName.isEmpty() &&
                !evidence.originalFilename.isEmpty() &&
                !evidence.fileVersion.isEmpty())
            {
                break;
            }
        }

        if (evidence.fileVersion.isEmpty())
        {
            VS_FIXEDFILEINFO* fixedInfo = nullptr;
            UINT fixedInfoBytes = 0U;
            if (::VerQueryValueW(
                    versionBytes.data(),
                    L"\\",
                    reinterpret_cast<void**>(&fixedInfo),
                    &fixedInfoBytes) &&
                fixedInfo != nullptr &&
                fixedInfoBytes >= sizeof(VS_FIXEDFILEINFO) &&
                fixedInfo->dwSignature == 0xFEEF04BDU)
            {
                evidence.fileVersion = QStringLiteral("%1.%2.%3.%4")
                    .arg(HIWORD(fixedInfo->dwFileVersionMS))
                    .arg(LOWORD(fixedInfo->dwFileVersionMS))
                    .arg(HIWORD(fixedInfo->dwFileVersionLS))
                    .arg(LOWORD(fixedInfo->dwFileVersionLS));
            }
        }
        return evidence;
    }

    QString calculateSha256(const QString& filePath)
    {
        QFile file(filePath);
        if (!file.open(QIODevice::ReadOnly))
        {
            return QString();
        }

        QCryptographicHash hasher(QCryptographicHash::Sha256);
        while (!file.atEnd())
        {
            const QByteArray block = file.read(1024 * 1024);
            if (block.isEmpty() && file.error() != QFile::NoError)
            {
                return QString();
            }
            hasher.addData(block);
        }
        return QString::fromLatin1(hasher.result().toHex());
    }

    void initializeOfflineTrustData(WINTRUST_DATA& trustData)
    {
        trustData = WINTRUST_DATA{};
        trustData.cbStruct = sizeof(trustData);
        trustData.dwUIChoice = WTD_UI_NONE;
        trustData.fdwRevocationChecks = WTD_REVOKE_NONE;
        trustData.dwProvFlags =
            WTD_SAFER_FLAG |
            WTD_CACHE_ONLY_URL_RETRIEVAL |
            WTD_DISABLE_MD2_MD4;
    }

    QString extractSigner(const WINTRUST_DATA& trustData)
    {
        if (trustData.hWVTStateData == nullptr)
        {
            return QString();
        }
        CRYPT_PROVIDER_DATA* const providerData =
            ::WTHelperProvDataFromStateData(trustData.hWVTStateData);
        if (providerData == nullptr)
        {
            return QString();
        }
        CRYPT_PROVIDER_SGNR* const signer =
            ::WTHelperGetProvSignerFromChain(providerData, 0, FALSE, 0);
        if (signer == nullptr || signer->csCertChain == 0U ||
            signer->pasCertChain == nullptr ||
            signer->pasCertChain[0].pCert == nullptr)
        {
            return QString();
        }

        const CERT_CONTEXT* const certificate = signer->pasCertChain[0].pCert;
        const DWORD requiredChars = ::CertGetNameStringW(
            certificate,
            CERT_NAME_SIMPLE_DISPLAY_TYPE,
            0,
            nullptr,
            nullptr,
            0);
        if (requiredChars <= 1U)
        {
            return QString();
        }

        std::vector<wchar_t> nameBuffer(requiredChars, L'\0');
        const DWORD writtenChars = ::CertGetNameStringW(
            certificate,
            CERT_NAME_SIMPLE_DISPLAY_TYPE,
            0,
            nullptr,
            nameBuffer.data(),
            requiredChars);
        if (writtenChars <= 1U)
        {
            return QString();
        }
        return QString::fromWCharArray(
            nameBuffer.data(),
            static_cast<int>(writtenChars - 1U)).trimmed();
    }

    LONG runWinTrustAndClose(
        WINTRUST_DATA& trustData,
        QString* const signerOut)
    {
        GUID policyGuid = WINTRUST_ACTION_GENERIC_VERIFY_V2;
        trustData.dwStateAction = WTD_STATEACTION_VERIFY;
        const LONG status = ::WinVerifyTrust(nullptr, &policyGuid, &trustData);
        if (signerOut != nullptr)
        {
            *signerOut = extractSigner(trustData);
        }
        trustData.dwStateAction = WTD_STATEACTION_CLOSE;
        ::WinVerifyTrust(nullptr, &policyGuid, &trustData);
        trustData.hWVTStateData = nullptr;
        return status;
    }

    bool calculateCatalogHash(
        const HCATADMIN catalogAdmin,
        const HANDLE fileHandle,
        std::vector<BYTE>& fileHash)
    {
        LARGE_INTEGER fileStart{};
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

        fileHash.resize(hashBytes);
        ::SetFilePointerEx(fileHandle, fileStart, nullptr, FILE_BEGIN);
        if (!::CryptCATAdminCalcHashFromFileHandle2(
                catalogAdmin,
                fileHandle,
                &hashBytes,
                fileHash.data(),
                0))
        {
            return false;
        }
        fileHash.resize(hashBytes);
        return true;
    }

    CatalogTrustResult verifyCatalogTrust(
        const QString& filePath,
        const HANDLE fileHandle)
    {
        CatalogTrustResult finalResult;
        const std::array<LPCWSTR, 3> algorithms{
            nullptr,
            BCRYPT_SHA256_ALGORITHM,
            BCRYPT_SHA1_ALGORITHM
        };
        QSet<QString> attemptedIdentifiers;

        for (const LPCWSTR algorithm : algorithms)
        {
            ScopedCatalogAdmin catalogAdmin;
            GUID subsystem = DRIVER_ACTION_VERIFY;
            if (!::CryptCATAdminAcquireContext2(
                    &catalogAdmin.value,
                    &subsystem,
                    algorithm,
                    nullptr,
                    0))
            {
                finalResult.lookupError = ::GetLastError();
                continue;
            }

            std::vector<BYTE> fileHash;
            if (!calculateCatalogHash(
                    catalogAdmin.value,
                    fileHandle,
                    fileHash))
            {
                finalResult.lookupError = ::GetLastError();
                continue;
            }

            const QString identifier = QString::fromLatin1(
                QByteArray(
                    reinterpret_cast<const char*>(fileHash.data()),
                    static_cast<qsizetype>(fileHash.size()))
                    .toHex().toUpper());
            if (attemptedIdentifiers.contains(identifier))
            {
                continue;
            }
            attemptedIdentifiers.insert(identifier);
            finalResult.fileIdentifier = identifier;

            HCATINFO previousCatalog = nullptr;
            for (;;)
            {
                HCATINFO currentCatalog = ::CryptCATAdminEnumCatalogFromHash(
                    catalogAdmin.value,
                    fileHash.data(),
                    static_cast<DWORD>(fileHash.size()),
                    0,
                    &previousCatalog);
                if (currentCatalog == nullptr)
                {
                    const DWORD enumerationError = ::GetLastError();
                    finalResult.lookupError = enumerationError == ERROR_SUCCESS
                        ? ERROR_NOT_FOUND
                        : enumerationError;
                    previousCatalog = nullptr;
                    break;
                }
                previousCatalog = currentCatalog;

                CATALOG_INFO catalogInfo{};
                catalogInfo.cbStruct = sizeof(catalogInfo);
                if (!::CryptCATCatalogInfoFromContext(
                        currentCatalog,
                        &catalogInfo,
                        0))
                {
                    finalResult.lookupError = ::GetLastError();
                    continue;
                }

                const QString catalogPath = QString::fromWCharArray(
                    catalogInfo.wszCatalogFile);
                WINTRUST_CATALOG_INFO trustCatalogInfo{};
                trustCatalogInfo.cbStruct = sizeof(trustCatalogInfo);
                trustCatalogInfo.pcwszCatalogFilePath =
                    reinterpret_cast<LPCWSTR>(catalogPath.utf16());
                trustCatalogInfo.pcwszMemberTag =
                    reinterpret_cast<LPCWSTR>(identifier.utf16());
                trustCatalogInfo.pcwszMemberFilePath =
                    reinterpret_cast<LPCWSTR>(filePath.utf16());
                trustCatalogInfo.hMemberFile = fileHandle;
                trustCatalogInfo.pbCalculatedFileHash = fileHash.data();
                trustCatalogInfo.cbCalculatedFileHash =
                    static_cast<DWORD>(fileHash.size());
                trustCatalogInfo.hCatAdmin = catalogAdmin.value;

                WINTRUST_DATA trustData{};
                initializeOfflineTrustData(trustData);
                trustData.dwUnionChoice = WTD_CHOICE_CATALOG;
                trustData.pCatalog = &trustCatalogInfo;
                LARGE_INTEGER fileStart{};
                ::SetFilePointerEx(fileHandle, fileStart, nullptr, FILE_BEGIN);

                QString catalogSigner;
                const LONG trustStatus = runWinTrustAndClose(
                    trustData,
                    &catalogSigner);
                finalResult.catalogPath = catalogPath;
                finalResult.trustStatus = trustStatus;
                finalResult.trustStatusAvailable = true;
                if (!catalogSigner.isEmpty())
                {
                    finalResult.signer = catalogSigner;
                }
                if (trustStatus == ERROR_SUCCESS)
                {
                    finalResult.trusted = true;
                    finalResult.lookupError = ERROR_SUCCESS;
                    ::CryptCATAdminReleaseCatalogContext(
                        catalogAdmin.value,
                        currentCatalog,
                        0);
                    previousCatalog = nullptr;
                    return finalResult;
                }
            }
        }
        return finalResult;
    }

    void verifyAuthenticode(ks::process::DllFileEvidence& evidence)
    {
        WINTRUST_FILE_INFO fileInfo{};
        fileInfo.cbStruct = sizeof(fileInfo);
        fileInfo.pcwszFilePath =
            reinterpret_cast<LPCWSTR>(evidence.path.utf16());

        WINTRUST_DATA embeddedTrustData{};
        initializeOfflineTrustData(embeddedTrustData);
        embeddedTrustData.dwUnionChoice = WTD_CHOICE_FILE;
        embeddedTrustData.pFile = &fileInfo;
        evidence.embeddedTrustStatus = static_cast<std::int32_t>(
            runWinTrustAndClose(embeddedTrustData, &evidence.signer));
        if (evidence.embeddedTrustStatus == ERROR_SUCCESS)
        {
            evidence.trusted = true;
            evidence.trustSource = ks::process::DllHijackTrustSource::Embedded;
            return;
        }

        evidence.catalogAttempted = true;
        ScopedFileHandle fileHandle(evidence.path);
        if (fileHandle.value == INVALID_HANDLE_VALUE)
        {
            evidence.catalogLookupError = ::GetLastError();
            return;
        }

        const CatalogTrustResult catalogTrust = verifyCatalogTrust(
            evidence.path,
            fileHandle.value);
        evidence.catalogTrustStatus =
            static_cast<std::int32_t>(catalogTrust.trustStatus);
        evidence.catalogLookupError = catalogTrust.lookupError;
        evidence.catalogTrustStatusAvailable =
            catalogTrust.trustStatusAvailable;
        if (!catalogTrust.signer.isEmpty())
        {
            evidence.signer = catalogTrust.signer;
        }
        if (catalogTrust.trusted)
        {
            evidence.trusted = true;
            evidence.trustSource = ks::process::DllHijackTrustSource::Catalog;
        }
    }

    ks::process::DllFileEvidence readFileEvidence(const QString& rawPath)
    {
        ks::process::DllFileEvidence evidence;
        evidence.path = normalizedAbsolutePath(rawPath);
        const QFileInfo fileInfo(evidence.path);
        evidence.readable = fileInfo.exists() && fileInfo.isFile() && fileInfo.isReadable();
        if (!fileInfo.exists() || !fileInfo.isFile())
        {
            return evidence;
        }

        evidence.sizeBytes = fileInfo.size() > 0
            ? static_cast<std::uint64_t>(fileInfo.size())
            : 0U;
        const DWORD attributes = ::GetFileAttributesW(
            reinterpret_cast<LPCWSTR>(evidence.path.utf16()));
        evidence.reparsePoint = attributes != INVALID_FILE_ATTRIBUTES &&
            (attributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0U;
        evidence.machine = readPeMachine(evidence.path);

        const VersionEvidence versionEvidence = readVersionEvidence(evidence.path);
        evidence.companyName = versionEvidence.companyName;
        evidence.originalFilename = versionEvidence.originalFilename;
        evidence.fileVersion = versionEvidence.fileVersion;
        evidence.sha256 = calculateSha256(evidence.path);
        verifyAuthenticode(evidence);
        return evidence;
    }

    QSet<QString> queryKnownDllNames()
    {
        QSet<QString> names;
        HKEY knownDllKey = nullptr;
        LONG openStatus = ::RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            L"SYSTEM\\CurrentControlSet\\Control\\Session Manager\\KnownDLLs",
            0,
            KEY_READ | KEY_WOW64_64KEY,
            &knownDllKey);
        if (openStatus != ERROR_SUCCESS)
        {
            openStatus = ::RegOpenKeyExW(
                HKEY_LOCAL_MACHINE,
                L"SYSTEM\\CurrentControlSet\\Control\\Session Manager\\KnownDLLs",
                0,
                KEY_READ,
                &knownDllKey);
        }
        if (openStatus != ERROR_SUCCESS || knownDllKey == nullptr)
        {
            return names;
        }

        DWORD valueCount = 0U;
        DWORD maxValueNameChars = 0U;
        DWORD maxValueDataBytes = 0U;
        if (::RegQueryInfoKeyW(
                knownDllKey,
                nullptr,
                nullptr,
                nullptr,
                nullptr,
                nullptr,
                nullptr,
                &valueCount,
                &maxValueNameChars,
                &maxValueDataBytes,
                nullptr,
                nullptr) == ERROR_SUCCESS)
        {
            std::vector<wchar_t> valueName(maxValueNameChars + 2U, L'\0');
            std::vector<BYTE> valueData(maxValueDataBytes + sizeof(wchar_t), 0U);
            for (DWORD valueIndex = 0U; valueIndex < valueCount; ++valueIndex)
            {
                DWORD valueNameChars = static_cast<DWORD>(valueName.size());
                DWORD valueDataBytes = static_cast<DWORD>(valueData.size());
                DWORD valueType = 0U;
                const LONG enumerateStatus = ::RegEnumValueW(
                    knownDllKey,
                    valueIndex,
                    valueName.data(),
                    &valueNameChars,
                    nullptr,
                    &valueType,
                    valueData.data(),
                    &valueDataBytes);
                if (enumerateStatus != ERROR_SUCCESS ||
                    (valueType != REG_SZ && valueType != REG_EXPAND_SZ) ||
                    valueDataBytes < sizeof(wchar_t))
                {
                    continue;
                }

                const auto* const valueText =
                    reinterpret_cast<const wchar_t*>(valueData.data());
                int valueChars = static_cast<int>(
                    valueDataBytes / sizeof(wchar_t));
                while (valueChars > 0 && valueText[valueChars - 1] == L'\0')
                {
                    --valueChars;
                }
                if (valueChars == 0)
                {
                    continue;
                }
                const QString dllName = QFileInfo(
                    QString::fromWCharArray(valueText, valueChars)
                        .trimmed())
                    .fileName()
                    .toCaseFolded();
                if (!dllName.isEmpty())
                {
                    names.insert(dllName);
                }
            }
        }
        ::RegCloseKey(knownDllKey);
        return names;
    }

    bool sameText(const QString& left, const QString& right)
    {
        return left.trimmed().compare(right.trimmed(), Qt::CaseInsensitive) == 0;
    }

    ks::process::DllHijackRisk classifyRisk(
        const ks::process::DllHijackFinding& finding)
    {
        if (finding.hashComparable && finding.hashesMatch)
        {
            return ks::process::DllHijackRisk::Safe;
        }
        if (!finding.machineCompatible)
        {
            return finding.presence == ks::process::DllHijackPresence::Loaded
                ? ks::process::DllHijackRisk::High
                : ks::process::DllHijackRisk::Informational;
        }

        const bool signerMismatch =
            finding.signerComparable && !finding.signersMatch;
        const bool originalNameMismatch =
            finding.originalFilenameComparable &&
            !finding.originalFilenamesMatch;
        const bool strongReplacementEvidence =
            !finding.localFile.trusted ||
            signerMismatch ||
            originalNameMismatch ||
            finding.localFile.reparsePoint;

        if (finding.presence == ks::process::DllHijackPresence::Loaded)
        {
            return strongReplacementEvidence
                ? ks::process::DllHijackRisk::High
                : ks::process::DllHijackRisk::Suspicious;
        }
        if (finding.knownDll && !finding.dllRedirectionPresent)
        {
            return ks::process::DllHijackRisk::Informational;
        }
        return strongReplacementEvidence
            ? ks::process::DllHijackRisk::Suspicious
            : ks::process::DllHijackRisk::Informational;
    }

    int riskSortValue(const ks::process::DllHijackRisk risk)
    {
        switch (risk)
        {
        case ks::process::DllHijackRisk::High:
            return 3;
        case ks::process::DllHijackRisk::Suspicious:
            return 2;
        case ks::process::DllHijackRisk::Informational:
            return 1;
        case ks::process::DllHijackRisk::Safe:
        default:
            return 0;
        }
    }
}

namespace ks::process
{
    DllHijackScanResult ScanProcessDllHijacking(
        const std::uint32_t pid,
        const std::uint64_t expectedCreationTime100ns,
        const QString& fallbackImagePath)
    {
        DllHijackScanResult result;

        std::uint64_t currentCreationTime100ns = 0U;
        std::string identityDiagnostic;
        if (!QueryProcessCreationTimeByPid(
                pid,
                &currentCreationTime100ns,
                &identityDiagnostic))
        {
            result.status = DllHijackScanStatus::ProcessIdentityUnavailable;
            result.diagnosticText = QString::fromStdString(identityDiagnostic);
            return result;
        }
        if (expectedCreationTime100ns != 0U &&
            expectedCreationTime100ns != currentCreationTime100ns)
        {
            result.status = DllHijackScanStatus::ProcessIdentityMismatch;
            result.diagnosticText = QStringLiteral("expected=%1 actual=%2")
                .arg(expectedCreationTime100ns)
                .arg(currentCreationTime100ns);
            return result;
        }

        const std::uint64_t verifiedCreationTime100ns =
            expectedCreationTime100ns != 0U
                ? expectedCreationTime100ns
                : currentCreationTime100ns;
        const ProcessModuleSnapshot moduleSnapshot =
            EnumerateProcessModulesAndThreadsIfIdentityMatches(
                pid,
                verifiedCreationTime100ns,
                false);
        result.loadedModuleEvidenceAvailable = !moduleSnapshot.modules.empty();

        const std::string queriedImagePath = QueryProcessPathByPid(pid);
        result.processImagePath = normalizedAbsolutePath(
            queriedImagePath.empty()
                ? fallbackImagePath
                : QString::fromStdString(queriedImagePath));
        if (result.processImagePath.isEmpty() ||
            !QFileInfo(result.processImagePath).isFile())
        {
            for (const ProcessModuleRecord& module : moduleSnapshot.modules)
            {
                const QString modulePath = normalizedAbsolutePath(
                    QString::fromStdString(module.modulePath));
                if (QFileInfo(modulePath).suffix().compare(
                        QStringLiteral("exe"),
                        Qt::CaseInsensitive) == 0)
                {
                    result.processImagePath = modulePath;
                    break;
                }
            }
        }
        if (result.processImagePath.isEmpty() ||
            !QFileInfo(result.processImagePath).isFile())
        {
            result.status = DllHijackScanStatus::ImagePathUnavailable;
            result.diagnosticText = QString::fromStdString(
                moduleSnapshot.diagnosticText);
            return result;
        }

        result.applicationDirectory = normalizedAbsolutePath(
            QFileInfo(result.processImagePath).absolutePath());
        if (result.applicationDirectory.isEmpty() ||
            !QFileInfo(result.applicationDirectory).isDir())
        {
            result.status = DllHijackScanStatus::ApplicationDirectoryUnavailable;
            return result;
        }

        const std::uint16_t processMachine = readPeMachine(
            result.processImagePath);
        const QString nativeSystemDirectory = queryNativeSystemDirectory();
        const QString wow64SystemDirectory = queryWow64SystemDirectory();
        result.systemDirectory = processMachine == IMAGE_FILE_MACHINE_I386 &&
                !wow64SystemDirectory.isEmpty()
            ? wow64SystemDirectory
            : nativeSystemDirectory;
        if (result.systemDirectory.isEmpty() ||
            !QFileInfo(result.systemDirectory).isDir())
        {
            result.status = DllHijackScanStatus::SystemDirectoryUnavailable;
            return result;
        }

        const QString applicationDirectoryKey = pathKey(
            result.applicationDirectory);
        if (applicationDirectoryKey == pathKey(nativeSystemDirectory) ||
            (!wow64SystemDirectory.isEmpty() &&
                applicationDirectoryKey == pathKey(wow64SystemDirectory)))
        {
            result.diagnosticText = QStringLiteral(
                "application directory is an architecture system directory");
            return result;
        }

        const QFileInfo redirectionInfo(result.processImagePath + QStringLiteral(".local"));
        result.dllRedirectionPresent = redirectionInfo.exists();

        QMap<QString, CandidateDll> candidates;
        auto addCandidate = [&candidates, &result](
            const QString& rawPath,
            const bool loaded)
        {
            const QString normalizedPath = normalizedAbsolutePath(rawPath);
            if (normalizedPath.isEmpty() ||
                QFileInfo(normalizedPath).suffix().compare(
                    QStringLiteral("dll"),
                    Qt::CaseInsensitive) != 0 ||
                !pathIsInsideDirectory(
                    normalizedPath,
                    result.applicationDirectory))
            {
                return;
            }

            const QString key = pathKey(normalizedPath);
            auto existing = candidates.find(key);
            if (existing == candidates.end())
            {
                CandidateDll candidate;
                candidate.path = normalizedPath;
                candidate.loaded = loaded;
                candidates.insert(key, candidate);
            }
            else if (loaded)
            {
                existing->loaded = true;
            }
        };

        QDirIterator directoryIterator(
            result.applicationDirectory,
            QStringList{QStringLiteral("*.dll")},
            QDir::Files | QDir::Hidden | QDir::System | QDir::NoDotAndDotDot,
            QDirIterator::NoIteratorFlags);
        while (directoryIterator.hasNext())
        {
            if (result.scannedApplicationDllCount >= MaxApplicationDllCount)
            {
                result.directoryEnumerationTruncated = true;
                break;
            }
            const QString dllPath = directoryIterator.next();
            ++result.scannedApplicationDllCount;
            addCandidate(dllPath, false);
        }

        for (const ProcessModuleRecord& module : moduleSnapshot.modules)
        {
            addCandidate(QString::fromStdString(module.modulePath), true);
        }

        const QSet<QString> knownDllNames = queryKnownDllNames();
        QHash<QString, DllFileEvidence> systemEvidenceCache;
        for (auto candidateIterator = candidates.cbegin();
             candidateIterator != candidates.cend();
             ++candidateIterator)
        {
            const CandidateDll& candidate = candidateIterator.value();
            const QString dllName = QFileInfo(candidate.path).fileName();
            const QString systemPath = normalizedAbsolutePath(
                QDir(result.systemDirectory).filePath(dllName));
            if (!QFileInfo(systemPath).isFile() ||
                pathKey(systemPath) == pathKey(candidate.path))
            {
                continue;
            }
            ++result.systemNameCollisionCount;

            const QString systemKey = pathKey(systemPath);
            auto systemEvidenceIterator = systemEvidenceCache.find(systemKey);
            if (systemEvidenceIterator == systemEvidenceCache.end())
            {
                systemEvidenceIterator = systemEvidenceCache.insert(
                    systemKey,
                    readFileEvidence(systemPath));
            }
            const DllFileEvidence& systemEvidence = systemEvidenceIterator.value();
            if (!systemEvidence.trusted)
            {
                continue;
            }
            ++result.signedSystemBaselineCount;
            if (!machinesCompatible(processMachine, systemEvidence.machine))
            {
                ++result.skippedArchitectureMismatchCount;
                continue;
            }

            DllHijackFinding finding;
            finding.localFile = readFileEvidence(candidate.path);
            finding.systemFile = systemEvidence;
            finding.presence = candidate.loaded
                ? DllHijackPresence::Loaded
                : DllHijackPresence::PresentOnly;
            finding.knownDll = knownDllNames.contains(dllName.toCaseFolded());
            finding.dllRedirectionPresent = result.dllRedirectionPresent;
            finding.hashComparable = !finding.localFile.sha256.isEmpty() &&
                !finding.systemFile.sha256.isEmpty();
            finding.hashesMatch = finding.hashComparable &&
                sameText(finding.localFile.sha256, finding.systemFile.sha256);
            finding.signerComparable = !finding.localFile.signer.isEmpty() &&
                !finding.systemFile.signer.isEmpty();
            finding.signersMatch = finding.signerComparable &&
                sameText(finding.localFile.signer, finding.systemFile.signer);
            finding.companyComparable = !finding.localFile.companyName.isEmpty() &&
                !finding.systemFile.companyName.isEmpty();
            finding.companiesMatch = finding.companyComparable &&
                sameText(
                    finding.localFile.companyName,
                    finding.systemFile.companyName);
            finding.originalFilenameComparable =
                !finding.localFile.originalFilename.isEmpty() &&
                !finding.systemFile.originalFilename.isEmpty();
            finding.originalFilenamesMatch =
                finding.originalFilenameComparable &&
                sameText(
                    finding.localFile.originalFilename,
                    finding.systemFile.originalFilename);
            finding.versionComparable = !finding.localFile.fileVersion.isEmpty() &&
                !finding.systemFile.fileVersion.isEmpty();
            finding.versionsMatch = finding.versionComparable &&
                sameText(
                    finding.localFile.fileVersion,
                    finding.systemFile.fileVersion);
            finding.machineCompatible = machinesCompatible(
                processMachine,
                finding.localFile.machine);
            finding.risk = classifyRisk(finding);
            result.findings.push_back(std::move(finding));
        }

        std::uint64_t finalCreationTime100ns = 0U;
        std::string finalIdentityDiagnostic;
        if (!QueryProcessCreationTimeByPid(
                pid,
                &finalCreationTime100ns,
                &finalIdentityDiagnostic))
        {
            result.status = DllHijackScanStatus::ProcessIdentityUnavailable;
            result.diagnosticText =
                QString::fromStdString(finalIdentityDiagnostic);
            result.findings.clear();
            return result;
        }
        if (finalCreationTime100ns != verifiedCreationTime100ns)
        {
            result.status = DllHijackScanStatus::ProcessIdentityMismatch;
            result.diagnosticText = QStringLiteral("expected=%1 actual=%2")
                .arg(verifiedCreationTime100ns)
                .arg(finalCreationTime100ns);
            result.findings.clear();
            return result;
        }

        std::sort(
            result.findings.begin(),
            result.findings.end(),
            [](const DllHijackFinding& left, const DllHijackFinding& right)
            {
                const int leftRisk = riskSortValue(left.risk);
                const int rightRisk = riskSortValue(right.risk);
                if (leftRisk != rightRisk)
                {
                    return leftRisk > rightRisk;
                }
                if (left.presence != right.presence)
                {
                    return left.presence == DllHijackPresence::Loaded;
                }
                return QFileInfo(left.localFile.path).fileName().compare(
                    QFileInfo(right.localFile.path).fileName(),
                    Qt::CaseInsensitive) < 0;
            });
        return result;
    }
}
