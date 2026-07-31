#include "ArkRuntimeDynData.h"

// Product policy: DynData must remain usable on fully offline target machines.
// Keep the former resolver source for reference while compiling it out of every
// build; pack misses are handled only by packaged profiles or feature-local
// signature resolvers and must never contact a symbol server on the target PC.
#if 0

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#include <OleAuto.h>
#include <DbgHelp.h>
#include <WinHttp.h>

#include <algorithm>
#include <array>
#include <cctype>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <limits>
#include <memory>
#include <mutex>
#include <sstream>
#include <string_view>
#include <system_error>
#include <unordered_map>
#include <utility>

#pragma comment(lib, "Dbghelp.lib")
#pragma comment(lib, "Winhttp.lib")

namespace ksword::ark
{
    namespace
    {
        constexpr std::uint32_t kMaximumProfileOffset = 0x0000FFFFU;
        constexpr std::uint32_t kMaximumGlobalRva = 0x7FFFFFFFU;
        constexpr std::size_t kSymbolNameCapacity = 1024U;

        enum class CatalogKind
        {
            StructOffset,
            TypeSize,
            GlobalRva
        };

        struct CatalogEntry
        {
            CatalogKind kind;
            std::uint32_t fieldId;
            const char* logicalName;
            const char* typeName;
            const char* memberOrSymbols;
            bool callback;
        };

#define KSW_RUNTIME_FIELD(id, logicalName, typeName, memberName) \
        { CatalogKind::StructOffset, id, logicalName, typeName, memberName, false },
#define KSW_RUNTIME_TYPE_SIZE(id, logicalName, typeName) \
        { CatalogKind::TypeSize, id, logicalName, typeName, "", false },
#define KSW_RUNTIME_GLOBAL(id, logicalName, symbolName, callbackValue) \
        { CatalogKind::GlobalRva, id, logicalName, "", symbolName, callbackValue },
#define KSW_RUNTIME_CALLBACK_FIELD(id, logicalName, typeName, memberName) \
        { CatalogKind::StructOffset, id, logicalName, typeName, memberName, true },
        constexpr CatalogEntry kCatalog[] = {
#include "ArkRuntimeDynDataCatalog.inc"
        };
#undef KSW_RUNTIME_CALLBACK_FIELD
#undef KSW_RUNTIME_GLOBAL
#undef KSW_RUNTIME_TYPE_SIZE
#undef KSW_RUNTIME_FIELD

        struct MemberLayout
        {
            std::uint32_t offset = 0;
            std::uint32_t bitPosition = 0;
            std::uint32_t storageBytes = 0;
            bool hasBitPosition = false;
        };

        struct PeIdentity
        {
            std::uint32_t machine = 0;
            std::uint32_t timeDateStamp = 0;
            std::uint32_t sizeOfImage = 0;
            GUID pdbGuid{};
            std::uint32_t pdbAge = 0;
            std::wstring pdbName;
            bool pdbIdentityAvailable = false;
        };

        struct ScopedHandle
        {
            HANDLE value = nullptr;

            ScopedHandle() = default;
            explicit ScopedHandle(const HANDLE handle) : value(handle) {}
            ScopedHandle(const ScopedHandle&) = delete;
            ScopedHandle& operator=(const ScopedHandle&) = delete;
            ScopedHandle(ScopedHandle&& other) noexcept : value(other.value)
            {
                other.value = nullptr;
            }
            ScopedHandle& operator=(ScopedHandle&& other) noexcept
            {
                if (this != &other)
                {
                    reset();
                    value = other.value;
                    other.value = nullptr;
                }
                return *this;
            }
            ~ScopedHandle()
            {
                reset();
            }
            void reset(const HANDLE replacement = nullptr)
            {
                if (value != nullptr && value != INVALID_HANDLE_VALUE)
                {
                    ::CloseHandle(value);
                }
                value = replacement;
            }
            explicit operator bool() const
            {
                return value != nullptr && value != INVALID_HANDLE_VALUE;
            }
        };

        struct ScopedView
        {
            const void* value = nullptr;
            ~ScopedView()
            {
                if (value != nullptr)
                {
                    ::UnmapViewOfFile(value);
                }
            }
        };

        struct ScopedInternetHandle
        {
            HINTERNET value = nullptr;

            ScopedInternetHandle() = default;
            explicit ScopedInternetHandle(const HINTERNET handle)
                : value(handle)
            {
            }
            ScopedInternetHandle(const ScopedInternetHandle&) = delete;
            ScopedInternetHandle& operator=(
                const ScopedInternetHandle&) = delete;
            ScopedInternetHandle(ScopedInternetHandle&& other) noexcept
                : value(other.value)
            {
                other.value = nullptr;
            }
            ScopedInternetHandle& operator=(
                ScopedInternetHandle&& other) noexcept
            {
                if (this != &other)
                {
                    reset();
                    value = other.value;
                    other.value = nullptr;
                }
                return *this;
            }
            ~ScopedInternetHandle()
            {
                reset();
            }
            void reset(const HINTERNET replacement = nullptr)
            {
                if (value != nullptr)
                {
                    ::WinHttpCloseHandle(value);
                }
                value = replacement;
            }
            explicit operator bool() const
            {
                return value != nullptr;
            }
        };

        struct DbgHelpSession
        {
            ScopedHandle key;
            DWORD previousOptions = 0U;
            bool optionsCaptured = false;
            bool initialized = false;
            DWORD64 moduleBase = 0ULL;

            ~DbgHelpSession()
            {
                if (initialized)
                {
                    if (moduleBase != 0ULL)
                    {
                        ::SymUnloadModule64(key.value, moduleBase);
                    }
                    ::SymCleanup(key.value);
                }
                if (optionsCaptured)
                {
                    ::SymSetOptions(previousOptions);
                }
            }
        };

        struct TypeLayout
        {
            bool loaded = false;
            std::uint64_t size = 0ULL;
            std::unordered_map<std::string, MemberLayout> members;
        };

        // DbgHelp is explicitly single-threaded. This mutex covers every call
        // made by the runtime profile resolver, including cleanup and options.
        std::mutex g_dbgHelpMutex;
        std::mutex g_pdbDownloadMutex;
        std::mutex g_resultCacheMutex;
        std::unordered_map<std::string, RuntimeDynDataResolveResult>
            g_resultCache;

        std::wstring lastErrorText(const wchar_t* const operation)
        {
            std::wostringstream stream;
            stream << operation << L" failed (Win32=" << ::GetLastError() << L")";
            return stream.str();
        }

        std::wstring environmentValue(const wchar_t* const name)
        {
            const DWORD required = ::GetEnvironmentVariableW(name, nullptr, 0U);
            if (required == 0U)
            {
                return {};
            }
            std::wstring value(required, L'\0');
            const DWORD copied = ::GetEnvironmentVariableW(name, value.data(), required);
            if (copied == 0U || copied >= required)
            {
                return {};
            }
            value.resize(copied);
            return value;
        }

        std::wstring joinDiagnostics(const std::vector<std::wstring>& lines)
        {
            std::wstring result;
            for (const std::wstring& line : lines)
            {
                if (line.empty())
                {
                    continue;
                }
                if (!result.empty())
                {
                    result += L" | ";
                }
                result += line;
            }
            return result;
        }

        std::string wideToUtf8(const std::wstring& value)
        {
            if (value.empty())
            {
                return {};
            }
            const int required = ::WideCharToMultiByte(
                CP_UTF8,
                WC_ERR_INVALID_CHARS,
                value.c_str(),
                static_cast<int>(value.size()),
                nullptr,
                0,
                nullptr,
                nullptr);
            if (required <= 0)
            {
                return {};
            }
            std::string result(static_cast<std::size_t>(required), '\0');
            const int copied = ::WideCharToMultiByte(
                CP_UTF8,
                WC_ERR_INVALID_CHARS,
                value.c_str(),
                static_cast<int>(value.size()),
                result.data(),
                required,
                nullptr,
                nullptr);
            if (copied != required)
            {
                return {};
            }
            return result;
        }

        template <std::size_t Size>
        void copyAnsi(char (&destination)[Size], const std::string& source)
        {
            static_assert(Size > 0U);
            std::memset(destination, 0, Size);
            const std::size_t count = std::min<std::size_t>(Size - 1U, source.size());
            if (count != 0U)
            {
                std::memcpy(destination, source.data(), count);
            }
        }

        template <std::size_t Size>
        void copyWide(wchar_t (&destination)[Size], const std::wstring& source)
        {
            static_assert(Size > 0U);
            std::fill(std::begin(destination), std::end(destination), L'\0');
            const std::size_t count = std::min<std::size_t>(Size - 1U, source.size());
            if (count != 0U)
            {
                std::copy_n(source.begin(), count, destination);
            }
        }

        bool rvaToRawOffset(
            const std::uint32_t rva,
            const std::uint32_t bytesRequired,
            const std::uint32_t sizeOfHeaders,
            const IMAGE_SECTION_HEADER* const sections,
            const std::uint16_t sectionCount,
            const std::uint64_t fileSize,
            std::uint64_t& rawOffsetOut)
        {
            rawOffsetOut = 0ULL;
            const std::uint64_t requiredEnd =
                static_cast<std::uint64_t>(rva) + bytesRequired;
            if (rva < sizeOfHeaders && requiredEnd <= fileSize)
            {
                rawOffsetOut = rva;
                return true;
            }
            if (sections == nullptr)
            {
                return false;
            }
            for (std::uint16_t index = 0U;
                 index < sectionCount;
                 ++index)
            {
                const IMAGE_SECTION_HEADER& section = sections[index];
                const std::uint64_t sectionStart =
                    section.VirtualAddress;
                const std::uint64_t sectionSpan = std::max<std::uint64_t>(
                    section.Misc.VirtualSize,
                    section.SizeOfRawData);
                if (rva < sectionStart ||
                    static_cast<std::uint64_t>(rva) >=
                        sectionStart + sectionSpan)
                {
                    continue;
                }
                const std::uint64_t delta =
                    static_cast<std::uint64_t>(rva) - sectionStart;
                if (delta + bytesRequired > section.SizeOfRawData)
                {
                    return false;
                }
                const std::uint64_t rawOffset =
                    static_cast<std::uint64_t>(
                        section.PointerToRawData) +
                    delta;
                if (rawOffset + bytesRequired > fileSize)
                {
                    return false;
                }
                rawOffsetOut = rawOffset;
                return true;
            }
            return false;
        }

        bool readRsdsIdentity(
            const std::uint8_t* const bytes,
            const std::uint64_t fileSize,
            const std::uint32_t debugDirectoryRva,
            const std::uint32_t debugDirectorySize,
            const std::uint32_t sizeOfHeaders,
            const IMAGE_SECTION_HEADER* const sections,
            const std::uint16_t sectionCount,
            PeIdentity& identityOut)
        {
            if (bytes == nullptr ||
                debugDirectoryRva == 0U ||
                debugDirectorySize < sizeof(IMAGE_DEBUG_DIRECTORY))
            {
                return false;
            }
            std::uint64_t directoryOffset = 0ULL;
            if (!rvaToRawOffset(
                    debugDirectoryRva,
                    debugDirectorySize,
                    sizeOfHeaders,
                    sections,
                    sectionCount,
                    fileSize,
                    directoryOffset))
            {
                return false;
            }

            const std::size_t directoryCount =
                debugDirectorySize / sizeof(IMAGE_DEBUG_DIRECTORY);
            const auto* const directories =
                reinterpret_cast<const IMAGE_DEBUG_DIRECTORY*>(
                    bytes + directoryOffset);
            for (std::size_t index = 0U;
                 index < directoryCount;
                 ++index)
            {
                const IMAGE_DEBUG_DIRECTORY& directory =
                    directories[index];
                if (directory.Type != IMAGE_DEBUG_TYPE_CODEVIEW ||
                    directory.SizeOfData < 25U)
                {
                    continue;
                }

                std::uint64_t recordOffset =
                    directory.PointerToRawData;
                if (recordOffset == 0ULL &&
                    !rvaToRawOffset(
                        directory.AddressOfRawData,
                        directory.SizeOfData,
                        sizeOfHeaders,
                        sections,
                        sectionCount,
                        fileSize,
                        recordOffset))
                {
                    continue;
                }
                if (recordOffset + directory.SizeOfData > fileSize)
                {
                    continue;
                }
                const std::uint8_t* const record =
                    bytes + recordOffset;
                if (std::memcmp(record, "RSDS", 4U) != 0)
                {
                    continue;
                }

                GUID guid{};
                std::uint32_t age = 0U;
                std::memcpy(&guid, record + 4U, sizeof(guid));
                std::memcpy(
                    &age,
                    record + 4U + sizeof(guid),
                    sizeof(age));
                static constexpr GUID zeroGuid{};
                if (std::memcmp(
                        &guid,
                        &zeroGuid,
                        sizeof(guid)) == 0 ||
                    age == 0U)
                {
                    continue;
                }

                const char* const rawPath =
                    reinterpret_cast<const char*>(
                        record + 4U + sizeof(guid) +
                        sizeof(age));
                const std::size_t pathCapacity =
                    directory.SizeOfData -
                    (4U + sizeof(guid) + sizeof(age));
                const void* const terminator =
                    std::memchr(rawPath, '\0', pathCapacity);
                if (terminator == nullptr)
                {
                    continue;
                }
                std::string pdbPath(
                    rawPath,
                    static_cast<const char*>(terminator));
                const std::size_t separator =
                    pdbPath.find_last_of("\\/");
                const std::string pdbName =
                    separator == std::string::npos
                        ? pdbPath
                        : pdbPath.substr(separator + 1U);
                if (pdbName.empty() ||
                    !std::all_of(
                        pdbName.cbegin(),
                        pdbName.cend(),
                        [](const char character) {
                            const unsigned char value =
                                static_cast<unsigned char>(
                                    character);
                            return (value >= 'A' &&
                                    value <= 'Z') ||
                                (value >= 'a' &&
                                 value <= 'z') ||
                                (value >= '0' &&
                                 value <= '9') ||
                                character == '.' ||
                                character == '_' ||
                                character == '-';
                        }))
                {
                    continue;
                }

                identityOut.pdbGuid = guid;
                identityOut.pdbAge = age;
                identityOut.pdbName.assign(
                    pdbName.cbegin(),
                    pdbName.cend());
                identityOut.pdbIdentityAvailable = true;
                return true;
            }
            return false;
        }

        bool readPeIdentity(const std::filesystem::path& path, PeIdentity& identityOut)
        {
            identityOut = {};
            ScopedHandle file(::CreateFileW(
                path.c_str(),
                GENERIC_READ,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                nullptr,
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                nullptr));
            if (!file)
            {
                return false;
            }

            LARGE_INTEGER fileSize{};
            if (::GetFileSizeEx(file.value, &fileSize) == FALSE ||
                fileSize.QuadPart < static_cast<LONGLONG>(sizeof(IMAGE_DOS_HEADER)))
            {
                return false;
            }

            ScopedHandle mapping(::CreateFileMappingW(file.value, nullptr, PAGE_READONLY, 0U, 0U, nullptr));
            if (!mapping)
            {
                return false;
            }
            ScopedView view{::MapViewOfFile(mapping.value, FILE_MAP_READ, 0U, 0U, 0U)};
            if (view.value == nullptr)
            {
                return false;
            }

            const auto* const bytes = static_cast<const std::uint8_t*>(view.value);
            const auto* const dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(bytes);
            if (dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew <= 0)
            {
                return false;
            }
            const std::uint64_t ntOffset = static_cast<std::uint64_t>(dos->e_lfanew);
            if (ntOffset + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) + sizeof(WORD) >
                static_cast<std::uint64_t>(fileSize.QuadPart))
            {
                return false;
            }
            const auto* const signature = reinterpret_cast<const DWORD*>(bytes + ntOffset);
            if (*signature != IMAGE_NT_SIGNATURE)
            {
                return false;
            }
            const auto* const fileHeader = reinterpret_cast<const IMAGE_FILE_HEADER*>(
                bytes + ntOffset + sizeof(DWORD));
            const auto* const optionalMagic = reinterpret_cast<const WORD*>(
                bytes + ntOffset + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER));
            const std::uint64_t optionalEnd =
                ntOffset + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) + fileHeader->SizeOfOptionalHeader;
            if (optionalEnd > static_cast<std::uint64_t>(fileSize.QuadPart))
            {
                return false;
            }

            std::uint32_t sizeOfImage = 0U;
            std::uint32_t sizeOfHeaders = 0U;
            std::uint32_t debugDirectoryRva = 0U;
            std::uint32_t debugDirectorySize = 0U;
            if (*optionalMagic == IMAGE_NT_OPTIONAL_HDR64_MAGIC &&
                fileHeader->SizeOfOptionalHeader >= sizeof(IMAGE_OPTIONAL_HEADER64))
            {
                const auto* const optional = reinterpret_cast<const IMAGE_OPTIONAL_HEADER64*>(optionalMagic);
                sizeOfImage = optional->SizeOfImage;
                sizeOfHeaders = optional->SizeOfHeaders;
                debugDirectoryRva =
                    optional->DataDirectory[
                        IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress;
                debugDirectorySize =
                    optional->DataDirectory[
                        IMAGE_DIRECTORY_ENTRY_DEBUG].Size;
            }
            else if (*optionalMagic == IMAGE_NT_OPTIONAL_HDR32_MAGIC &&
                fileHeader->SizeOfOptionalHeader >= sizeof(IMAGE_OPTIONAL_HEADER32))
            {
                const auto* const optional = reinterpret_cast<const IMAGE_OPTIONAL_HEADER32*>(optionalMagic);
                sizeOfImage = optional->SizeOfImage;
                sizeOfHeaders = optional->SizeOfHeaders;
                debugDirectoryRva =
                    optional->DataDirectory[
                        IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress;
                debugDirectorySize =
                    optional->DataDirectory[
                        IMAGE_DIRECTORY_ENTRY_DEBUG].Size;
            }
            else
            {
                return false;
            }

            identityOut.machine = fileHeader->Machine;
            identityOut.timeDateStamp = fileHeader->TimeDateStamp;
            identityOut.sizeOfImage = sizeOfImage;
            const auto* const sections =
                reinterpret_cast<const IMAGE_SECTION_HEADER*>(
                    bytes + optionalEnd);
            const std::uint64_t sectionsEnd =
                optionalEnd +
                static_cast<std::uint64_t>(
                    fileHeader->NumberOfSections) *
                    sizeof(IMAGE_SECTION_HEADER);
            if (sectionsEnd <=
                static_cast<std::uint64_t>(
                    fileSize.QuadPart))
            {
                (void)readRsdsIdentity(
                    bytes,
                    static_cast<std::uint64_t>(
                        fileSize.QuadPart),
                    debugDirectoryRva,
                    debugDirectorySize,
                    sizeOfHeaders,
                    sections,
                    fileHeader->NumberOfSections,
                    identityOut);
            }
            return sizeOfImage != 0U;
        }

        std::vector<std::filesystem::path> imageCandidates(const ArkDynModuleIdentity& identity)
        {
            std::vector<std::filesystem::path> candidates;
            std::filesystem::path modulePath(identity.moduleName);
            if (modulePath.has_parent_path())
            {
                candidates.push_back(modulePath);
            }

            const std::filesystem::path fileName = modulePath.filename();
            if (fileName.empty())
            {
                return candidates;
            }

            std::array<wchar_t, MAX_PATH + 1U> systemDirectory{};
            const UINT copied = ::GetSystemDirectoryW(
                systemDirectory.data(),
                static_cast<UINT>(systemDirectory.size()));
            if (copied != 0U && copied < systemDirectory.size())
            {
                const std::filesystem::path root(systemDirectory.data());
                candidates.push_back(root / fileName);
                candidates.push_back(root / L"drivers" / fileName);
            }

            std::vector<std::filesystem::path> unique;
            for (const auto& candidate : candidates)
            {
                if (std::find(unique.begin(), unique.end(), candidate) == unique.end())
                {
                    unique.push_back(candidate);
                }
            }
            return unique;
        }

        bool findIdentityMatchedImage(
            const ArkDynModuleIdentity& identity,
            std::filesystem::path& pathOut,
            PeIdentity& peIdentityOut,
            std::wstring& diagnosticOut)
        {
            pathOut.clear();
            peIdentityOut = {};
            diagnosticOut.clear();
            bool readableCandidate = false;
            for (const auto& candidate : imageCandidates(identity))
            {
                PeIdentity pe{};
                if (!readPeIdentity(candidate, pe))
                {
                    continue;
                }
                readableCandidate = true;
                if (pe.machine == identity.machine &&
                    pe.timeDateStamp == identity.timeDateStamp &&
                    pe.sizeOfImage == identity.sizeOfImage)
                {
                    pathOut = candidate;
                    peIdentityOut = pe;
                    return true;
                }
            }

            diagnosticOut = readableCandidate
                ? L"local PE candidates did not match the loaded Machine/Timestamp/SizeOfImage"
                : L"no readable local PE candidate was found for the loaded module";
            return false;
        }

        std::filesystem::path defaultSymbolCachePath()
        {
            const std::wstring localAppData =
                environmentValue(L"LOCALAPPDATA");
            if (!localAppData.empty())
            {
                return std::filesystem::path(localAppData) /
                    L"KSword" /
                    L"symbols";
            }
            const std::wstring temporary =
                environmentValue(L"TEMP");
            if (!temporary.empty())
            {
                return std::filesystem::path(temporary) /
                    L"KSword-symbols";
            }
            return {};
        }

        std::wstring symbolSearchPath(
            const std::filesystem::path& exactPdbDirectory)
        {
            std::vector<std::wstring> parts;
            if (!exactPdbDirectory.empty())
            {
                parts.push_back(
                    exactPdbDirectory.wstring());
            }
            const std::wstring configured = environmentValue(L"KSWORD_SYMBOL_PATH");
            if (!configured.empty())
            {
                parts.push_back(configured);
            }
            const std::wstring ntPath = environmentValue(L"_NT_SYMBOL_PATH");
            if (!ntPath.empty() && ntPath != configured)
            {
                parts.push_back(ntPath);
            }

            const std::filesystem::path cachePath =
                defaultSymbolCachePath();
            if (!cachePath.empty())
            {
                std::error_code error;
                std::filesystem::create_directories(cachePath, error);
                parts.push_back(
                    L"srv*" + cachePath.wstring() +
                    L"*https://msdl.microsoft.com/download/symbols");
            }
            else
            {
                parts.push_back(L"srv*https://msdl.microsoft.com/download/symbols");
            }

            std::wstring result;
            for (const std::wstring& part : parts)
            {
                if (part.empty())
                {
                    continue;
                }
                if (!result.empty())
                {
                    result += L";";
                }
                result += part;
            }
            return result;
        }

        std::string guidText(const GUID& guid)
        {
            char buffer[64]{};
            const int written = std::snprintf(
                buffer,
                sizeof(buffer),
                "%08lX-%04hX-%04hX-%02hhX%02hhX-%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX",
                guid.Data1,
                guid.Data2,
                guid.Data3,
                guid.Data4[0],
                guid.Data4[1],
                guid.Data4[2],
                guid.Data4[3],
                guid.Data4[4],
                guid.Data4[5],
                guid.Data4[6],
                guid.Data4[7]);
            return written > 0 ? std::string(buffer, static_cast<std::size_t>(written)) : std::string();
        }

        bool guidPresent(const GUID& guid)
        {
            static constexpr GUID zero{};
            return std::memcmp(&guid, &zero, sizeof(guid)) != 0;
        }

        std::wstring pdbSymbolKey(
            const GUID& guid,
            const std::uint32_t age)
        {
            std::string compactGuid = guidText(guid);
            compactGuid.erase(
                std::remove(
                    compactGuid.begin(),
                    compactGuid.end(),
                    '-'),
                compactGuid.end());
            std::ostringstream key;
            key << compactGuid << std::uppercase << std::hex << age;
            const std::string keyText = key.str();
            return std::wstring(
                keyText.cbegin(),
                keyText.cend());
        }

        bool fileLooksLikePdbCacheEntry(
            const std::filesystem::path& path)
        {
            std::error_code error;
            const std::uintmax_t size =
                std::filesystem::file_size(path, error);
            return !error && size >= 1024U;
        }

        bool downloadHttpsFile(
            const std::wstring& url,
            const std::filesystem::path& destination,
            std::wstring& diagnosticOut)
        {
            diagnosticOut.clear();
            URL_COMPONENTS components{};
            components.dwStructSize = sizeof(components);
            components.dwSchemeLength =
                static_cast<DWORD>(-1);
            components.dwHostNameLength =
                static_cast<DWORD>(-1);
            components.dwUrlPathLength =
                static_cast<DWORD>(-1);
            components.dwExtraInfoLength =
                static_cast<DWORD>(-1);
            if (::WinHttpCrackUrl(
                    url.c_str(),
                    static_cast<DWORD>(url.size()),
                    0U,
                    &components) == FALSE ||
                components.lpszHostName == nullptr ||
                components.dwHostNameLength == 0U ||
                components.nScheme != INTERNET_SCHEME_HTTPS)
            {
                diagnosticOut =
                    L"runtime PDB symbol-server URL is invalid";
                return false;
            }

            const std::wstring host(
                components.lpszHostName,
                components.dwHostNameLength);
            std::wstring resource(
                components.lpszUrlPath,
                components.dwUrlPathLength);
            if (components.lpszExtraInfo != nullptr &&
                components.dwExtraInfoLength != 0U)
            {
                resource.append(
                    components.lpszExtraInfo,
                    components.dwExtraInfoLength);
            }
            if (resource.empty())
            {
                resource = L"/";
            }

            ScopedInternetHandle session(::WinHttpOpen(
                L"KSword Runtime PDB Resolver/1.0",
                WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,
                WINHTTP_NO_PROXY_NAME,
                WINHTTP_NO_PROXY_BYPASS,
                0U));
            if (!session)
            {
                diagnosticOut = lastErrorText(L"WinHttpOpen");
                return false;
            }
            (void)::WinHttpSetTimeouts(
                session.value,
                10000,
                10000,
                15000,
                120000);

            ScopedInternetHandle connection(::WinHttpConnect(
                session.value,
                host.c_str(),
                components.nPort,
                0U));
            if (!connection)
            {
                diagnosticOut =
                    lastErrorText(L"WinHttpConnect");
                return false;
            }
            ScopedInternetHandle request(::WinHttpOpenRequest(
                connection.value,
                L"GET",
                resource.c_str(),
                nullptr,
                WINHTTP_NO_REFERER,
                WINHTTP_DEFAULT_ACCEPT_TYPES,
                WINHTTP_FLAG_SECURE));
            if (!request)
            {
                diagnosticOut =
                    lastErrorText(L"WinHttpOpenRequest");
                return false;
            }
            if (::WinHttpSendRequest(
                    request.value,
                    WINHTTP_NO_ADDITIONAL_HEADERS,
                    0U,
                    WINHTTP_NO_REQUEST_DATA,
                    0U,
                    0U,
                    0U) == FALSE ||
                ::WinHttpReceiveResponse(
                    request.value,
                    nullptr) == FALSE)
            {
                diagnosticOut =
                    lastErrorText(L"WinHTTP request");
                return false;
            }

            DWORD statusCode = 0U;
            DWORD statusBytes = sizeof(statusCode);
            if (::WinHttpQueryHeaders(
                    request.value,
                    WINHTTP_QUERY_STATUS_CODE |
                        WINHTTP_QUERY_FLAG_NUMBER,
                    WINHTTP_HEADER_NAME_BY_INDEX,
                    &statusCode,
                    &statusBytes,
                    WINHTTP_NO_HEADER_INDEX) == FALSE ||
                statusCode != HTTP_STATUS_OK)
            {
                std::wostringstream diagnostic;
                diagnostic
                    << L"runtime PDB download returned HTTP "
                    << statusCode;
                diagnosticOut = diagnostic.str();
                return false;
            }

            constexpr std::uint64_t kMaximumPdbBytes =
                512ULL * 1024ULL * 1024ULL;
            DWORD contentLength = 0U;
            DWORD contentLengthBytes =
                sizeof(contentLength);
            if (::WinHttpQueryHeaders(
                    request.value,
                    WINHTTP_QUERY_CONTENT_LENGTH |
                        WINHTTP_QUERY_FLAG_NUMBER,
                    WINHTTP_HEADER_NAME_BY_INDEX,
                    &contentLength,
                    &contentLengthBytes,
                    WINHTTP_NO_HEADER_INDEX) != FALSE &&
                (contentLength < 1024U ||
                 contentLength >
                    kMaximumPdbBytes))
            {
                diagnosticOut =
                    L"runtime PDB download size is outside the safety bound";
                return false;
            }

            std::error_code directoryError;
            std::filesystem::create_directories(
                destination.parent_path(),
                directoryError);
            if (directoryError)
            {
                diagnosticOut =
                    L"runtime PDB cache directory could not be created";
                return false;
            }

            std::wostringstream temporaryName;
            temporaryName
                << destination.filename().wstring()
                << L".part."
                << ::GetCurrentProcessId()
                << L"."
                << ::GetTickCount64();
            const std::filesystem::path temporary =
                destination.parent_path() /
                temporaryName.str();
            ScopedHandle output(::CreateFileW(
                temporary.c_str(),
                GENERIC_WRITE,
                0U,
                nullptr,
                CREATE_NEW,
                FILE_ATTRIBUTE_TEMPORARY |
                    FILE_FLAG_SEQUENTIAL_SCAN,
                nullptr));
            if (!output)
            {
                diagnosticOut =
                    lastErrorText(L"CreateFileW PDB cache");
                return false;
            }

            bool succeeded = true;
            std::uint64_t totalBytes = 0ULL;
            std::array<std::uint8_t, 64U * 1024U>
                buffer{};
            for (;;)
            {
                DWORD bytesRead = 0U;
                if (::WinHttpReadData(
                        request.value,
                        buffer.data(),
                        static_cast<DWORD>(buffer.size()),
                        &bytesRead) == FALSE)
                {
                    diagnosticOut =
                        lastErrorText(L"WinHttpReadData");
                    succeeded = false;
                    break;
                }
                if (bytesRead == 0U)
                {
                    break;
                }
                if (totalBytes + bytesRead >
                    kMaximumPdbBytes)
                {
                    diagnosticOut =
                        L"runtime PDB download exceeded the safety bound";
                    succeeded = false;
                    break;
                }
                DWORD bytesWritten = 0U;
                if (::WriteFile(
                        output.value,
                        buffer.data(),
                        bytesRead,
                        &bytesWritten,
                        nullptr) == FALSE ||
                    bytesWritten != bytesRead)
                {
                    diagnosticOut =
                        lastErrorText(L"WriteFile PDB cache");
                    succeeded = false;
                    break;
                }
                totalBytes += bytesRead;
            }
            if (succeeded &&
                totalBytes < 1024U)
            {
                diagnosticOut =
                    L"runtime PDB download was unexpectedly small";
                succeeded = false;
            }
            if (succeeded &&
                ::FlushFileBuffers(output.value) == FALSE)
            {
                diagnosticOut =
                    lastErrorText(L"FlushFileBuffers PDB cache");
                succeeded = false;
            }
            output.reset();

            if (succeeded &&
                ::MoveFileExW(
                    temporary.c_str(),
                    destination.c_str(),
                    MOVEFILE_REPLACE_EXISTING |
                        MOVEFILE_WRITE_THROUGH) == FALSE)
            {
                diagnosticOut =
                    lastErrorText(L"MoveFileExW PDB cache");
                succeeded = false;
            }
            if (!succeeded)
            {
                (void)::DeleteFileW(temporary.c_str());
                return false;
            }
            std::wostringstream diagnostic;
            diagnostic
                << L"downloaded exact runtime PDB ("
                << totalBytes
                << L" bytes)";
            diagnosticOut = diagnostic.str();
            return true;
        }

        bool prepareExactPdb(
            const PeIdentity& peIdentity,
            std::filesystem::path& pdbPathOut,
            std::wstring& diagnosticOut)
        {
            pdbPathOut.clear();
            diagnosticOut.clear();
            if (!peIdentity.pdbIdentityAvailable ||
                peIdentity.pdbName.empty() ||
                !guidPresent(peIdentity.pdbGuid) ||
                peIdentity.pdbAge == 0U)
            {
                diagnosticOut =
                    L"local PE does not contain a valid RSDS PDB identity";
                return false;
            }

            const std::filesystem::path cacheRoot =
                defaultSymbolCachePath();
            if (cacheRoot.empty())
            {
                diagnosticOut =
                    L"runtime PDB cache root is unavailable";
                return false;
            }
            const std::wstring symbolKey =
                pdbSymbolKey(
                    peIdentity.pdbGuid,
                    peIdentity.pdbAge);
            const std::filesystem::path destination =
                cacheRoot /
                peIdentity.pdbName /
                symbolKey /
                peIdentity.pdbName;

            std::lock_guard<std::mutex> downloadLock(
                g_pdbDownloadMutex);
            if (fileLooksLikePdbCacheEntry(destination))
            {
                pdbPathOut = destination;
                diagnosticOut =
                    L"exact runtime PDB is present in the local cache";
                return true;
            }

            std::wstring server =
                environmentValue(L"KSWORD_SYMBOL_SERVER");
            if (server.empty())
            {
                server =
                    L"https://msdl.microsoft.com/download/symbols";
            }
            while (!server.empty() &&
                   server.back() == L'/')
            {
                server.pop_back();
            }
            const std::wstring url =
                server +
                L"/" +
                peIdentity.pdbName +
                L"/" +
                symbolKey +
                L"/" +
                peIdentity.pdbName;
            if (!downloadHttpsFile(
                    url,
                    destination,
                    diagnosticOut))
            {
                return false;
            }
            pdbPathOut = destination;
            return true;
        }

        std::string profileName(
            const ArkDynModuleIdentity& identity,
            const std::string& pdbGuid,
            const std::uint32_t pdbAge)
        {
            std::string module = wideToUtf8(std::filesystem::path(identity.moduleName).filename().wstring());
            for (char& character : module)
            {
                if (!std::isalnum(static_cast<unsigned char>(character)))
                {
                    character = '_';
                }
            }
            std::string compactGuid;
            compactGuid.reserve(pdbGuid.size());
            for (const char character : pdbGuid)
            {
                if (character != '-')
                {
                    compactGuid.push_back(
                        static_cast<char>(std::tolower(static_cast<unsigned char>(character))));
                }
            }
            std::ostringstream stream;
            stream << "runtime_pdb_" << module << "_" << compactGuid << "_" << pdbAge;
            return stream.str();
        }

        std::string resultCacheKey(
            const ArkDynModuleIdentity& identity,
            const std::vector<std::string>& extraSymbolNames)
        {
            std::vector<std::string> normalizedSymbols =
                extraSymbolNames;
            std::sort(
                normalizedSymbols.begin(),
                normalizedSymbols.end());
            normalizedSymbols.erase(
                std::unique(
                    normalizedSymbols.begin(),
                    normalizedSymbols.end()),
                normalizedSymbols.end());

            std::ostringstream stream;
            stream << identity.classId << ':'
                   << identity.machine << ':'
                   << identity.timeDateStamp << ':'
                   << identity.sizeOfImage << ':'
                   << identity.imageBase << ':'
                   << wideToUtf8(identity.moduleName);
            for (const std::string& symbol : normalizedSymbols)
            {
                stream << '\x1f' << symbol;
            }
            return stream.str();
        }

        bool initializeDbgHelp(
            const std::filesystem::path& imagePath,
            const ArkDynModuleIdentity& identity,
            const PeIdentity& peIdentity,
            const std::filesystem::path& exactPdbDirectory,
            DbgHelpSession& session,
            IMAGEHLP_MODULEW64& moduleInfoOut,
            std::wstring& diagnosticOut)
        {
            diagnosticOut.clear();
            session.key.reset(::CreateEventW(nullptr, TRUE, FALSE, nullptr));
            if (!session.key)
            {
                diagnosticOut = lastErrorText(L"CreateEventW");
                return false;
            }

            session.previousOptions = ::SymGetOptions();
            session.optionsCaptured = true;
            const DWORD resolverOptions =
                (session.previousOptions |
                SYMOPT_CASE_INSENSITIVE |
                SYMOPT_EXACT_SYMBOLS |
                SYMOPT_FAIL_CRITICAL_ERRORS |
                SYMOPT_UNDNAME) &
                ~SYMOPT_DEFERRED_LOADS;
            ::SymSetOptions(resolverOptions);

            const std::wstring searchPath =
                symbolSearchPath(exactPdbDirectory);
            if (::SymInitializeW(session.key.value, searchPath.c_str(), FALSE) == FALSE)
            {
                diagnosticOut = lastErrorText(L"SymInitializeW");
                return false;
            }
            session.initialized = true;

            session.moduleBase = ::SymLoadModuleExW(
                session.key.value,
                nullptr,
                imagePath.c_str(),
                nullptr,
                identity.imageBase,
                identity.sizeOfImage,
                nullptr,
                0U);
            if (session.moduleBase == 0ULL)
            {
                diagnosticOut = lastErrorText(L"SymLoadModuleExW");
                return false;
            }
            if (session.moduleBase != identity.imageBase)
            {
                diagnosticOut = L"DbgHelp loaded the module at an unexpected base";
                return false;
            }

            moduleInfoOut = {};
            moduleInfoOut.SizeOfStruct = sizeof(moduleInfoOut);
            if (::SymGetModuleInfoW64(
                    session.key.value,
                    session.moduleBase,
                    &moduleInfoOut) == FALSE)
            {
                diagnosticOut = lastErrorText(L"SymGetModuleInfoW64");
                return false;
            }
            if (moduleInfoOut.PdbUnmatched != FALSE ||
                moduleInfoOut.LoadedPdbName[0] == L'\0' ||
                !guidPresent(moduleInfoOut.PdbSig70) ||
                moduleInfoOut.PdbAge == 0U ||
                !peIdentity.pdbIdentityAvailable ||
                std::memcmp(
                    &moduleInfoOut.PdbSig70,
                    &peIdentity.pdbGuid,
                    sizeof(GUID)) != 0 ||
                moduleInfoOut.PdbAge !=
                    peIdentity.pdbAge)
            {
                diagnosticOut = L"DbgHelp did not load an exact GUID/Age-matched PDB";
                return false;
            }
            return true;
        }

        bool findTypeIndex(
            const DbgHelpSession& session,
            const std::string& typeName,
            ULONG& typeIndexOut)
        {
            std::array<std::uint8_t, sizeof(SYMBOL_INFO) + kSymbolNameCapacity> storage{};
            auto* const symbol = reinterpret_cast<SYMBOL_INFO*>(storage.data());
            symbol->SizeOfStruct = sizeof(SYMBOL_INFO);
            symbol->MaxNameLen = static_cast<ULONG>(kSymbolNameCapacity);
            if (::SymGetTypeFromName(
                    session.key.value,
                    session.moduleBase,
                    typeName.c_str(),
                    symbol) == FALSE)
            {
                return false;
            }
            typeIndexOut = symbol->TypeIndex;
            return typeIndexOut != 0U;
        }

        bool variantToUnsigned32(
            const VARIANT& source,
            std::uint32_t& valueOut)
        {
            std::uint64_t value = 0ULL;
            switch (source.vt)
            {
            case VT_UI1:
                value = source.bVal;
                break;
            case VT_I1:
                if (source.cVal < 0) return false;
                value = static_cast<std::uint8_t>(source.cVal);
                break;
            case VT_UI2:
                value = source.uiVal;
                break;
            case VT_I2:
                if (source.iVal < 0) return false;
                value = static_cast<std::uint16_t>(source.iVal);
                break;
            case VT_UI4:
                value = source.ulVal;
                break;
            case VT_UINT:
                value = source.uintVal;
                break;
            case VT_I4:
                if (source.lVal < 0) return false;
                value = static_cast<std::uint32_t>(source.lVal);
                break;
            case VT_INT:
                if (source.intVal < 0) return false;
                value = static_cast<std::uint32_t>(source.intVal);
                break;
            case VT_UI8:
                value = source.ullVal;
                break;
            case VT_I8:
                if (source.llVal < 0) return false;
                value = static_cast<std::uint64_t>(source.llVal);
                break;
            default:
                return false;
            }
            if (value > std::numeric_limits<std::uint32_t>::max())
            {
                return false;
            }
            valueOut = static_cast<std::uint32_t>(value);
            return true;
        }

        bool resolveEnumValue(
            const DbgHelpSession& session,
            const std::string& enumName,
            const std::string& enumeratorName,
            std::uint32_t& valueOut,
            std::uint32_t& storageBytesOut)
        {
            valueOut = 0U;
            storageBytesOut = 0U;
            ULONG typeIndex = 0U;
            if (!findTypeIndex(session, enumName, typeIndex))
            {
                return false;
            }

            ULONG64 typeLength = 0ULL;
            if (::SymGetTypeInfo(
                    session.key.value,
                    session.moduleBase,
                    typeIndex,
                    TI_GET_LENGTH,
                    &typeLength) == FALSE ||
                typeLength == 0ULL ||
                typeLength > sizeof(std::uint32_t))
            {
                return false;
            }

            ULONG childCount = 0U;
            if (::SymGetTypeInfo(
                    session.key.value,
                    session.moduleBase,
                    typeIndex,
                    TI_GET_CHILDRENCOUNT,
                    &childCount) == FALSE ||
                childCount == 0U)
            {
                return false;
            }
            const std::size_t bufferBytes =
                sizeof(TI_FINDCHILDREN_PARAMS) +
                (static_cast<std::size_t>(childCount) - 1U) *
                    sizeof(ULONG);
            std::vector<std::uint8_t> childStorage(
                bufferBytes,
                0U);
            auto* const children =
                reinterpret_cast<TI_FINDCHILDREN_PARAMS*>(
                    childStorage.data());
            children->Count = childCount;
            children->Start = 0U;
            if (::SymGetTypeInfo(
                    session.key.value,
                    session.moduleBase,
                    typeIndex,
                    TI_FINDCHILDREN,
                    children) == FALSE)
            {
                return false;
            }

            for (ULONG index = 0U; index < childCount; ++index)
            {
                const ULONG childId = children->ChildId[index];
                wchar_t* allocatedName = nullptr;
                if (::SymGetTypeInfo(
                        session.key.value,
                        session.moduleBase,
                        childId,
                        TI_GET_SYMNAME,
                        &allocatedName) == FALSE ||
                    allocatedName == nullptr)
                {
                    continue;
                }
                const std::unique_ptr<wchar_t, decltype(&::LocalFree)> name(
                    allocatedName,
                    &::LocalFree);
                if (wideToUtf8(std::wstring(name.get())) != enumeratorName)
                {
                    continue;
                }

                VARIANT enumValue{};
                if (::SymGetTypeInfo(
                        session.key.value,
                        session.moduleBase,
                        childId,
                        TI_GET_VALUE,
                        &enumValue) == FALSE ||
                    !variantToUnsigned32(enumValue, valueOut))
                {
                    return false;
                }
                storageBytesOut =
                    static_cast<std::uint32_t>(typeLength);
                return true;
            }
            return false;
        }

        bool loadTypeLayout(
            const DbgHelpSession& session,
            const std::string& typeName,
            TypeLayout& layoutOut)
        {
            layoutOut = {};
            ULONG typeIndex = 0U;
            if (!findTypeIndex(session, typeName, typeIndex))
            {
                return false;
            }

            ULONG64 typeLength = 0ULL;
            if (::SymGetTypeInfo(
                    session.key.value,
                    session.moduleBase,
                    typeIndex,
                    TI_GET_LENGTH,
                    &typeLength) != FALSE)
            {
                layoutOut.size = typeLength;
            }

            ULONG childCount = 0U;
            if (::SymGetTypeInfo(
                    session.key.value,
                    session.moduleBase,
                    typeIndex,
                    TI_GET_CHILDRENCOUNT,
                    &childCount) == FALSE)
            {
                return false;
            }
            if (childCount == 0U)
            {
                layoutOut.loaded = true;
                return true;
            }

            const std::size_t bufferBytes =
                sizeof(TI_FINDCHILDREN_PARAMS) +
                (static_cast<std::size_t>(childCount) - 1U) * sizeof(ULONG);
            std::vector<std::uint8_t> childStorage(bufferBytes, 0U);
            auto* const children = reinterpret_cast<TI_FINDCHILDREN_PARAMS*>(childStorage.data());
            children->Count = childCount;
            children->Start = 0U;
            if (::SymGetTypeInfo(
                    session.key.value,
                    session.moduleBase,
                    typeIndex,
                    TI_FINDCHILDREN,
                    children) == FALSE)
            {
                return false;
            }

            for (ULONG index = 0U; index < childCount; ++index)
            {
                const ULONG childId = children->ChildId[index];
                wchar_t* allocatedName = nullptr;
                if (::SymGetTypeInfo(
                        session.key.value,
                        session.moduleBase,
                        childId,
                        TI_GET_SYMNAME,
                        &allocatedName) == FALSE ||
                    allocatedName == nullptr)
                {
                    continue;
                }
                const std::unique_ptr<wchar_t, decltype(&::LocalFree)> memberName(
                    allocatedName,
                    &::LocalFree);

                DWORD offset = 0U;
                if (::SymGetTypeInfo(
                        session.key.value,
                        session.moduleBase,
                        childId,
                        TI_GET_OFFSET,
                        &offset) == FALSE)
                {
                    continue;
                }

                MemberLayout member{};
                member.offset = offset;
                DWORD bitPosition = 0U;
                if (::SymGetTypeInfo(
                        session.key.value,
                        session.moduleBase,
                        childId,
                        TI_GET_BITPOSITION,
                        &bitPosition) != FALSE)
                {
                    member.hasBitPosition = true;
                    member.bitPosition = bitPosition;
                }

                ULONG memberTypeId = 0U;
                if (::SymGetTypeInfo(
                        session.key.value,
                        session.moduleBase,
                        childId,
                        TI_GET_TYPEID,
                        &memberTypeId) != FALSE)
                {
                    ULONG64 memberLength = 0ULL;
                    if (::SymGetTypeInfo(
                            session.key.value,
                            session.moduleBase,
                            memberTypeId,
                            TI_GET_LENGTH,
                            &memberLength) != FALSE &&
                        memberLength <= std::numeric_limits<std::uint32_t>::max())
                    {
                        member.storageBytes = static_cast<std::uint32_t>(memberLength);
                    }
                }

                const std::wstring wideName(memberName.get());
                const std::string utf8Name = wideToUtf8(wideName);
                if (!utf8Name.empty())
                {
                    layoutOut.members.emplace(utf8Name, member);
                }
            }

            layoutOut.loaded = true;
            return true;
        }

        class TypeResolver
        {
        public:
            explicit TypeResolver(const DbgHelpSession& session) : m_session(session) {}

            bool member(
                const std::string& typeName,
                const std::string& memberName,
                MemberLayout& memberOut)
            {
                TypeLayout& layout = layoutFor(typeName);
                if (!layout.loaded)
                {
                    return false;
                }
                const auto iterator = layout.members.find(memberName);
                if (iterator == layout.members.end())
                {
                    return false;
                }
                memberOut = iterator->second;
                return true;
            }

            bool typeSize(const std::string& typeName, std::uint32_t& sizeOut)
            {
                TypeLayout& layout = layoutFor(typeName);
                if (!layout.loaded || layout.size == 0ULL ||
                    layout.size > std::numeric_limits<std::uint32_t>::max())
                {
                    return false;
                }
                sizeOut = static_cast<std::uint32_t>(layout.size);
                return true;
            }

        private:
            TypeLayout& layoutFor(const std::string& typeName)
            {
                const auto existing = m_layouts.find(typeName);
                if (existing != m_layouts.end())
                {
                    return existing->second;
                }
                TypeLayout layout{};
                loadTypeLayout(m_session, typeName, layout);
                return m_layouts.emplace(typeName, std::move(layout)).first->second;
            }

            const DbgHelpSession& m_session;
            std::unordered_map<std::string, TypeLayout> m_layouts;
        };

        std::vector<std::string_view> splitAliases(const char* aliases)
        {
            std::vector<std::string_view> result;
            const std::string_view text = aliases != nullptr ? std::string_view(aliases) : std::string_view();
            std::size_t start = 0U;
            while (start <= text.size())
            {
                const std::size_t separator = text.find('|', start);
                const std::size_t end = separator == std::string_view::npos ? text.size() : separator;
                if (end > start)
                {
                    result.push_back(text.substr(start, end - start));
                }
                if (separator == std::string_view::npos)
                {
                    break;
                }
                start = separator + 1U;
            }
            return result;
        }

        bool resolveSymbolRva(
            const DbgHelpSession& session,
            const std::string& symbolName,
            const std::uint32_t imageSize,
            std::uint32_t& rvaOut)
        {
            rvaOut = 0U;
            std::array<std::uint8_t, sizeof(SYMBOL_INFO) + kSymbolNameCapacity> storage{};
            auto* const symbol = reinterpret_cast<SYMBOL_INFO*>(storage.data());
            symbol->SizeOfStruct = sizeof(SYMBOL_INFO);
            symbol->MaxNameLen = static_cast<ULONG>(kSymbolNameCapacity);
            if (::SymFromName(session.key.value, symbolName.c_str(), symbol) == FALSE)
            {
                return false;
            }
            if (symbol->Address <= session.moduleBase)
            {
                return false;
            }
            const DWORD64 rva = symbol->Address - session.moduleBase;
            if (rva >= imageSize || rva > kMaximumGlobalRva)
            {
                return false;
            }
            rvaOut = static_cast<std::uint32_t>(rva);
            return true;
        }

        bool resolveAliasedSymbolRva(
            const DbgHelpSession& session,
            const char* aliases,
            const std::uint32_t imageSize,
            std::uint32_t& rvaOut)
        {
            for (const std::string_view alias : splitAliases(aliases))
            {
                if (resolveSymbolRva(
                        session,
                        std::string(alias),
                        imageSize,
                        rvaOut))
                {
                    return true;
                }
            }
            return false;
        }

        void appendLegacyField(
            RuntimeDynDataResolveResult& result,
            const std::uint32_t fieldId,
            const std::uint32_t offset)
        {
            DynDataProfileField field{};
            field.fieldId = fieldId;
            field.offset = offset;
            result.profile.fields.push_back(field);
        }

        void appendExItem(
            RuntimeDynDataResolveResult& result,
            const std::uint32_t fieldId,
            const std::uint32_t itemKind,
            const std::uint32_t value,
            const bool callback)
        {
            DynDataProfileExItem item{};
            item.itemId = fieldId;
            item.itemKind = itemKind;
            item.value = value;
            item.flags = callback
                ? KSW_DYN_PROFILE_EX_ITEM_FLAG_REQUIRED |
                    KSW_DYN_PROFILE_EX_ITEM_FLAG_CALLBACK
                : 0U;
            result.profileEx.items.push_back(item);
        }

        void appendV4Item(
            RuntimeDynDataResolveResult& result,
            const std::uint32_t itemId,
            const std::uint32_t itemKind,
            const std::uint32_t flags,
            const std::uint32_t groupId,
            const std::uint32_t value,
            const std::uint32_t aux0 = 0U,
            const std::uint32_t aux1 = 0U,
            const std::uint32_t aux2 = 0U,
            const std::uint32_t aux3 = 0U)
        {
            KSW_DYN_V4_ITEM_PACKET item{};
            item.itemId = itemId;
            item.itemKind = itemKind;
            item.flags = flags;
            item.capabilityGroupId = groupId;
            item.valueLow = value;
            item.valueHigh = 0U;
            item.aux0 = aux0;
            item.aux1 = aux1;
            item.aux2 = aux2;
            item.aux3 = aux3;
            result.profileV4.items.push_back(item);
        }

        void resolveCanonicalCatalog(
            const DbgHelpSession& session,
            TypeResolver& types,
            const ArkDynModuleIdentity& identity,
            RuntimeDynDataResolveResult& result,
            std::vector<std::wstring>& diagnostics)
        {
            std::uint32_t missingMembers = 0U;
            std::uint32_t missingTypes = 0U;
            std::uint32_t missingGlobals = 0U;
            for (const CatalogEntry& entry : kCatalog)
            {
                if (entry.kind == CatalogKind::StructOffset)
                {
                    MemberLayout member{};
                    if (!types.member(entry.typeName, entry.memberOrSymbols, member) ||
                        member.offset > kMaximumProfileOffset)
                    {
                        ++missingMembers;
                        continue;
                    }
                    if (!entry.callback)
                    {
                        appendLegacyField(result, entry.fieldId, member.offset);
                        ++result.resolvedFieldCount;
                    }
                    appendExItem(
                        result,
                        entry.fieldId,
                        KSW_DYN_PROFILE_EX_ITEM_KIND_STRUCT_OFFSET,
                        member.offset,
                        entry.callback);
                    appendV4Item(
                        result,
                        entry.fieldId,
                        KSW_DYN_V4_ITEM_KIND_STRUCT_OFFSET,
                        KSW_DYN_V4_ITEM_FLAG_REQUIRED,
                        KSW_DYN_V4_CAPABILITY_GROUP_NTOS_CORE,
                        member.offset);
                }
                else if (entry.kind == CatalogKind::TypeSize)
                {
                    std::uint32_t typeSize = 0U;
                    if (!types.typeSize(entry.typeName, typeSize) ||
                        typeSize == 0U ||
                        typeSize > kMaximumProfileOffset)
                    {
                        ++missingTypes;
                        continue;
                    }
                    appendExItem(
                        result,
                        entry.fieldId,
                        KSW_DYN_PROFILE_EX_ITEM_KIND_STRUCT_OFFSET,
                        typeSize,
                        false);
                    appendV4Item(
                        result,
                        entry.fieldId,
                        KSW_DYN_V4_ITEM_KIND_TYPE_SIZE,
                        KSW_DYN_V4_ITEM_FLAG_REQUIRED,
                        KSW_DYN_V4_CAPABILITY_GROUP_NTOS_CORE,
                        typeSize);
                }
                else
                {
                    std::uint32_t rva = 0U;
                    if (!resolveAliasedSymbolRva(
                            session,
                            entry.memberOrSymbols,
                            identity.sizeOfImage,
                            rva))
                    {
                        ++missingGlobals;
                        continue;
                    }
                    appendExItem(
                        result,
                        entry.fieldId,
                        KSW_DYN_PROFILE_EX_ITEM_KIND_GLOBAL_RVA,
                        rva,
                        entry.callback);
                    appendV4Item(
                        result,
                        entry.fieldId,
                        KSW_DYN_V4_ITEM_KIND_GLOBAL_RVA,
                        KSW_DYN_V4_ITEM_FLAG_REQUIRED,
                        KSW_DYN_V4_CAPABILITY_GROUP_NTOS_CORE,
                        rva);
                }
            }
            result.resolvedTypedItemCount =
                static_cast<std::uint32_t>(result.profileEx.items.size());

            std::wostringstream coverage;
            coverage << L"runtime catalog resolved fields=" << result.resolvedFieldCount
                     << L", typedItems=" << result.resolvedTypedItemCount
                     << L", missingMembers=" << missingMembers
                     << L", missingTypes=" << missingTypes
                     << L", missingGlobals=" << missingGlobals;
            diagnostics.push_back(coverage.str());
        }

        bool resolveMemberAliases(
            TypeResolver& types,
            const std::initializer_list<std::pair<const char*, const char*>>& candidates,
            MemberLayout& memberOut)
        {
            for (const auto& candidate : candidates)
            {
                if (types.member(candidate.first, candidate.second, memberOut))
                {
                    return true;
                }
            }
            return false;
        }

        bool resolveTypeAliases(
            TypeResolver& types,
            const std::initializer_list<const char*>& candidates,
            std::uint32_t& sizeOut)
        {
            for (const char* candidate : candidates)
            {
                if (types.typeSize(candidate, sizeOut))
                {
                    return true;
                }
            }
            return false;
        }

        void resolveNtosV4Items(
            TypeResolver& types,
            RuntimeDynDataResolveResult& result)
        {
            MemberLayout member{};
            if (types.member("_ETHREAD", "ActiveExWorker", member) &&
                member.offset <= kMaximumProfileOffset &&
                member.hasBitPosition)
            {
                appendV4Item(
                    result,
                    KSW_DYN_V4_ITEM_ID_ETH_ACTIVE_EX_WORKER,
                    KSW_DYN_V4_ITEM_KIND_BIT_FIELD,
                    KSW_DYN_V4_ITEM_FLAG_REQUIRED,
                    KSW_DYN_V4_CAPABILITY_GROUP_TIMER_DPC,
                    member.offset,
                    member.bitPosition,
                    1U,
                    member.storageBytes);
            }

            const struct
            {
                std::uint32_t itemId;
                const char* typeName;
                const char* memberName;
            } memberItems[] = {
                {KSW_DYN_V4_ITEM_ID_KPRCB_TIMER_TABLE, "_KPRCB", "TimerTable"},
                {KSW_DYN_V4_ITEM_ID_KTIMER_TABLE_TIMER_ENTRIES, "_KTIMER_TABLE", "TimerEntries"},
                {KSW_DYN_V4_ITEM_ID_KTIMER_TABLE_ENTRY_LOCK, "_KTIMER_TABLE_ENTRY", "Lock"},
                {KSW_DYN_V4_ITEM_ID_KTIMER_TABLE_ENTRY_ENTRY, "_KTIMER_TABLE_ENTRY", "Entry"},
                {KSW_DYN_V4_ITEM_ID_KTIMER_TABLE_ENTRY_TIME, "_KTIMER_TABLE_ENTRY", "Time"},
                {KSW_DYN_V4_ITEM_ID_KTIMER_TIMER_LIST_ENTRY, "_KTIMER", "TimerListEntry"},
                {KSW_DYN_V4_ITEM_ID_KTIMER_DUE_TIME, "_KTIMER", "DueTime"},
                {KSW_DYN_V4_ITEM_ID_KTIMER_DPC, "_KTIMER", "Dpc"},
                {KSW_DYN_V4_ITEM_ID_KTIMER_PERIOD, "_KTIMER", "Period"},
                {KSW_DYN_V4_ITEM_ID_KDPC_DEFERRED_ROUTINE, "_KDPC", "DeferredRoutine"},
                {KSW_DYN_V4_ITEM_ID_KDPC_DEFERRED_CONTEXT, "_KDPC", "DeferredContext"},
            };
            for (const auto& item : memberItems)
            {
                if (types.member(item.typeName, item.memberName, member) &&
                    member.offset <= kMaximumProfileOffset)
                {
                    appendV4Item(
                        result,
                        item.itemId,
                        KSW_DYN_V4_ITEM_KIND_STRUCT_OFFSET,
                        KSW_DYN_V4_ITEM_FLAG_REQUIRED,
                        KSW_DYN_V4_CAPABILITY_GROUP_TIMER_DPC,
                        member.offset);
                }
            }

            if (types.member("_KTIMER", "TimerType", member) &&
                member.offset <= kMaximumProfileOffset)
            {
                appendV4Item(
                    result,
                    KSW_DYN_V4_ITEM_ID_KTIMER_TIMER_TYPE,
                    KSW_DYN_V4_ITEM_KIND_STRUCT_OFFSET,
                    KSW_DYN_V4_ITEM_FLAG_REQUIRED,
                    KSW_DYN_V4_CAPABILITY_GROUP_TIMER_DPC,
                    member.offset);
            }
            else
            {
                MemberLayout header{};
                MemberLayout type{};
                if (types.member("_KTIMER", "Header", header) &&
                    types.member("_DISPATCHER_HEADER", "Type", type) &&
                    header.offset <= kMaximumProfileOffset - type.offset)
                {
                    appendV4Item(
                        result,
                        KSW_DYN_V4_ITEM_ID_KTIMER_TIMER_TYPE,
                        KSW_DYN_V4_ITEM_KIND_STRUCT_OFFSET,
                        KSW_DYN_V4_ITEM_FLAG_REQUIRED,
                        KSW_DYN_V4_CAPABILITY_GROUP_TIMER_DPC,
                        header.offset + type.offset);
                }
            }

            const struct
            {
                std::uint32_t itemId;
                const char* typeName;
            } sizeItems[] = {
                {KSW_DYN_V4_ITEM_ID_KTIMER_TABLE_TYPE_SIZE, "_KTIMER_TABLE"},
                {KSW_DYN_V4_ITEM_ID_KTIMER_TABLE_ENTRY_TYPE_SIZE, "_KTIMER_TABLE_ENTRY"},
                {KSW_DYN_V4_ITEM_ID_KTIMER_TYPE_SIZE, "_KTIMER"},
                {KSW_DYN_V4_ITEM_ID_KDPC_TYPE_SIZE, "_KDPC"},
            };
            for (const auto& item : sizeItems)
            {
                std::uint32_t typeSize = 0U;
                if (types.typeSize(item.typeName, typeSize) &&
                    typeSize != 0U &&
                    typeSize <= kMaximumProfileOffset)
                {
                    appendV4Item(
                        result,
                        item.itemId,
                        KSW_DYN_V4_ITEM_KIND_TYPE_SIZE,
                        KSW_DYN_V4_ITEM_FLAG_REQUIRED,
                        KSW_DYN_V4_CAPABILITY_GROUP_TIMER_DPC,
                        typeSize);
                }
            }
        }

        void resolveNtosWorkQueueV4Items(
            const DbgHelpSession& session,
            TypeResolver& types,
            const ArkDynModuleIdentity& identity,
            RuntimeDynDataResolveResult& result)
        {
            const struct
            {
                std::uint32_t itemId;
                const char* symbolName;
            } globalItems[] = {
                {KSW_DYN_V4_ITEM_ID_WQ_PSP_SYSTEM_PARTITION, "PspSystemPartition"},
                {KSW_DYN_V4_ITEM_ID_WQ_EXP_BUILTIN_PRIORITIES, "ExpBuiltinPriorities"},
            };
            for (const auto& item : globalItems)
            {
                std::uint32_t rva = 0U;
                if (resolveSymbolRva(
                        session,
                        item.symbolName,
                        identity.sizeOfImage,
                        rva))
                {
                    appendV4Item(
                        result,
                        item.itemId,
                        KSW_DYN_V4_ITEM_KIND_GLOBAL_RVA,
                        KSW_DYN_V4_ITEM_FLAG_REQUIRED,
                        KSW_DYN_V4_CAPABILITY_GROUP_WORK_QUEUE,
                        rva);
                }
            }

            const struct
            {
                std::uint32_t itemId;
                const char* typeName;
                const char* memberName;
            } memberItems[] = {
                {KSW_DYN_V4_ITEM_ID_WQ_EPARTITION_EX_PARTITION, "_EPARTITION", "ExPartition"},
                {KSW_DYN_V4_ITEM_ID_WQ_EX_PARTITION_WORK_QUEUES, "_EX_PARTITION", "WorkQueues"},
                {KSW_DYN_V4_ITEM_ID_WQ_EX_WORK_QUEUE_WORK_PRI_QUEUE, "_EX_WORK_QUEUE", "WorkPriQueue"},
                {KSW_DYN_V4_ITEM_ID_WQ_EX_WORK_QUEUE_QUEUE_INDEX, "_EX_WORK_QUEUE", "QueueIndex"},
                {KSW_DYN_V4_ITEM_ID_WQ_KPRI_QUEUE_ENTRY_LIST_HEAD, "_KPRIQUEUE", "EntryListHead"},
                {KSW_DYN_V4_ITEM_ID_WQ_KPRI_QUEUE_THREAD_LIST_HEAD, "_KPRIQUEUE", "ThreadListHead"},
                {KSW_DYN_V4_ITEM_ID_WQ_KTHREAD_QUEUE, "_KTHREAD", "Queue"},
                {KSW_DYN_V4_ITEM_ID_WQ_KTHREAD_QUEUE_LIST_ENTRY, "_KTHREAD", "QueueListEntry"},
                {KSW_DYN_V4_ITEM_ID_WQ_WORK_ITEM_LIST, "_WORK_QUEUE_ITEM", "List"},
                {KSW_DYN_V4_ITEM_ID_WQ_WORK_ITEM_ROUTINE, "_WORK_QUEUE_ITEM", "WorkerRoutine"},
                {KSW_DYN_V4_ITEM_ID_WQ_WORK_ITEM_PARAMETER, "_WORK_QUEUE_ITEM", "Parameter"},
                {KSW_DYN_V4_ITEM_ID_WQ_ETHREAD_START_ADDRESS, "_ETHREAD", "StartAddress"},
                {KSW_DYN_V4_ITEM_ID_WQ_ETHREAD_TCB, "_ETHREAD", "Tcb"},
            };
            MemberLayout member{};
            for (const auto& item : memberItems)
            {
                if (types.member(
                        item.typeName,
                        item.memberName,
                        member) &&
                    member.offset <= kMaximumProfileOffset)
                {
                    appendV4Item(
                        result,
                        item.itemId,
                        KSW_DYN_V4_ITEM_KIND_STRUCT_OFFSET,
                        KSW_DYN_V4_ITEM_FLAG_REQUIRED,
                        KSW_DYN_V4_CAPABILITY_GROUP_WORK_QUEUE,
                        member.offset);
                }
            }

            const struct
            {
                std::uint32_t itemId;
                const char* typeName;
            } sizeItems[] = {
                {KSW_DYN_V4_ITEM_ID_WQ_EPARTITION_TYPE_SIZE, "_EPARTITION"},
                {KSW_DYN_V4_ITEM_ID_WQ_EX_PARTITION_TYPE_SIZE, "_EX_PARTITION"},
                {KSW_DYN_V4_ITEM_ID_WQ_EX_WORK_QUEUE_TYPE_SIZE, "_EX_WORK_QUEUE"},
                {KSW_DYN_V4_ITEM_ID_WQ_KPRI_QUEUE_TYPE_SIZE, "_KPRIQUEUE"},
                {KSW_DYN_V4_ITEM_ID_WQ_KTHREAD_TYPE_SIZE, "_KTHREAD"},
                {KSW_DYN_V4_ITEM_ID_WQ_WORK_ITEM_TYPE_SIZE, "_WORK_QUEUE_ITEM"},
                {KSW_DYN_V4_ITEM_ID_WQ_ETHREAD_TYPE_SIZE, "_ETHREAD"},
            };
            for (const auto& item : sizeItems)
            {
                std::uint32_t typeSize = 0U;
                if (types.typeSize(item.typeName, typeSize) &&
                    typeSize != 0U &&
                    typeSize <= kMaximumProfileOffset)
                {
                    appendV4Item(
                        result,
                        item.itemId,
                        KSW_DYN_V4_ITEM_KIND_TYPE_SIZE,
                        KSW_DYN_V4_ITEM_FLAG_REQUIRED,
                        KSW_DYN_V4_CAPABILITY_GROUP_WORK_QUEUE,
                        typeSize);
                }
            }

            std::uint32_t enumValue = 0U;
            std::uint32_t enumStorageBytes = 0U;
            if (resolveEnumValue(
                    session,
                    "_EXQUEUEINDEX",
                    "ExPoolUntrusted",
                    enumValue,
                    enumStorageBytes))
            {
                appendV4Item(
                    result,
                    KSW_DYN_V4_ITEM_ID_WQ_EX_POOL_UNTRUSTED,
                    KSW_DYN_V4_ITEM_KIND_ENUM_VALUE,
                    KSW_DYN_V4_ITEM_FLAG_REQUIRED,
                    KSW_DYN_V4_CAPABILITY_GROUP_WORK_QUEUE,
                    enumValue,
                    enumStorageBytes);
            }
        }

        void resolveFltmgrV4Items(
            TypeResolver& types,
            RuntimeDynDataResolveResult& result)
        {
            MemberLayout member{};
            if (types.member("_FLT_FILTER", "Operations", member) &&
                member.offset <= kMaximumProfileOffset)
            {
                appendV4Item(
                    result,
                    KSW_DYN_V4_ITEM_ID_FLT_FILTER_OPERATIONS,
                    KSW_DYN_V4_ITEM_KIND_STRUCT_OFFSET,
                    KSW_DYN_V4_ITEM_FLAG_REQUIRED,
                    KSW_DYN_V4_CAPABILITY_GROUP_FLTMGR_MINIFILTER,
                    member.offset);
            }
        }

        void resolveCiV4Items(
            const DbgHelpSession& session,
            TypeResolver& types,
            const ArkDynModuleIdentity& identity,
            RuntimeDynDataResolveResult& result)
        {
            std::uint32_t rva = 0U;
            if (resolveSymbolRva(
                    session,
                    "g_KernelHashBucketList",
                    identity.sizeOfImage,
                    rva))
            {
                appendV4Item(
                    result,
                    KSW_DYN_V4_ITEM_ID_CI_KERNEL_HASH_BUCKET_LIST,
                    KSW_DYN_V4_ITEM_KIND_GLOBAL_RVA,
                    KSW_DYN_V4_ITEM_FLAG_REQUIRED,
                    KSW_DYN_V4_CAPABILITY_GROUP_CI_KERNEL_HASH,
                    rva);
            }
            if (resolveSymbolRva(
                    session,
                    "g_HashCacheLock",
                    identity.sizeOfImage,
                    rva))
            {
                appendV4Item(
                    result,
                    KSW_DYN_V4_ITEM_ID_CI_HASH_CACHE_LOCK,
                    KSW_DYN_V4_ITEM_KIND_GLOBAL_RVA,
                    KSW_DYN_V4_ITEM_FLAG_REQUIRED,
                    KSW_DYN_V4_CAPABILITY_GROUP_CI_KERNEL_HASH,
                    rva);
            }

            const struct
            {
                std::uint32_t itemId;
                const char* memberName;
                bool optional;
            } memberItems[] = {
                {KSW_DYN_V4_ITEM_ID_CI_HASH_ENTRY_NEXT, "Next", false},
                {KSW_DYN_V4_ITEM_ID_CI_HASH_ENTRY_DRIVER_NAME, "DriverName", false},
                {KSW_DYN_V4_ITEM_ID_CI_HASH_ENTRY_TIME_DATE_STAMP, "TimeDateStamp", true},
                {KSW_DYN_V4_ITEM_ID_CI_HASH_ENTRY_LOAD_STATUS, "LoadStatus", true},
                {KSW_DYN_V4_ITEM_ID_CI_HASH_ENTRY_IMAGE_BASE, "ImageBase", true},
                {KSW_DYN_V4_ITEM_ID_CI_HASH_ENTRY_IMAGE_SIZE, "ImageSize", true},
            };
            for (const auto& item : memberItems)
            {
                MemberLayout member{};
                if (resolveMemberAliases(
                        types,
                        {
                            {"_MINCRYPT_HASH_BUCKET_ENTRY", item.memberName},
                            {"_HASH_BUCKET_ENTRY", item.memberName},
                            {"HashBucketEntry", item.memberName},
                            {"_CI_HASH_CACHE_ENTRY", item.memberName},
                        },
                        member) &&
                    member.offset <= kMaximumProfileOffset)
                {
                    appendV4Item(
                        result,
                        item.itemId,
                        KSW_DYN_V4_ITEM_KIND_STRUCT_OFFSET,
                        item.optional
                            ? KSW_DYN_V4_ITEM_FLAG_OPTIONAL
                            : KSW_DYN_V4_ITEM_FLAG_REQUIRED,
                        KSW_DYN_V4_CAPABILITY_GROUP_CI_KERNEL_HASH,
                        member.offset);
                }
            }

            std::uint32_t typeSize = 0U;
            if (resolveTypeAliases(
                    types,
                    {
                        "_MINCRYPT_HASH_BUCKET_ENTRY",
                        "_HASH_BUCKET_ENTRY",
                        "HashBucketEntry",
                        "_CI_HASH_CACHE_ENTRY",
                    },
                    typeSize) &&
                typeSize != 0U &&
                typeSize <= kMaximumProfileOffset)
            {
                appendV4Item(
                    result,
                    KSW_DYN_V4_ITEM_ID_CI_HASH_ENTRY_TYPE_SIZE,
                    KSW_DYN_V4_ITEM_KIND_TYPE_SIZE,
                    KSW_DYN_V4_ITEM_FLAG_REQUIRED,
                    KSW_DYN_V4_CAPABILITY_GROUP_CI_KERNEL_HASH,
                    typeSize);
            }
        }

        void resolveModuleV4Items(
            const DbgHelpSession& session,
            TypeResolver& types,
            const ArkDynModuleIdentity& identity,
            RuntimeDynDataResolveResult& result)
        {
            switch (identity.classId)
            {
            case KSW_DYN_PROFILE_CLASS_NTOSKRNL:
            case KSW_DYN_PROFILE_CLASS_NTKRLA57:
                resolveNtosV4Items(types, result);
                resolveNtosWorkQueueV4Items(
                    session,
                    types,
                    identity,
                    result);
                break;
            case KSW_DYN_PROFILE_CLASS_FLTMGR:
                resolveFltmgrV4Items(types, result);
                break;
            case KSW_DYN_PROFILE_CLASS_CI:
                resolveCiV4Items(session, types, identity, result);
                break;
            default:
                break;
            }
        }

        const char* groupName(const std::uint32_t groupId)
        {
            switch (groupId)
            {
            case KSW_DYN_V4_CAPABILITY_GROUP_NTOS_CORE:
                return "ntos.core";
            case KSW_DYN_V4_CAPABILITY_GROUP_TIMER_DPC:
                return "timer.dpc";
            case KSW_DYN_V4_CAPABILITY_GROUP_FLTMGR_MINIFILTER:
                return "fltmgr.minifilter";
            case KSW_DYN_V4_CAPABILITY_GROUP_CI_KERNEL_HASH:
                return "ci.kernel_hash";
            case KSW_DYN_V4_CAPABILITY_GROUP_WORK_QUEUE:
                return "ntos.work_queue";
            default:
                return "runtime.unknown";
            }
        }

        void buildV4Groups(RuntimeDynDataResolveResult& result)
        {
            std::array<bool, KSW_DYN_V4_MAX_CAPABILITY_GROUPS_PER_MODULE + 1U> seen{};
            for (const KSW_DYN_V4_ITEM_PACKET& item : result.profileV4.items)
            {
                if (item.capabilityGroupId < seen.size())
                {
                    seen[item.capabilityGroupId] = true;
                }
            }
            for (std::uint32_t groupId = 1U; groupId < seen.size(); ++groupId)
            {
                if (!seen[groupId])
                {
                    continue;
                }
                KSW_DYN_V4_CAPABILITY_GROUP_PACKET group{};
                group.groupId = groupId;
                group.flags = 0U;
                copyAnsi(group.groupName, groupName(groupId));
                for (const KSW_DYN_V4_ITEM_PACKET& item : result.profileV4.items)
                {
                    if (item.capabilityGroupId != groupId)
                    {
                        continue;
                    }
                    if ((item.flags & KSW_DYN_V4_ITEM_FLAG_REQUIRED) != 0U)
                    {
                        ++group.requiredItemCount;
                    }
                    else if ((item.flags & KSW_DYN_V4_ITEM_FLAG_OPTIONAL) != 0U)
                    {
                        ++group.optionalItemCount;
                    }
                }
                switch (groupId)
                {
                case KSW_DYN_V4_CAPABILITY_GROUP_TIMER_DPC:
                    group.requiredItemCount = 17U;
                    group.optionalItemCount = 0U;
                    break;
                case KSW_DYN_V4_CAPABILITY_GROUP_FLTMGR_MINIFILTER:
                    group.requiredItemCount = 1U;
                    group.optionalItemCount = 0U;
                    break;
                case KSW_DYN_V4_CAPABILITY_GROUP_CI_KERNEL_HASH:
                    group.requiredItemCount = 5U;
                    group.optionalItemCount = 4U;
                    break;
                case KSW_DYN_V4_CAPABILITY_GROUP_WORK_QUEUE:
                    group.requiredItemCount = 23U;
                    group.optionalItemCount = 0U;
                    break;
                default:
                    break;
                }
                result.profileV4.capabilityGroups.push_back(group);
            }
            result.resolvedV4ItemCount =
                static_cast<std::uint32_t>(result.profileV4.items.size());
        }

        void fillProfileMetadata(
            const ArkDynModuleIdentity& identity,
            const IMAGEHLP_MODULEW64& moduleInfo,
            RuntimeDynDataResolveResult& result)
        {
            const std::string pdbGuid = guidText(moduleInfo.PdbSig70);
            const std::string pdbName = wideToUtf8(
                std::filesystem::path(moduleInfo.LoadedPdbName).filename().wstring());
            const std::string name = profileName(identity, pdbGuid, moduleInfo.PdbAge);

            result.profile.profileName = name;
            result.profile.pdbName = pdbName;
            result.profile.pdbGuid = pdbGuid;
            result.profile.pdbAge = moduleInfo.PdbAge;
            result.profile.ntoskrnl = identity;

            result.profileEx.profileName = name;
            result.profileEx.pdbName = pdbName;
            result.profileEx.pdbGuid = pdbGuid;
            result.profileEx.pdbAge = moduleInfo.PdbAge;
            result.profileEx.ntoskrnl = identity;

            result.profileV4.flags = 0U;
            result.profileV4.module.image.present = identity.present ? 1UL : 0UL;
            result.profileV4.module.image.classId = identity.classId;
            result.profileV4.module.image.machine = identity.machine;
            result.profileV4.module.image.timeDateStamp = identity.timeDateStamp;
            result.profileV4.module.image.sizeOfImage = identity.sizeOfImage;
            result.profileV4.module.image.imageBase = identity.imageBase;
            copyWide(result.profileV4.module.image.moduleName, identity.moduleName);
            copyAnsi(result.profileV4.module.profileName, name);
            copyAnsi(result.profileV4.module.pdb.pdbName, pdbName);
            copyAnsi(result.profileV4.module.pdb.pdbGuid, pdbGuid);
            result.profileV4.module.pdb.pdbAge = moduleInfo.PdbAge;
        }
    }

    RuntimeDynDataResolveResult ResolveRuntimeDynDataProfile(
        const ArkDynModuleIdentity& identity,
        const std::vector<std::string>& extraSymbolNames)
    {
        RuntimeDynDataResolveResult result{};
        result.attempted = true;
        std::vector<std::wstring> diagnostics;

        if (!identity.present ||
            identity.machine == 0U ||
            identity.timeDateStamp == 0U ||
            identity.sizeOfImage == 0U ||
            identity.imageBase == 0ULL ||
            identity.moduleName.empty())
        {
            result.diagnostics = L"loaded module identity is incomplete";
            return result;
        }

        const std::string cacheKey =
            resultCacheKey(identity, extraSymbolNames);
        {
            std::lock_guard<std::mutex> cacheLock(
                g_resultCacheMutex);
            const auto cached = g_resultCache.find(cacheKey);
            if (cached != g_resultCache.end())
            {
                return cached->second;
            }
        }

        std::filesystem::path imagePath;
        PeIdentity peIdentity{};
        std::wstring imageDiagnostic;
        if (!findIdentityMatchedImage(
                identity,
                imagePath,
                peIdentity,
                imageDiagnostic))
        {
            result.diagnostics = imageDiagnostic;
            return result;
        }
        result.imageIdentityMatched = true;
        result.imagePath = imagePath.wstring();
        if (!peIdentity.pdbIdentityAvailable)
        {
            result.diagnostics =
                L"local PE does not contain a valid RSDS PDB identity";
            return result;
        }

        std::filesystem::path preparedPdbPath;
        std::wstring pdbPreparationDiagnostic;
        const bool preparedExactPdb = prepareExactPdb(
            peIdentity,
            preparedPdbPath,
            pdbPreparationDiagnostic);
        if (!pdbPreparationDiagnostic.empty())
        {
            diagnostics.push_back(
                pdbPreparationDiagnostic);
        }

        std::lock_guard<std::mutex> lock(g_dbgHelpMutex);
        DbgHelpSession session{};
        IMAGEHLP_MODULEW64 moduleInfo{};
        std::wstring dbgHelpDiagnostic;
        if (!initializeDbgHelp(
                imagePath,
                identity,
                peIdentity,
                preparedExactPdb
                    ? preparedPdbPath.parent_path()
                    : std::filesystem::path(),
                session,
                moduleInfo,
                dbgHelpDiagnostic))
        {
            diagnostics.push_back(dbgHelpDiagnostic);
            result.diagnostics =
                joinDiagnostics(diagnostics);
            return result;
        }

        result.pdbIdentityAvailable = true;
        result.pdbPath = moduleInfo.LoadedPdbName;
        fillProfileMetadata(identity, moduleInfo, result);

        TypeResolver types(session);
        if (identity.classId == KSW_DYN_PROFILE_CLASS_NTOSKRNL ||
            identity.classId == KSW_DYN_PROFILE_CLASS_NTKRLA57)
        {
            resolveCanonicalCatalog(
                session,
                types,
                identity,
                result,
                diagnostics);
        }
        resolveModuleV4Items(session, types, identity, result);

        for (const std::string& symbolName : extraSymbolNames)
        {
            if (symbolName.empty())
            {
                continue;
            }
            std::uint32_t rva = 0U;
            if (resolveSymbolRva(session, symbolName, identity.sizeOfImage, rva))
            {
                result.symbolRvas.emplace(symbolName, rva);
            }
        }

        buildV4Groups(result);
        std::wostringstream summary;
        summary << L"exact runtime PDB loaded; v1=" << result.profile.fields.size()
                << L", EX=" << result.profileEx.items.size()
                << L", v4=" << result.profileV4.items.size()
                << L", extraSymbols=" << result.symbolRvas.size();
        diagnostics.insert(diagnostics.begin(), summary.str());
        result.diagnostics = joinDiagnostics(diagnostics);
        result.valid =
            (!result.profile.fields.empty() ||
             !result.profileEx.items.empty() ||
             !result.profileV4.items.empty() ||
             !result.symbolRvas.empty()) &&
            !result.profile.pdbName.empty() &&
            !result.profile.pdbGuid.empty() &&
            result.profile.pdbAge != 0U;
        if (result.valid)
        {
            std::lock_guard<std::mutex> cacheLock(
                g_resultCacheMutex);
            g_resultCache.insert_or_assign(cacheKey, result);
        }
        return result;
    }
}
#else
namespace ksword::ark
{
    RuntimeDynDataResolveResult ResolveRuntimeDynDataProfile(
        const ArkDynModuleIdentity& identity,
        const std::vector<std::string>& extraSymbolNames)
    {
        (void)identity;
        (void)extraSymbolNames;
        return {};
    }
}
#endif
