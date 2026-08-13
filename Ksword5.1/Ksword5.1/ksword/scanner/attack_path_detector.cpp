#include "scanner_internal.h"

#include "../file/pe_analyzer.h"

// ============================================================
// ksword/scanner/attack_path_detector.cpp
// 作用：
// - 以多阶段静态证据识别 EXIT/GhostSystemDriver 攻击路径；
// - 关联 ISO 内的宿主与同目录代理 DLL，并在内存中检查内嵌驱动；
// - 不挂载容器、不落地解码结果，也不调用任何目标代码。
// ============================================================

#include <algorithm>
#include <array>
#include <cctype>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace ks::scanner::detail
{
    namespace
    {
        constexpr std::uint32_t kMatchThreshold = 60;
        constexpr std::size_t kMinimumEncodedCharacters = 4096;
        constexpr std::size_t kMaximumEncodedCharacters = 8U * 1024U * 1024U;
        constexpr std::size_t kMaximumDecodedBytes = 64U * 1024U * 1024U;
        constexpr std::size_t kMaximumArtifactScanBytes = 32U * 1024U * 1024U;

        // ArtifactSignals 作用：缓存一次字节扫描得到的行为布尔量和首个证据偏移。
        struct ArtifactSignals
        {
            bool cefExportSurface = false;
            bool cmstpluaElevation = false;
            bool pebMasquerade = false;
            bool ghostDriverService = false;
            bool avpEvasion = false;
            bool defenderRegistryImpairment = false;
            bool securityProcessTermination = false;
            bool driverUnloadAnd360Cleanup = false;
            std::uint64_t cefOffset = 0;
            std::uint64_t elevationOffset = 0;
            std::uint64_t masqueradeOffset = 0;
            std::uint64_t serviceOffset = 0;
            std::uint64_t avpOffset = 0;
            std::uint64_t defenderOffset = 0;
            std::uint64_t terminationOffset = 0;
            std::uint64_t unloadOffset = 0;
        };

        // LowerAscii 只处理协议、模块名和文件名中的 ASCII，避免依赖区域设置。
        std::string LowerAscii(std::string value)
        {
            for (char& character : value)
            {
                const unsigned char byte = static_cast<unsigned char>(character);
                if (byte >= 'A' && byte <= 'Z')
                {
                    character = static_cast<char>(byte - 'A' + 'a');
                }
            }
            return value;
        }

        bool EndsWith(const std::string_view value, const std::string_view suffix)
        {
            return value.size() >= suffix.size() &&
                value.substr(value.size() - suffix.size()) == suffix;
        }

        // FindAsciiInsensitive 返回首个 ASCII 不区分大小写匹配，找不到时返回 size()。
        std::size_t FindAsciiInsensitive(
            const std::span<const std::uint8_t> bytes,
            const std::string_view needle)
        {
            if (needle.empty() || needle.size() > bytes.size())
            {
                return bytes.size();
            }

            for (std::size_t offset = 0;
                 offset <= bytes.size() - needle.size();
                 ++offset)
            {
                bool matched = true;
                for (std::size_t index = 0; index < needle.size(); ++index)
                {
                    unsigned char left = bytes[offset + index];
                    unsigned char right = static_cast<unsigned char>(needle[index]);
                    if (left >= 'A' && left <= 'Z')
                    {
                        left = static_cast<unsigned char>(left - 'A' + 'a');
                    }
                    if (right >= 'A' && right <= 'Z')
                    {
                        right = static_cast<unsigned char>(right - 'A' + 'a');
                    }
                    if (left != right)
                    {
                        matched = false;
                        break;
                    }
                }
                if (matched)
                {
                    return offset;
                }
            }
            return bytes.size();
        }

        // FindWideAsciiInsensitive 检查 UTF-16LE 形式的 ASCII IOC。
        std::size_t FindWideAsciiInsensitive(
            const std::span<const std::uint8_t> bytes,
            const std::string_view needle)
        {
            const std::size_t encodedBytes = needle.size() * 2U;
            if (needle.empty() || encodedBytes > bytes.size())
            {
                return bytes.size();
            }

            for (std::size_t offset = 0;
                 offset <= bytes.size() - encodedBytes;
                 ++offset)
            {
                bool matched = true;
                for (std::size_t index = 0; index < needle.size(); ++index)
                {
                    unsigned char left = bytes[offset + index * 2U];
                    unsigned char right = static_cast<unsigned char>(needle[index]);
                    if (bytes[offset + index * 2U + 1U] != 0)
                    {
                        matched = false;
                        break;
                    }
                    if (left >= 'A' && left <= 'Z')
                    {
                        left = static_cast<unsigned char>(left - 'A' + 'a');
                    }
                    if (right >= 'A' && right <= 'Z')
                    {
                        right = static_cast<unsigned char>(right - 'A' + 'a');
                    }
                    if (left != right)
                    {
                        matched = false;
                        break;
                    }
                }
                if (matched)
                {
                    return offset;
                }
            }
            return bytes.size();
        }

        std::size_t FindText(
            const std::span<const std::uint8_t> bytes,
            const std::string_view text)
        {
            const std::size_t asciiOffset = FindAsciiInsensitive(bytes, text);
            const std::size_t wideOffset = FindWideAsciiInsensitive(bytes, text);
            return std::min(asciiOffset, wideOffset);
        }

        bool ContainsText(
            const std::span<const std::uint8_t> bytes,
            const std::string_view text)
        {
            return FindText(bytes, text) != bytes.size();
        }

        std::size_t CountTextSet(
            const std::span<const std::uint8_t> bytes,
            const std::span<const std::string_view> values)
        {
            return static_cast<std::size_t>(std::count_if(
                values.begin(),
                values.end(),
                [bytes](const std::string_view value)
                {
                    return ContainsText(bytes, value);
                }));
        }

        bool IsBase64Character(const std::uint8_t byte)
        {
            return (byte >= 'A' && byte <= 'Z') ||
                (byte >= 'a' && byte <= 'z') ||
                (byte >= '0' && byte <= '9') ||
                byte == '+' ||
                byte == '/' ||
                byte == '=';
        }

        int Base64Value(const std::uint8_t byte)
        {
            if (byte >= 'A' && byte <= 'Z') return byte - 'A';
            if (byte >= 'a' && byte <= 'z') return byte - 'a' + 26;
            if (byte >= '0' && byte <= '9') return byte - '0' + 52;
            if (byte == '+') return 62;
            if (byte == '/') return 63;
            return -1;
        }

        // DecodeBase64 采用严格四字节组和尾部填充校验，并在分配前检查上限。
        bool DecodeBase64(
            const std::span<const std::uint8_t> input,
            std::vector<std::uint8_t>& output)
        {
            output.clear();
            if (input.empty() || (input.size() % 4U) != 0)
            {
                return false;
            }
            const std::size_t maximumOutput = (input.size() / 4U) * 3U;
            if (maximumOutput > kMaximumDecodedBytes)
            {
                return false;
            }
            output.reserve(maximumOutput);

            for (std::size_t offset = 0; offset < input.size(); offset += 4U)
            {
                const bool lastGroup = offset + 4U == input.size();
                const std::uint8_t third = input[offset + 2U];
                const std::uint8_t fourth = input[offset + 3U];
                const int a = Base64Value(input[offset]);
                const int b = Base64Value(input[offset + 1U]);
                const int c = third == '=' ? 0 : Base64Value(third);
                const int d = fourth == '=' ? 0 : Base64Value(fourth);
                if (a < 0 || b < 0 || c < 0 || d < 0 ||
                    (!lastGroup && (third == '=' || fourth == '=')) ||
                    (third == '=' && fourth != '='))
                {
                    output.clear();
                    return false;
                }

                const std::uint32_t value =
                    (static_cast<std::uint32_t>(a) << 18U) |
                    (static_cast<std::uint32_t>(b) << 12U) |
                    (static_cast<std::uint32_t>(c) << 6U) |
                    static_cast<std::uint32_t>(d);
                output.push_back(static_cast<std::uint8_t>(value >> 16U));
                if (third != '=')
                {
                    output.push_back(static_cast<std::uint8_t>(value >> 8U));
                }
                if (fourth != '=')
                {
                    output.push_back(static_cast<std::uint8_t>(value));
                }
            }
            return true;
        }

        int HexValue(const std::uint8_t byte)
        {
            if (byte >= '0' && byte <= '9') return byte - '0';
            if (byte >= 'a' && byte <= 'f') return byte - 'a' + 10;
            if (byte >= 'A' && byte <= 'F') return byte - 'A' + 10;
            return -1;
        }

        bool DecodeHex(
            const std::span<const std::uint8_t> input,
            std::vector<std::uint8_t>& output)
        {
            output.clear();
            if (input.empty() || (input.size() % 2U) != 0 ||
                input.size() / 2U > kMaximumDecodedBytes)
            {
                return false;
            }
            output.reserve(input.size() / 2U);
            for (std::size_t offset = 0; offset < input.size(); offset += 2U)
            {
                const int high = HexValue(input[offset]);
                const int low = HexValue(input[offset + 1U]);
                if (high < 0 || low < 0)
                {
                    output.clear();
                    return false;
                }
                output.push_back(static_cast<std::uint8_t>((high << 4) | low));
            }
            return true;
        }

        // LooksLikePe 先核对 DOS 偏移和 NT 签名，拒绝只有 MZ 字样的诱饵数据。
        bool LooksLikePe(const std::span<const std::uint8_t> bytes)
        {
            if (bytes.size() < 0x40U || bytes[0] != 'M' || bytes[1] != 'Z')
            {
                return false;
            }
            const std::uint32_t ntOffset =
                static_cast<std::uint32_t>(bytes[0x3CU]) |
                (static_cast<std::uint32_t>(bytes[0x3DU]) << 8U) |
                (static_cast<std::uint32_t>(bytes[0x3EU]) << 16U) |
                (static_cast<std::uint32_t>(bytes[0x3FU]) << 24U);
            return ntOffset <= bytes.size() &&
                bytes.size() - ntOffset >= 4U &&
                bytes[ntOffset] == 'P' &&
                bytes[ntOffset + 1U] == 'E' &&
                bytes[ntOffset + 2U] == 0 &&
                bytes[ntOffset + 3U] == 0;
        }

        // DecodeEmbeddedDriver 仅接受“UTF-16 Base64 -> Base64 -> hex -> MZ”完整链。
        bool DecodeEmbeddedDriver(
            const std::span<const std::uint8_t> bytes,
            std::vector<std::uint8_t>& driverOut,
            std::uint64_t& encodedOffsetOut)
        {
            driverOut.clear();
            for (std::size_t cursor = 0; cursor + 1U < bytes.size();)
            {
                if (!IsBase64Character(bytes[cursor]) || bytes[cursor + 1U] != 0)
                {
                    ++cursor;
                    continue;
                }

                const std::size_t start = cursor;
                std::vector<std::uint8_t> firstLayerText;
                while (cursor + 1U < bytes.size() &&
                    IsBase64Character(bytes[cursor]) &&
                    bytes[cursor + 1U] == 0 &&
                    firstLayerText.size() <= kMaximumEncodedCharacters)
                {
                    firstLayerText.push_back(bytes[cursor]);
                    cursor += 2U;
                }
                if (firstLayerText.size() < kMinimumEncodedCharacters ||
                    firstLayerText.size() > kMaximumEncodedCharacters)
                {
                    continue;
                }

                // 邻接 ASCII 字符可能与 UTF-16LE 首字符偶然组成一对；尝试四种
                // Base64 相位即可去除这种最多三个字符的前缀污染。
                const std::size_t maximumPrefix = std::min<std::size_t>(
                    4U,
                    firstLayerText.size());
                for (std::size_t prefix = 0; prefix < maximumPrefix; ++prefix)
                {
                    const auto alignedFirstLayer = std::span<const std::uint8_t>(
                        firstLayerText).subspan(prefix);
                    if (alignedFirstLayer.size() < kMinimumEncodedCharacters ||
                        (alignedFirstLayer.size() % 4U) != 0)
                    {
                        continue;
                    }

                    std::vector<std::uint8_t> secondLayerText;
                    std::vector<std::uint8_t> hexText;
                    std::vector<std::uint8_t> decoded;
                    if (!DecodeBase64(alignedFirstLayer, secondLayerText) ||
                        !DecodeBase64(secondLayerText, hexText) ||
                        !DecodeHex(hexText, decoded) ||
                        !LooksLikePe(decoded))
                    {
                        continue;
                    }
                    driverOut = std::move(decoded);
                    encodedOffsetOut = start + prefix * 2U;
                    return true;
                }
            }
            return false;
        }

        ArtifactSignals CollectSignals(const std::span<const std::uint8_t> bytes)
        {
            ArtifactSignals signals{};
            const std::array<std::string_view, 3> cefNames{
                "cef_execute_process", "cef_initialize", "cef_shutdown"
            };
            signals.cefExportSurface = CountTextSet(bytes, cefNames) == cefNames.size();
            signals.cefOffset = FindText(bytes, "cef_execute_process");

            const bool hasElevationMoniker =
                ContainsText(bytes, "Elevation:Administrator!new:") &&
                ContainsText(bytes, "3E5FC7F9-9A51-4367-9063-A120244FBEC7");
            signals.cmstpluaElevation = hasElevationMoniker &&
                ContainsText(bytes, "CoGetObject") &&
                ContainsText(bytes, "CheckTokenMembership");
            signals.elevationOffset = FindText(bytes, "Elevation:Administrator!new:");

            signals.pebMasquerade = ContainsText(bytes, "explorer.exe") &&
                ContainsText(bytes, "NtQueryInformationProcess") &&
                ContainsText(bytes, "ReadProcessMemory");
            signals.masqueradeOffset = FindText(bytes, "explorer.exe");

            signals.ghostDriverService = ContainsText(bytes, "GhostSystemDriver") &&
                ContainsText(bytes, "CreateServiceW") &&
                ContainsText(bytes, "StartServiceW");
            signals.serviceOffset = FindText(bytes, "GhostSystemDriver");
            signals.avpEvasion = ContainsText(bytes, "avp.exe");
            signals.avpOffset = FindText(bytes, "avp.exe");

            const std::array<std::string_view, 6> defenderTerms{
                "TamperProtection", "DisableRealtimeMonitoring", "WdFilter",
                "WdBoot", "WdNisDrv", "WinDefend"
            };
            signals.defenderRegistryImpairment =
                CountTextSet(bytes, defenderTerms) >= 4U &&
                ContainsText(bytes, "ZwSetValueKey");
            signals.defenderOffset = FindText(bytes, "TamperProtection");

            const std::array<std::string_view, 8> processTargets{
                "MsMpEng.exe", "NisSrv.exe", "360tray.exe", "360Safe.exe",
                "ZhuDongFangYu.exe", "AvastSvc.exe", "AVGSvc.exe", "QQPCTray.exe"
            };
            signals.securityProcessTermination =
                CountTextSet(bytes, processTargets) >= 3U &&
                ContainsText(bytes, "ZwTerminateProcess");
            signals.terminationOffset = FindText(bytes, "ZwTerminateProcess");

            signals.driverUnloadAnd360Cleanup =
                ContainsText(bytes, "ZwUnloadDriver") &&
                ContainsText(bytes, "\\Registry\\Machine\\SOFTWARE\\360");
            signals.unloadOffset = FindText(bytes, "ZwUnloadDriver");
            return signals;
        }

        // AddEvidence 对 code+artifact 去重，确保容器别名不会重复抬高评分。
        void AddEvidence(
            BinaryScanResult& result,
            std::string code,
            std::string stage,
            std::string artifact,
            std::string technique,
            const AttackPathSeverity severity,
            const std::uint32_t score,
            const bool hasOffset,
            const std::uint64_t offset)
        {
            const auto duplicate = std::find_if(
                result.attackPath.evidence.begin(),
                result.attackPath.evidence.end(),
                [&code, &artifact](const AttackPathEvidence& evidence)
                {
                    return evidence.code == code && evidence.artifact == artifact;
                });
            if (duplicate != result.attackPath.evidence.end())
            {
                return;
            }

            result.attackPath.ruleId = "KSWORD.EXIT_GHOST_CHAIN.V1";
            result.attackPath.family = "EXIT / GhostSystemDriver";
            result.attackPath.evidence.push_back(AttackPathEvidence{
                std::move(code),
                std::move(stage),
                std::move(artifact),
                std::move(technique),
                severity,
                score,
                hasOffset,
                offset
            });
        }

        void AppendSignalEvidence(
            const ArtifactSignals& signals,
            const std::string& artifact,
            const std::uint64_t baseOffset,
            const bool offsetsAreFileOffsets,
            BinaryScanResult& result)
        {
            if (signals.cefExportSurface)
            {
                AddEvidence(result, "proxy.cef_surface", "sideload", artifact,
                    "T1574.002", AttackPathSeverity::Suspicious, 10,
                    offsetsAreFileOffsets,
                    baseOffset + signals.cefOffset);
            }
            if (signals.cmstpluaElevation)
            {
                AddEvidence(result, "proxy.cmstplua_uac", "elevation", artifact,
                    "T1548.002", AttackPathSeverity::Critical, 25,
                    offsetsAreFileOffsets,
                    baseOffset + signals.elevationOffset);
            }
            if (signals.pebMasquerade)
            {
                AddEvidence(result, "proxy.peb_masquerade", "masquerade", artifact,
                    "T1036", AttackPathSeverity::High, 15,
                    offsetsAreFileOffsets,
                    baseOffset + signals.masqueradeOffset);
            }
            if (signals.ghostDriverService)
            {
                AddEvidence(result, "proxy.driver_service", "persistence", artifact,
                    "T1543.003", AttackPathSeverity::Critical, 20,
                    offsetsAreFileOffsets,
                    baseOffset + signals.serviceOffset);
            }
            if (signals.avpEvasion &&
                (signals.cmstpluaElevation || signals.ghostDriverService))
            {
                AddEvidence(result, "proxy.avp_evasion", "defense_evasion", artifact,
                    "T1562.001", AttackPathSeverity::Suspicious, 5,
                    offsetsAreFileOffsets,
                    baseOffset + signals.avpOffset);
            }
            if (signals.defenderRegistryImpairment)
            {
                AddEvidence(result, "driver.defender_registry", "defense_evasion", artifact,
                    "T1562.001 / T1112", AttackPathSeverity::Critical, 30,
                    offsetsAreFileOffsets,
                    baseOffset + signals.defenderOffset);
            }
            if (signals.securityProcessTermination)
            {
                AddEvidence(result, "driver.security_process_kill", "defense_evasion", artifact,
                    "T1562.001", AttackPathSeverity::Critical, 20,
                    offsetsAreFileOffsets,
                    baseOffset + signals.terminationOffset);
            }
            if (signals.driverUnloadAnd360Cleanup)
            {
                AddEvidence(result, "driver.unload_360", "defense_evasion", artifact,
                    "T1562.001", AttackPathSeverity::Critical, 15,
                    offsetsAreFileOffsets,
                    baseOffset + signals.unloadOffset);
            }
        }

        bool HasEvidenceCode(
            const BinaryScanResult& result,
            const std::string_view code)
        {
            return std::any_of(
                result.attackPath.evidence.begin(),
                result.attackPath.evidence.end(),
                [code](const AttackPathEvidence& evidence)
                {
                    return evidence.code == code;
                });
        }

        // FinalizeDetection 同时要求高分与关键阶段组合，压低孤立字符串误报。
        void FinalizeDetection(BinaryScanResult& result)
        {
            std::uint32_t total = 0;
            for (const AttackPathEvidence& evidence : result.attackPath.evidence)
            {
                total = std::min<std::uint32_t>(100U, total + evidence.score);
            }
            result.attackPath.score = total;

            const bool dropperPath =
                HasEvidenceCode(result, "proxy.driver_service") &&
                (HasEvidenceCode(result, "proxy.cmstplua_uac") ||
                 HasEvidenceCode(result, "embedded.double_base64_driver"));
            const bool driverPath =
                HasEvidenceCode(result, "driver.defender_registry") &&
                HasEvidenceCode(result, "driver.security_process_kill");
            result.attackPath.matched =
                total >= kMatchThreshold && (dropperPath || driverPath);
        }

        bool ImportsLibcef(const std::span<const std::uint8_t> bytes)
        {
            if (bytes.size() > kMaximumArtifactScanBytes)
            {
                return false;
            }
            const std::vector<std::uint8_t> copy(bytes.begin(), bytes.end());
            const ks::file::PeAnalysisResult analysis =
                ks::file::AnalyzePeBytes(copy);
            if (!analysis.success)
            {
                return false;
            }
            return std::any_of(
                analysis.importModules.begin(),
                analysis.importModules.end(),
                [](const ks::file::PeImportModuleSummary& module)
                {
                    const std::string moduleName = LowerAscii(module.dllName);
                    return moduleName == "libcef.dll" || moduleName == "libcef";
                });
        }
    }

    void DetectAttackPathInPe(
        const std::span<const std::uint8_t> bytes,
        const std::string_view artifact,
        const std::uint64_t baseOffset,
        const ScanOptions&,
        BinaryScanResult& result)
    {
        if (bytes.size() > kMaximumArtifactScanBytes || !LooksLikePe(bytes))
        {
            return;
        }

        const std::string artifactName =
            artifact.empty() ? std::string("<selected-file>") : std::string(artifact);
        AppendSignalEvidence(
            CollectSignals(bytes),
            artifactName,
            baseOffset,
            true,
            result);

        // 解码仅发生在内存；解码字节不写入磁盘，也不交给系统加载器。
        std::vector<std::uint8_t> decodedDriver;
        std::uint64_t encodedOffset = 0;
        if (DecodeEmbeddedDriver(bytes, decodedDriver, encodedOffset))
        {
            AddEvidence(result, "embedded.double_base64_driver", "payload_decode",
                artifactName, "T1140", AttackPathSeverity::Critical, 20, true,
                baseOffset + encodedOffset);
            AppendSignalEvidence(
                CollectSignals(decodedDriver),
                artifactName + "::<decoded-driver>",
                0,
                false,
                result);
        }
        FinalizeDetection(result);
    }

    void DetectAttackPathInContainer(
        const std::span<const std::uint8_t> bytes,
        const std::vector<ContainerMember>& members,
        const ScanOptions& options,
        BinaryScanResult& result)
    {
        const ContainerMember* libcefMember = nullptr;
        std::vector<const ContainerMember*> executableMembers;
        for (const ContainerMember& member : members)
        {
            if (member.directory || member.offset > bytes.size() ||
                member.size > bytes.size() - member.offset)
            {
                continue;
            }
            const std::string loweredPath = LowerAscii(member.path);
            if (EndsWith(loweredPath, "/libcef.dll") || loweredPath == "libcef.dll")
            {
                libcefMember = &member;
            }
            if (EndsWith(loweredPath, ".exe"))
            {
                executableMembers.push_back(&member);
            }

            const auto memberBytes = bytes.subspan(
                static_cast<std::size_t>(member.offset),
                static_cast<std::size_t>(member.size));
            DetectAttackPathInPe(
                memberBytes,
                member.path,
                member.offset,
                options,
                result);
        }

        // 只有解析出的 PE 导入表确实依赖同容器 libcef.dll 时，才记录侧载关联。
        if (libcefMember != nullptr)
        {
            for (const ContainerMember* executable : executableMembers)
            {
                const auto executableBytes = bytes.subspan(
                    static_cast<std::size_t>(executable->offset),
                    static_cast<std::size_t>(executable->size));
                if (!ImportsLibcef(executableBytes))
                {
                    continue;
                }
                AddEvidence(result, "container.libcef_sideload_pair", "sideload",
                    executable->path + " -> " + libcefMember->path,
                    "T1574.002", AttackPathSeverity::High, 20, true,
                    executable->offset);
                break;
            }
        }
        FinalizeDetection(result);
    }
}
