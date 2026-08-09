#include "NetToolsDiagnostics.h"

#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <icmpapi.h>
#include <windns.h>

#include <algorithm>
#include <cstdio>
#include <iterator>
#include <limits>
#include <string>
#include <vector>

#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "Iphlpapi.lib")
#pragma comment(lib, "Dnsapi.lib")

namespace Ksword::Features::NetTools {
namespace {

// kEchoPayloadSize matches what the Windows ping tool sends. Keeping it identical
// means a result from this page can be compared with one from a console session
// without wondering whether the payload size changed the path MTU behaviour.
constexpr WORD kEchoPayloadSize = 32;

// kReplySlack covers the ICMP error message the stack may append after the reply
// structure. IcmpSendEcho2 rejects a buffer that has no room for it, and the
// documented minimum is 8 bytes; the extra room here costs nothing.
constexpr std::size_t kReplySlack = 64;

constexpr std::uint32_t kMaxEchoCount = 32;
constexpr std::uint32_t kMaxHopCount = 64;

void AppendLine(std::wstring& text, const std::wstring& line) {
    text += line;
    text += L"\r\n";
}

std::wstring FormatMilliseconds(const std::uint32_t value) {
    return value == 0 ? std::wstring(L"<1 ms") : std::to_wstring(value) + L" ms";
}

// IcmpStatusText turns an IP_STATUS into wording an operator can act on. The raw
// codes are not in the system message table, so FormatMessage would only produce
// "unknown error" for the interesting half of them.
std::wstring IcmpStatusText(const ULONG status) {
    switch (status) {
    case IP_SUCCESS: return L"成功";
    case IP_BUF_TOO_SMALL: return L"回复缓冲区太小";
    case IP_DEST_NET_UNREACHABLE: return L"目标网络不可达";
    case IP_DEST_HOST_UNREACHABLE: return L"目标主机不可达";
    case IP_DEST_PROT_UNREACHABLE: return L"目标协议不可达";
    case IP_DEST_PORT_UNREACHABLE: return L"目标端口不可达";
    case IP_NO_RESOURCES: return L"IP 资源不足";
    case IP_BAD_OPTION: return L"IP 选项无效";
    case IP_HW_ERROR: return L"硬件错误";
    case IP_PACKET_TOO_BIG: return L"数据包过大";
    case IP_REQ_TIMED_OUT: return L"请求超时";
    case IP_BAD_REQ: return L"请求无效";
    case IP_BAD_ROUTE: return L"路由无效";
    case IP_TTL_EXPIRED_TRANSIT: return L"传输中 TTL 过期";
    case IP_TTL_EXPIRED_REASSEM: return L"重组时 TTL 过期";
    case IP_PARAM_PROBLEM: return L"参数错误";
    case IP_SOURCE_QUENCH: return L"源抑制";
    case IP_OPTION_TOO_BIG: return L"IP 选项过长";
    case IP_BAD_DESTINATION: return L"目标地址无效";
    case IP_GENERAL_FAILURE: return L"常规故障";
    default: break;
    }
    return L"ICMP 状态 " + std::to_wstring(status);
}

struct ResolvedTarget final {
    bool resolved = false;
    std::uint32_t address = 0;    // Network byte order.
    std::wstring addressText;
    std::wstring diagnostic;
};

// ResolveIpv4 turns a host name or literal into one IPv4 address. Input is the
// user's text; processing asks the resolver for AF_INET only; output carries the
// first answer, because an operator asking to ping a name wants the address the
// system itself would use and that is the first one the resolver ranks.
ResolvedTarget ResolveIpv4(const std::wstring& target) {
    ResolvedTarget resolved{};
    if (target.empty()) {
        resolved.diagnostic = L"请先填写目标主机名或 IP 地址。";
        return resolved;
    }

    EnsureWinsockInitialized();
    ADDRINFOW hints{};
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    PADDRINFOW info = nullptr;
    const int status = ::GetAddrInfoW(target.c_str(), nullptr, &hints, &info);
    if (status != 0 || info == nullptr) {
        if (info != nullptr) {
            ::FreeAddrInfoW(info);
        }
        resolved.diagnostic = L"无法解析目标 " + target + L" 的 IPv4 地址：" +
            FormatWin32Error(static_cast<std::uint32_t>(status)) +
            L"。该目标可能只提供 IPv6 地址，本页的 ICMP 探测仅支持 IPv4。";
        return resolved;
    }

    for (const ADDRINFOW* cursor = info; cursor != nullptr; cursor = cursor->ai_next) {
        if (cursor->ai_family != AF_INET || cursor->ai_addr == nullptr ||
            cursor->ai_addrlen < sizeof(sockaddr_in)) {
            continue;
        }
        const auto* address = reinterpret_cast<const sockaddr_in*>(cursor->ai_addr);
        resolved.address = static_cast<std::uint32_t>(address->sin_addr.S_un.S_addr);
        resolved.addressText = FormatIpv4Address(resolved.address);
        resolved.resolved = true;
        break;
    }
    ::FreeAddrInfoW(info);
    if (!resolved.resolved) {
        resolved.diagnostic = L"目标 " + target + L" 没有可用的 IPv4 地址。";
    }
    return resolved;
}

// IcmpSession owns the ICMP handle for one probe run. Both ping and traceroute
// have several early exits and the handle has to be closed on all of them.
class IcmpSession final {
public:
    IcmpSession() : handle_(::IcmpCreateFile()) {
    }

    ~IcmpSession() {
        if (handle_ != INVALID_HANDLE_VALUE && handle_ != nullptr) {
            ::IcmpCloseHandle(handle_);
        }
    }

    IcmpSession(const IcmpSession&) = delete;
    IcmpSession& operator=(const IcmpSession&) = delete;

    bool valid() const noexcept {
        return handle_ != INVALID_HANDLE_VALUE && handle_ != nullptr;
    }

    HANDLE get() const noexcept {
        return handle_;
    }

private:
    HANDLE handle_ = INVALID_HANDLE_VALUE;
};

DiagnosticResult RunPing(const DiagnosticRequest& request) {
    DiagnosticResult result{};
    const ResolvedTarget target = ResolveIpv4(request.target);
    if (!target.resolved) {
        result.text = target.diagnostic;
        result.summary = L"Ping 未执行：目标解析失败。";
        return result;
    }

    IcmpSession session;
    if (!session.valid()) {
        result.text = L"无法创建 ICMP 句柄：" + FormatWin32Error(::GetLastError()) + L"。";
        result.summary = L"Ping 未执行：ICMP 句柄创建失败。";
        return result;
    }

    const std::uint32_t echoCount = std::clamp<std::uint32_t>(request.echoCount, 1, kMaxEchoCount);
    unsigned char payload[kEchoPayloadSize]{};
    for (std::size_t index = 0; index < sizeof(payload); ++index) {
        payload[index] = static_cast<unsigned char>(L'a' + (index % 23));
    }
    std::vector<unsigned char> replyBuffer(sizeof(ICMP_ECHO_REPLY) + kEchoPayloadSize + kReplySlack, 0);

    AppendLine(result.text, L"正在 Ping " + request.target + L" [" + target.addressText + L"]，数据 " +
        std::to_wstring(kEchoPayloadSize) + L" 字节：");

    std::uint32_t received = 0;
    std::uint32_t minimum = (std::numeric_limits<std::uint32_t>::max)();
    std::uint32_t maximum = 0;
    std::uint64_t total = 0;
    for (std::uint32_t attempt = 0; attempt < echoCount; ++attempt) {
        const DWORD replies = ::IcmpSendEcho2(
            session.get(),
            nullptr,
            nullptr,
            nullptr,
            static_cast<IPAddr>(target.address),
            payload,
            kEchoPayloadSize,
            nullptr,
            replyBuffer.data(),
            static_cast<DWORD>(replyBuffer.size()),
            request.timeoutMs);
        if (replies == 0) {
            AppendLine(result.text, L"请求失败：" + FormatWin32Error(::GetLastError()));
            continue;
        }
        const auto* reply = reinterpret_cast<const ICMP_ECHO_REPLY*>(replyBuffer.data());
        if (reply->Status != IP_SUCCESS) {
            AppendLine(result.text, L"来自 " + FormatIpv4Address(static_cast<std::uint32_t>(reply->Address)) +
                L" 的回应：" + IcmpStatusText(reply->Status));
            continue;
        }
        ++received;
        const std::uint32_t roundTrip = static_cast<std::uint32_t>(reply->RoundTripTime);
        minimum = (std::min)(minimum, roundTrip);
        maximum = (std::max)(maximum, roundTrip);
        total += roundTrip;
        AppendLine(result.text, L"来自 " + FormatIpv4Address(static_cast<std::uint32_t>(reply->Address)) +
            L" 的回复：字节=" + std::to_wstring(reply->DataSize) +
            L" 时间=" + FormatMilliseconds(roundTrip) +
            L" TTL=" + std::to_wstring(reply->Options.Ttl));
    }

    const std::uint32_t lost = echoCount - received;
    const std::uint32_t lossPercent = echoCount == 0 ? 0 : lost * 100 / echoCount;
    AppendLine(result.text, L"");
    AppendLine(result.text, L"Ping 统计：已发送 = " + std::to_wstring(echoCount) +
        L"，已接收 = " + std::to_wstring(received) +
        L"，丢失 = " + std::to_wstring(lost) + L"（" + std::to_wstring(lossPercent) + L"% 丢失）");
    if (received != 0) {
        AppendLine(result.text, L"往返行程时间：最短 = " + FormatMilliseconds(minimum) +
            L"，最长 = " + FormatMilliseconds(maximum) +
            L"，平均 = " + FormatMilliseconds(static_cast<std::uint32_t>(total / received)));
    }

    result.success = received != 0;
    result.summary = L"Ping " + target.addressText + L" 完成：接收 " + std::to_wstring(received) + L"/" +
        std::to_wstring(echoCount) + L"，丢失 " + std::to_wstring(lossPercent) + L"%。";
    return result;
}

DiagnosticResult RunTraceRoute(const DiagnosticRequest& request) {
    DiagnosticResult result{};
    const ResolvedTarget target = ResolveIpv4(request.target);
    if (!target.resolved) {
        result.text = target.diagnostic;
        result.summary = L"路由跟踪未执行：目标解析失败。";
        return result;
    }

    IcmpSession session;
    if (!session.valid()) {
        result.text = L"无法创建 ICMP 句柄：" + FormatWin32Error(::GetLastError()) + L"。";
        result.summary = L"路由跟踪未执行：ICMP 句柄创建失败。";
        return result;
    }

    const std::uint32_t maxHops = std::clamp<std::uint32_t>(request.maxHops, 1, kMaxHopCount);
    unsigned char payload[kEchoPayloadSize]{};
    for (std::size_t index = 0; index < sizeof(payload); ++index) {
        payload[index] = static_cast<unsigned char>(L'a' + (index % 23));
    }
    std::vector<unsigned char> replyBuffer(sizeof(ICMP_ECHO_REPLY) + kEchoPayloadSize + kReplySlack, 0);

    AppendLine(result.text, L"通过最多 " + std::to_wstring(maxHops) + L" 个跃点跟踪到 " + request.target +
        L" [" + target.addressText + L"] 的路由：");
    AppendLine(result.text, L"");

    bool reached = false;
    std::uint32_t lastHop = 0;
    for (std::uint32_t hop = 1; hop <= maxHops && !reached; ++hop) {
        lastHop = hop;
        IP_OPTION_INFORMATION options{};
        options.Ttl = static_cast<UCHAR>(hop);
        const DWORD replies = ::IcmpSendEcho2(
            session.get(),
            nullptr,
            nullptr,
            nullptr,
            static_cast<IPAddr>(target.address),
            payload,
            kEchoPayloadSize,
            &options,
            replyBuffer.data(),
            static_cast<DWORD>(replyBuffer.size()),
            request.timeoutMs);
        const std::wstring prefix = (hop < 10 ? L"  " : L" ") + std::to_wstring(hop);
        if (replies == 0) {
            const DWORD error = ::GetLastError();
            if (error == IP_REQ_TIMED_OUT) {
                AppendLine(result.text, prefix + L"\t*\t请求超时");
                continue;
            }
            AppendLine(result.text, prefix + L"\t*\t" + FormatWin32Error(error));
            continue;
        }

        const auto* reply = reinterpret_cast<const ICMP_ECHO_REPLY*>(replyBuffer.data());
        const std::wstring hopAddress = FormatIpv4Address(static_cast<std::uint32_t>(reply->Address));
        if (reply->Status == IP_SUCCESS) {
            reached = true;
            AppendLine(result.text, prefix + L"\t" + FormatMilliseconds(static_cast<std::uint32_t>(reply->RoundTripTime)) +
                L"\t" + hopAddress + L"\t（已到达目标）");
            continue;
        }
        if (reply->Status == IP_TTL_EXPIRED_TRANSIT) {
            AppendLine(result.text, prefix + L"\t" + FormatMilliseconds(static_cast<std::uint32_t>(reply->RoundTripTime)) +
                L"\t" + hopAddress);
            continue;
        }
        // Anything else is still a real router answering, so the hop address is
        // printed alongside the reason rather than collapsed into a timeout.
        AppendLine(result.text, prefix + L"\t*\t" + hopAddress + L"\t" + IcmpStatusText(reply->Status));
    }

    AppendLine(result.text, L"");
    AppendLine(result.text, reached ? L"跟踪完成。" : L"未在跃点上限内到达目标，跟踪结束。");
    result.success = reached;
    result.summary = reached
        ? L"路由跟踪完成：" + std::to_wstring(lastHop) + L" 跳到达 " + target.addressText + L"。"
        : L"路由跟踪结束：" + std::to_wstring(lastHop) + L" 跳内未到达 " + target.addressText + L"。";
    return result;
}

std::wstring DnsTypeText(const WORD type) {
    switch (type) {
    case DNS_TYPE_A: return L"A";
    case DNS_TYPE_NS: return L"NS";
    case DNS_TYPE_CNAME: return L"CNAME";
    case DNS_TYPE_SOA: return L"SOA";
    case DNS_TYPE_PTR: return L"PTR";
    case DNS_TYPE_MX: return L"MX";
    case DNS_TYPE_TEXT: return L"TXT";
    case DNS_TYPE_AAAA: return L"AAAA";
    case DNS_TYPE_SRV: return L"SRV";
    case DNS_TYPE_ANY: return L"ANY";
    default: break;
    }
    return L"类型 " + std::to_wstring(type);
}

std::wstring SafeName(PCWSTR name) {
    return name == nullptr ? std::wstring{} : std::wstring(name);
}

// DnsRecordValueText renders one answer. Only the record types the combo offers
// are decoded; anything else still shows up as a row with its type and TTL so an
// unexpected answer in an ANY query is visible rather than dropped.
std::wstring DnsRecordValueText(const DNS_RECORDW& record) {
    switch (record.wType) {
    case DNS_TYPE_A:
        return FormatIpv4Address(static_cast<std::uint32_t>(record.Data.A.IpAddress));
    case DNS_TYPE_AAAA:
        return FormatIpv6Address(reinterpret_cast<const std::uint8_t*>(record.Data.AAAA.Ip6Address.IP6Byte), 0);
    case DNS_TYPE_NS:
    case DNS_TYPE_CNAME:
    case DNS_TYPE_PTR:
        return SafeName(record.Data.PTR.pNameHost);
    case DNS_TYPE_MX:
        return L"优先级 " + std::to_wstring(record.Data.MX.wPreference) + L" " + SafeName(record.Data.MX.pNameExchange);
    case DNS_TYPE_SRV:
        return SafeName(record.Data.SRV.pNameTarget) + L":" + std::to_wstring(record.Data.SRV.wPort) +
            L"（优先级 " + std::to_wstring(record.Data.SRV.wPriority) +
            L"，权重 " + std::to_wstring(record.Data.SRV.wWeight) + L"）";
    case DNS_TYPE_SOA:
        return L"主服务器 " + SafeName(record.Data.SOA.pNamePrimaryServer) +
            L"，管理员 " + SafeName(record.Data.SOA.pNameAdministrator) +
            L"，序列号 " + std::to_wstring(record.Data.SOA.dwSerialNo) +
            L"，刷新 " + std::to_wstring(record.Data.SOA.dwRefresh) +
            L"，重试 " + std::to_wstring(record.Data.SOA.dwRetry) +
            L"，过期 " + std::to_wstring(record.Data.SOA.dwExpire);
    case DNS_TYPE_TEXT: {
        std::wstring text;
        for (DWORD index = 0; index < record.Data.TXT.dwStringCount; ++index) {
            if (!text.empty()) {
                text += L" ";
            }
            text += L"\"" + SafeName(record.Data.TXT.pStringArray[index]) + L"\"";
        }
        return text;
    }
    default:
        break;
    }
    return L"（未解码，数据长度 " + std::to_wstring(record.wDataLength) + L" 字节）";
}

DiagnosticResult RunDnsLookup(const DiagnosticRequest& request) {
    DiagnosticResult result{};
    if (request.target.empty()) {
        result.text = L"请先填写要查询的域名。";
        result.summary = L"DNS 查询未执行：域名为空。";
        return result;
    }

    const WORD recordType = request.dnsRecordType == 0 ? static_cast<WORD>(DNS_TYPE_A) : request.dnsRecordType;
    PDNS_RECORD records = nullptr;
    const DNS_STATUS status = ::DnsQuery_W(
        request.target.c_str(), recordType, DNS_QUERY_STANDARD, nullptr, &records, nullptr);
    if (status != ERROR_SUCCESS) {
        if (records != nullptr) {
            ::DnsFree(records, DnsFreeRecordList);
        }
        result.text = L"DNS 查询 " + request.target + L"（" + DnsTypeText(recordType) + L"）失败：" +
            FormatWin32Error(static_cast<std::uint32_t>(status)) + L"。";
        result.summary = L"DNS 查询失败。";
        return result;
    }

    AppendLine(result.text, L"DNS 查询：" + request.target + L"，记录类型 " + DnsTypeText(recordType));
    AppendLine(result.text, L"");
    std::size_t count = 0;
    for (const DNS_RECORDW* cursor = records; cursor != nullptr; cursor = cursor->pNext) {
        ++count;
        AppendLine(result.text, DnsTypeText(cursor->wType) + L"\t" + SafeName(cursor->pName) +
            L"\tTTL=" + std::to_wstring(cursor->dwTtl) + L"\t" + DnsRecordValueText(*cursor));
    }
    ::DnsFree(records, DnsFreeRecordList);

    AppendLine(result.text, L"");
    AppendLine(result.text, L"共 " + std::to_wstring(count) + L" 条记录。");
    result.success = count != 0;
    result.summary = L"DNS 查询 " + request.target + L" 返回 " + std::to_wstring(count) + L" 条记录。";
    return result;
}

// DnsRecordTypeChoice pairs one combo label with its DNS_TYPE_* value. The two
// are declared together so adding a record type cannot leave the label list and
// the value list out of step.
struct DnsRecordTypeChoice final {
    const wchar_t* label;
    WORD value;
};

constexpr DnsRecordTypeChoice kDnsRecordTypeChoices[] = {
    { L"A", DNS_TYPE_A },
    { L"AAAA", DNS_TYPE_AAAA },
    { L"CNAME", DNS_TYPE_CNAME },
    { L"MX", DNS_TYPE_MX },
    { L"NS", DNS_TYPE_NS },
    { L"TXT", DNS_TYPE_TEXT },
    { L"PTR", DNS_TYPE_PTR },
    { L"SOA", DNS_TYPE_SOA },
    { L"SRV", DNS_TYPE_SRV },
    { L"ANY", DNS_TYPE_ANY },
};

} // namespace

int DnsRecordTypeChoiceCount() {
    return static_cast<int>(std::size(kDnsRecordTypeChoices));
}

const wchar_t* DnsRecordTypeChoiceLabel(const int index) {
    if (index < 0 || index >= DnsRecordTypeChoiceCount()) {
        return L"A";
    }
    return kDnsRecordTypeChoices[static_cast<std::size_t>(index)].label;
}

std::uint16_t DnsRecordTypeChoiceValue(const int index) {
    if (index < 0 || index >= DnsRecordTypeChoiceCount()) {
        return static_cast<std::uint16_t>(DNS_TYPE_A);
    }
    return static_cast<std::uint16_t>(kDnsRecordTypeChoices[static_cast<std::size_t>(index)].value);
}

DiagnosticResult RunDiagnostic(const DiagnosticRequest& request) {
    switch (request.kind) {
    case DiagnosticKind::Ping:
        return RunPing(request);
    case DiagnosticKind::TraceRoute:
        return RunTraceRoute(request);
    case DiagnosticKind::DnsLookup:
        return RunDnsLookup(request);
    }
    DiagnosticResult result{};
    result.text = L"未知的网络诊断类型。";
    result.summary = result.text;
    return result;
}

} // namespace Ksword::Features::NetTools
