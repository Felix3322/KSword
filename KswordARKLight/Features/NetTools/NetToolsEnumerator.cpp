#include "NetToolsEnumerator.h"

#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <objbase.h>
#include <oleauto.h>
#include <netfw.h>
#include <tlhelp32.h>

#include <algorithm>
#include <cstddef>
#include <unordered_map>
#include <utility>
#include <vector>

#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "Iphlpapi.lib")
#pragma comment(lib, "Ole32.lib")
#pragma comment(lib, "OleAut32.lib")

namespace Ksword::Features::NetTools {
namespace {

// kTableRetryLimit bounds the size/read retry loop. The connection tables change
// between the sizing call and the read whenever anything on the machine opens a
// socket, so one retry is normal and an endless loop is not.
constexpr int kTableRetryLimit = 8;

using ProcessNameMap = std::unordered_map<std::uint32_t, std::wstring>;

// BuildProcessNameMap snapshots every process image name once per refresh.
// Opening each owner process individually would cost one handle per connection
// row and still fail for protected processes; the toolhelp snapshot names them
// all in a single pass without any access rights.
ProcessNameMap BuildProcessNameMap() {
    ProcessNameMap names;
    HANDLE snapshot = ::CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        return names;
    }
    PROCESSENTRY32W entry{};
    entry.dwSize = sizeof(entry);
    if (::Process32FirstW(snapshot, &entry)) {
        do {
            names.emplace(static_cast<std::uint32_t>(entry.th32ProcessID), entry.szExeFile);
        } while (::Process32NextW(snapshot, &entry));
    }
    ::CloseHandle(snapshot);
    return names;
}

std::wstring ProcessNameFor(const ProcessNameMap& names, const std::uint32_t processId) {
    if (processId == 0) {
        return L"System Idle Process";
    }
    if (processId == 4) {
        return L"System";
    }
    const auto found = names.find(processId);
    return found == names.end() ? std::wstring{} : found->second;
}

// HostPort converts a table port field to host order. The tables report the port
// in network order inside a DWORD, so the upper half is padding and must not
// reach the conversion.
std::uint16_t HostPort(const DWORD tablePort) {
    return ::ntohs(static_cast<u_short>(tablePort & 0xFFFFu));
}

// FetchTable runs the two-call size/read protocol into a growable buffer. Input
// is a callable taking (buffer, &size); output is true when the final read
// succeeded, with the Win32 status left in lastError either way.
template <typename Fetch>
bool FetchTable(std::vector<unsigned char>& buffer, DWORD& lastError, Fetch fetch) {
    buffer.clear();
    DWORD size = 0;
    lastError = fetch(nullptr, &size);
    for (int attempt = 0; attempt < kTableRetryLimit && lastError == ERROR_INSUFFICIENT_BUFFER; ++attempt) {
        buffer.assign(static_cast<std::size_t>(size), 0);
        lastError = fetch(buffer.data(), &size);
    }
    if (lastError != NO_ERROR) {
        buffer.clear();
        return false;
    }
    return true;
}

void AppendDiagnostic(std::wstring& diagnostic, const wchar_t* tableName, const DWORD error) {
    if (!diagnostic.empty()) {
        diagnostic += L" ";
    }
    diagnostic += std::wstring(tableName) + L" 读取失败：" + FormatWin32Error(error) + L"。";
}

void CollectTcp4(std::vector<ConnectionEntry>& entries, const ProcessNameMap& names, std::wstring& diagnostic) {
    std::vector<unsigned char> buffer;
    DWORD error = NO_ERROR;
    if (!FetchTable(buffer, error, [](void* target, DWORD* size) {
            return ::GetExtendedTcpTable(target, size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
        })) {
        AppendDiagnostic(diagnostic, L"IPv4 TCP 表", error);
        return;
    }
    if (buffer.empty()) {
        return;
    }
    const auto* table = reinterpret_cast<const MIB_TCPTABLE_OWNER_PID*>(buffer.data());
    for (DWORD index = 0; index < table->dwNumEntries; ++index) {
        const MIB_TCPROW_OWNER_PID& row = table->table[index];
        ConnectionEntry entry{};
        entry.protocol = ConnectionProtocol::Tcp4;
        entry.localAddress = FormatIpv4Address(row.dwLocalAddr);
        entry.remoteAddress = FormatIpv4Address(row.dwRemoteAddr);
        entry.localPort = HostPort(row.dwLocalPort);
        entry.remotePort = HostPort(row.dwRemotePort);
        entry.state = row.dwState;
        entry.hasState = true;
        entry.processId = row.dwOwningPid;
        entry.processName = ProcessNameFor(names, entry.processId);
        entry.rawLocalAddress = row.dwLocalAddr;
        entry.rawRemoteAddress = row.dwRemoteAddr;
        entry.rawLocalPort = row.dwLocalPort;
        entry.rawRemotePort = row.dwRemotePort;
        entries.push_back(std::move(entry));
    }
}

void CollectTcp6(std::vector<ConnectionEntry>& entries, const ProcessNameMap& names, std::wstring& diagnostic) {
    std::vector<unsigned char> buffer;
    DWORD error = NO_ERROR;
    if (!FetchTable(buffer, error, [](void* target, DWORD* size) {
            return ::GetExtendedTcpTable(target, size, FALSE, AF_INET6, TCP_TABLE_OWNER_PID_ALL, 0);
        })) {
        AppendDiagnostic(diagnostic, L"IPv6 TCP 表", error);
        return;
    }
    if (buffer.empty()) {
        return;
    }
    const auto* table = reinterpret_cast<const MIB_TCP6TABLE_OWNER_PID*>(buffer.data());
    for (DWORD index = 0; index < table->dwNumEntries; ++index) {
        const MIB_TCP6ROW_OWNER_PID& row = table->table[index];
        ConnectionEntry entry{};
        entry.protocol = ConnectionProtocol::Tcp6;
        entry.localAddress = FormatIpv6Address(row.ucLocalAddr, row.dwLocalScopeId);
        entry.remoteAddress = FormatIpv6Address(row.ucRemoteAddr, row.dwRemoteScopeId);
        entry.localPort = HostPort(row.dwLocalPort);
        entry.remotePort = HostPort(row.dwRemotePort);
        entry.state = row.dwState;
        entry.hasState = true;
        entry.processId = row.dwOwningPid;
        entry.processName = ProcessNameFor(names, entry.processId);
        entries.push_back(std::move(entry));
    }
}

void CollectUdp4(std::vector<ConnectionEntry>& entries, const ProcessNameMap& names, std::wstring& diagnostic) {
    std::vector<unsigned char> buffer;
    DWORD error = NO_ERROR;
    if (!FetchTable(buffer, error, [](void* target, DWORD* size) {
            return ::GetExtendedUdpTable(target, size, FALSE, AF_INET, UDP_TABLE_OWNER_PID, 0);
        })) {
        AppendDiagnostic(diagnostic, L"IPv4 UDP 表", error);
        return;
    }
    if (buffer.empty()) {
        return;
    }
    const auto* table = reinterpret_cast<const MIB_UDPTABLE_OWNER_PID*>(buffer.data());
    for (DWORD index = 0; index < table->dwNumEntries; ++index) {
        const MIB_UDPROW_OWNER_PID& row = table->table[index];
        ConnectionEntry entry{};
        entry.protocol = ConnectionProtocol::Udp4;
        entry.localAddress = FormatIpv4Address(row.dwLocalAddr);
        entry.localPort = HostPort(row.dwLocalPort);
        entry.processId = row.dwOwningPid;
        entry.processName = ProcessNameFor(names, entry.processId);
        entry.rawLocalAddress = row.dwLocalAddr;
        entry.rawLocalPort = row.dwLocalPort;
        entries.push_back(std::move(entry));
    }
}

void CollectUdp6(std::vector<ConnectionEntry>& entries, const ProcessNameMap& names, std::wstring& diagnostic) {
    std::vector<unsigned char> buffer;
    DWORD error = NO_ERROR;
    if (!FetchTable(buffer, error, [](void* target, DWORD* size) {
            return ::GetExtendedUdpTable(target, size, FALSE, AF_INET6, UDP_TABLE_OWNER_PID, 0);
        })) {
        AppendDiagnostic(diagnostic, L"IPv6 UDP 表", error);
        return;
    }
    if (buffer.empty()) {
        return;
    }
    const auto* table = reinterpret_cast<const MIB_UDP6TABLE_OWNER_PID*>(buffer.data());
    for (DWORD index = 0; index < table->dwNumEntries; ++index) {
        const MIB_UDP6ROW_OWNER_PID& row = table->table[index];
        ConnectionEntry entry{};
        entry.protocol = ConnectionProtocol::Udp6;
        entry.localAddress = FormatIpv6Address(row.ucLocalAddr, row.dwLocalScopeId);
        entry.localPort = HostPort(row.dwLocalPort);
        entry.processId = row.dwOwningPid;
        entry.processName = ProcessNameFor(names, entry.processId);
        entries.push_back(std::move(entry));
    }
}

// ComHandle owns one COM interface pointer. It exists because the firewall walk
// has half a dozen early-exit paths and hand-written Release calls on each of
// them are exactly how leaks get in.
template <typename Interface>
class ComHandle final {
public:
    ComHandle() = default;

    ~ComHandle() {
        reset();
    }

    ComHandle(const ComHandle&) = delete;
    ComHandle& operator=(const ComHandle&) = delete;

    Interface** put() noexcept {
        reset();
        return &pointer_;
    }

    void** putVoid() noexcept {
        reset();
        return reinterpret_cast<void**>(&pointer_);
    }

    Interface* get() const noexcept {
        return pointer_;
    }

    Interface* operator->() const noexcept {
        return pointer_;
    }

    explicit operator bool() const noexcept {
        return pointer_ != nullptr;
    }

    void reset() noexcept {
        if (pointer_ != nullptr) {
            pointer_->Release();
            pointer_ = nullptr;
        }
    }

private:
    Interface* pointer_ = nullptr;
};

// TakeBstr copies an out-parameter BSTR into a std::wstring and frees it. The
// firewall interface hands out a fresh allocation for every string property, so
// every successful getter has to be paired with a SysFreeString.
std::wstring TakeBstr(BSTR value) {
    if (value == nullptr) {
        return {};
    }
    std::wstring text(value, ::SysStringLen(value));
    ::SysFreeString(value);
    return text;
}

std::wstring ReadStringProperty(HRESULT (STDMETHODCALLTYPE INetFwRule::*getter)(BSTR*), INetFwRule& rule) {
    BSTR value = nullptr;
    if (FAILED((rule.*getter)(&value))) {
        return {};
    }
    return TakeBstr(value);
}

std::wstring ProfileStateText(INetFwPolicy2& policy, const NET_FW_PROFILE_TYPE2 profile, const wchar_t* label) {
    VARIANT_BOOL enabled = VARIANT_FALSE;
    if (FAILED(policy.get_FirewallEnabled(profile, &enabled))) {
        return std::wstring(label) + L"=未知";
    }
    return std::wstring(label) + (enabled != VARIANT_FALSE ? L"=开启" : L"=关闭");
}

} // namespace

ConnectionEnumerationResult EnumerateConnections() {
    ConnectionEnumerationResult result{};
    EnsureWinsockInitialized();
    const ProcessNameMap names = BuildProcessNameMap();
    CollectTcp4(result.entries, names, result.diagnosticText);
    CollectTcp6(result.entries, names, result.diagnosticText);
    CollectUdp4(result.entries, names, result.diagnosticText);
    CollectUdp6(result.entries, names, result.diagnosticText);
    // Partial success is still success: the diagnostic names whichever table was
    // unreadable, and the rows that were read remain useful on their own.
    result.success = !result.entries.empty() || result.diagnosticText.empty();
    return result;
}

FirewallEnumerationResult EnumerateFirewallRules() {
    FirewallEnumerationResult result{};

    const HRESULT initialized = ::CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE);
    // RPC_E_CHANGED_MODE means someone already initialized this thread with the
    // other apartment model. The firewall proxy works either way, but the
    // uninitialize must not run in that case or it would unbalance their count.
    const bool ownsComInitialization = SUCCEEDED(initialized);
    if (FAILED(initialized) && initialized != RPC_E_CHANGED_MODE) {
        result.diagnosticText = L"COM 初始化失败：" + FormatWin32Error(static_cast<std::uint32_t>(initialized)) + L"。";
        return result;
    }

    {
        ComHandle<INetFwPolicy2> policy;
        HRESULT status = ::CoCreateInstance(
            __uuidof(NetFwPolicy2), nullptr, CLSCTX_INPROC_SERVER, __uuidof(INetFwPolicy2), policy.putVoid());
        if (FAILED(status) || !policy) {
            result.diagnosticText =
                L"无法创建防火墙策略对象（INetFwPolicy2）：" + FormatWin32Error(static_cast<std::uint32_t>(status)) +
                L"。该接口需要 Windows Defender Firewall 服务（MpsSvc）处于运行状态。";
        } else {
            result.profileSummary =
                ProfileStateText(*policy.get(), NET_FW_PROFILE2_DOMAIN, L"域") + L"，" +
                ProfileStateText(*policy.get(), NET_FW_PROFILE2_PRIVATE, L"专用") + L"，" +
                ProfileStateText(*policy.get(), NET_FW_PROFILE2_PUBLIC, L"公用");

            ComHandle<INetFwRules> rules;
            status = policy->get_Rules(rules.put());
            if (FAILED(status) || !rules) {
                result.diagnosticText =
                    L"无法读取防火墙规则集合：" + FormatWin32Error(static_cast<std::uint32_t>(status)) + L"。";
            } else {
                ComHandle<IUnknown> unknown;
                status = rules->get__NewEnum(unknown.put());
                ComHandle<IEnumVARIANT> enumerator;
                if (SUCCEEDED(status) && unknown) {
                    status = unknown->QueryInterface(__uuidof(IEnumVARIANT), enumerator.putVoid());
                }
                if (FAILED(status) || !enumerator) {
                    result.diagnosticText =
                        L"无法枚举防火墙规则：" + FormatWin32Error(static_cast<std::uint32_t>(status)) + L"。";
                } else {
                    VARIANT item{};
                    ::VariantInit(&item);
                    ULONG fetched = 0;
                    while (enumerator->Next(1, &item, &fetched) == S_OK && fetched == 1) {
                        if (item.vt == VT_DISPATCH && item.pdispVal != nullptr) {
                            ComHandle<INetFwRule> rule;
                            if (SUCCEEDED(item.pdispVal->QueryInterface(__uuidof(INetFwRule), rule.putVoid())) && rule) {
                                FirewallRuleEntry entry{};
                                entry.name = ReadStringProperty(&INetFwRule::get_Name, *rule.get());
                                entry.description = ReadStringProperty(&INetFwRule::get_Description, *rule.get());
                                entry.grouping = ReadStringProperty(&INetFwRule::get_Grouping, *rule.get());
                                entry.applicationName = ReadStringProperty(&INetFwRule::get_ApplicationName, *rule.get());
                                entry.serviceName = ReadStringProperty(&INetFwRule::get_ServiceName, *rule.get());
                                entry.localPorts = ReadStringProperty(&INetFwRule::get_LocalPorts, *rule.get());
                                entry.remotePorts = ReadStringProperty(&INetFwRule::get_RemotePorts, *rule.get());
                                entry.localAddresses = ReadStringProperty(&INetFwRule::get_LocalAddresses, *rule.get());
                                entry.remoteAddresses = ReadStringProperty(&INetFwRule::get_RemoteAddresses, *rule.get());
                                entry.interfaceTypes = ReadStringProperty(&INetFwRule::get_InterfaceTypes, *rule.get());

                                NET_FW_RULE_DIRECTION direction = NET_FW_RULE_DIR_IN;
                                if (SUCCEEDED(rule->get_Direction(&direction))) {
                                    entry.direction = static_cast<std::int32_t>(direction);
                                }
                                NET_FW_ACTION action = NET_FW_ACTION_BLOCK;
                                if (SUCCEEDED(rule->get_Action(&action))) {
                                    entry.action = static_cast<std::int32_t>(action);
                                }
                                LONG protocol = 0;
                                if (SUCCEEDED(rule->get_Protocol(&protocol))) {
                                    entry.protocol = static_cast<std::int32_t>(protocol);
                                }
                                long profiles = 0;
                                if (SUCCEEDED(rule->get_Profiles(&profiles))) {
                                    entry.profiles = static_cast<std::int32_t>(profiles);
                                }
                                VARIANT_BOOL enabled = VARIANT_FALSE;
                                if (SUCCEEDED(rule->get_Enabled(&enabled))) {
                                    entry.enabled = enabled != VARIANT_FALSE;
                                }
                                VARIANT_BOOL edgeTraversal = VARIANT_FALSE;
                                if (SUCCEEDED(rule->get_EdgeTraversal(&edgeTraversal))) {
                                    entry.edgeTraversal = edgeTraversal != VARIANT_FALSE;
                                }
                                result.entries.push_back(std::move(entry));
                            }
                        }
                        ::VariantClear(&item);
                        ::VariantInit(&item);
                        fetched = 0;
                    }
                    ::VariantClear(&item);
                    result.success = true;
                }
            }
        }
    }

    if (ownsComInitialization) {
        ::CoUninitialize();
    }
    return result;
}

} // namespace Ksword::Features::NetTools
