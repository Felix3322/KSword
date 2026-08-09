#include "NetToolsActions.h"

#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>

#include <string>

#pragma comment(lib, "Iphlpapi.lib")

namespace Ksword::Features::NetTools {
namespace {

std::wstring DescribeEntry(const ConnectionEntry& entry) {
    return entry.localAddress + L":" + std::to_wstring(entry.localPort) + L" -> " +
        entry.remoteAddress + L":" + std::to_wstring(entry.remotePort);
}

} // namespace

NetToolsActionResult CloseTcpConnection(const ConnectionEntry& entry) {
    NetToolsActionResult result{};
    if (!ConnectionCanClose(entry)) {
        result.message = L"该连接不支持结束：SetTcpEntry 只能删除 IPv4 TCP 已连接状态的 TCB。";
        return result;
    }

    MIB_TCPROW row{};
    // The tuple is copied back exactly as the table reported it. Re-deriving the
    // addresses from the display text would go through two conversions and any
    // rounding of a scope or a leading zero would silently target a different
    // connection than the one on screen.
    row.dwState = MIB_TCP_STATE_DELETE_TCB;
    row.dwLocalAddr = static_cast<DWORD>(entry.rawLocalAddress);
    row.dwLocalPort = static_cast<DWORD>(entry.rawLocalPort);
    row.dwRemoteAddr = static_cast<DWORD>(entry.rawRemoteAddress);
    row.dwRemotePort = static_cast<DWORD>(entry.rawRemotePort);

    const DWORD status = ::SetTcpEntry(&row);
    if (status == NO_ERROR) {
        result.success = true;
        result.message = L"已结束连接 " + DescribeEntry(entry) + L"。";
        return result;
    }
    if (status == ERROR_ACCESS_DENIED) {
        result.message = L"结束连接 " + DescribeEntry(entry) +
            L" 失败：需要管理员权限，请以管理员身份重新运行。";
        return result;
    }
    if (status == ERROR_MR_MID_NOT_FOUND) {
        // The stack returns this when the tuple no longer matches a live TCB,
        // which usually means the connection already closed between the snapshot
        // and the click rather than that anything went wrong.
        result.message = L"结束连接 " + DescribeEntry(entry) +
            L" 失败：该连接已不存在，请刷新后重试。";
        return result;
    }
    result.message = L"结束连接 " + DescribeEntry(entry) + L" 失败：" + FormatWin32Error(status) + L"。";
    return result;
}

} // namespace Ksword::Features::NetTools
