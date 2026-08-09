#include "NetToolsFeature.h"

#include "NetToolsConnectionView.h"
#include "NetToolsDiagnosticView.h"
#include "NetToolsFirewallView.h"
#include "../../Ui/Controls.h"
#include "../../Ui/TabUtil.h"
#include "../../Ui/Theme.h"

#include <commctrl.h>

#include <algorithm>

namespace Ksword::Features::NetTools {
namespace {

constexpr wchar_t kNetToolsFeatureClass[] = L"KswordARKLight.NetToolsFeaturePage";

constexpr int kTabControlId = 66401;
constexpr int kConnectionTabIndex = 0;
constexpr int kDiagnosticTabIndex = 1;
constexpr int kFirewallTabIndex = 2;

constexpr int kMargin = 6;

// NetToolsFeaturePageState owns the root page HWND and the three subviews. Each
// subview keeps its own async tasks and its own refresh button, so this host has
// no toolbar of its own: a shared "refresh" would mean something different on
// every tab.
struct NetToolsFeaturePageState final {
    HWND hwnd = nullptr;
    HWND tab = nullptr;
    HWND connectionView = nullptr;
    HWND diagnosticView = nullptr;
    HWND firewallView = nullptr;
    int currentTab = kConnectionTabIndex;
};

NetToolsFeaturePageState* StateFromWindow(HWND hwnd) {
    return reinterpret_cast<NetToolsFeaturePageState*>(::GetWindowLongPtrW(hwnd, GWLP_USERDATA));
}

int Width(const RECT& rc) {
    return rc.right > rc.left ? static_cast<int>(rc.right - rc.left) : 0;
}

int Height(const RECT& rc) {
    return rc.bottom > rc.top ? static_cast<int>(rc.bottom - rc.top) : 0;
}

// ShowChildPages toggles the selected subview while retaining every child HWND.
// The pages are never destroyed on a tab switch: the connection table and the
// firewall rule list are both expensive to rebuild, and a diagnostics run in
// flight would lose its output.
void ShowChildPages(NetToolsFeaturePageState& state) {
    if (state.connectionView) {
        ::ShowWindow(state.connectionView, state.currentTab == kConnectionTabIndex ? SW_SHOW : SW_HIDE);
    }
    if (state.diagnosticView) {
        ::ShowWindow(state.diagnosticView, state.currentTab == kDiagnosticTabIndex ? SW_SHOW : SW_HIDE);
    }
    if (state.firewallView) {
        ::ShowWindow(state.firewallView, state.currentTab == kFirewallTabIndex ? SW_SHOW : SW_HIDE);
    }
}

void LayoutChildren(NetToolsFeaturePageState& state) {
    if (!state.hwnd || !state.tab) {
        return;
    }

    RECT client{};
    ::GetClientRect(state.hwnd, &client);
    ::MoveWindow(state.tab, kMargin, kMargin,
        (std::max)(100, Width(client) - kMargin * 2),
        (std::max)(100, Height(client) - kMargin * 2), TRUE);

    RECT pageRect{};
    ::GetClientRect(state.tab, &pageRect);
    TabCtrl_AdjustRect(state.tab, FALSE, &pageRect);
    const HWND childViews[] = { state.connectionView, state.diagnosticView, state.firewallView };
    for (HWND child : childViews) {
        if (child) {
            ::MoveWindow(child, pageRect.left, pageRect.top, Width(pageRect), Height(pageRect), TRUE);
        }
    }
    ShowChildPages(state);
}

bool CreateChildControls(NetToolsFeaturePageState& state) {
    state.tab = Ksword::Ui::CreateTabControl(state.hwnd, kTabControlId, 0, 0, 0, 0);
    if (!state.tab) {
        return false;
    }

    Ksword::Ui::AddTabPage(state.tab, kConnectionTabIndex, { L"连接管理" });
    Ksword::Ui::AddTabPage(state.tab, kDiagnosticTabIndex, { L"网络诊断" });
    Ksword::Ui::AddTabPage(state.tab, kFirewallTabIndex, { L"防火墙规则" });
    ::SendMessageW(state.tab, TCM_SETCURSEL, static_cast<WPARAM>(kConnectionTabIndex), 0);
    state.currentTab = kConnectionTabIndex;

    RECT pageRect{ 0, 0, 100, 100 };
    ::GetClientRect(state.tab, &pageRect);
    TabCtrl_AdjustRect(state.tab, FALSE, &pageRect);
    const RECT childBounds{ 0, 0, (std::max)(1, Width(pageRect)), (std::max)(1, Height(pageRect)) };

    state.connectionView = CreateNetToolsConnectionView(state.tab, childBounds);
    state.diagnosticView = CreateNetToolsDiagnosticView(state.tab, childBounds);
    state.firewallView = CreateNetToolsFirewallView(state.tab, childBounds);
    if (!state.connectionView || !state.diagnosticView || !state.firewallView) {
        return false;
    }

    Ksword::Ui::SetWindowFontRecursive(state.hwnd);
    return true;
}

LRESULT CALLBACK NetToolsFeatureProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    NetToolsFeaturePageState* state = StateFromWindow(hwnd);
    if (msg == WM_NCCREATE) {
        auto* create = reinterpret_cast<CREATESTRUCTW*>(lParam);
        state = create ? static_cast<NetToolsFeaturePageState*>(create->lpCreateParams) : nullptr;
        if (state) {
            state->hwnd = hwnd;
            ::SetWindowLongPtrW(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(state));
        }
    }

    switch (msg) {
    case WM_CREATE:
        if (state) {
            if (!CreateChildControls(*state)) {
                delete state;
                ::SetWindowLongPtrW(hwnd, GWLP_USERDATA, 0);
                return -1;
            }
            LayoutChildren(*state);
        }
        return 0;
    case WM_SIZE:
        if (state) {
            LayoutChildren(*state);
        }
        return 0;
    case WM_NOTIFY:
        if (state) {
            const auto* header = reinterpret_cast<const NMHDR*>(lParam);
            if (header && header->idFrom == kTabControlId && header->code == TCN_SELCHANGE) {
                const LRESULT selected = ::SendMessageW(state->tab, TCM_GETCURSEL, 0, 0);
                if (selected >= 0) {
                    state->currentTab = static_cast<int>(selected);
                }
                ShowChildPages(*state);
                return 0;
            }
        }
        break;
    case WM_CTLCOLORSTATIC: {
        HDC dc = reinterpret_cast<HDC>(wParam);
        ::SetBkMode(dc, TRANSPARENT);
        ::SetTextColor(dc, Ksword::Ui::AppTheme().textColor);
        return reinterpret_cast<LRESULT>(Ksword::Ui::AppTheme().windowBrush());
    }
    case WM_NCDESTROY:
        delete state;
        ::SetWindowLongPtrW(hwnd, GWLP_USERDATA, 0);
        return 0;
    default:
        break;
    }

    return ::DefWindowProcW(hwnd, msg, wParam, lParam);
}

bool RegisterNetToolsFeatureClass() {
    static bool registered = false;
    if (registered) {
        return true;
    }

    WNDCLASSW windowClass{};
    windowClass.lpfnWndProc = NetToolsFeatureProc;
    windowClass.hInstance = ::GetModuleHandleW(nullptr);
    windowClass.hCursor = ::LoadCursorW(nullptr, IDC_ARROW);
    windowClass.hbrBackground = Ksword::Ui::AppTheme().windowBrush();
    windowClass.lpszClassName = kNetToolsFeatureClass;
    registered = ::RegisterClassW(&windowClass) != 0 || ::GetLastError() == ERROR_CLASS_ALREADY_EXISTS;
    return registered;
}

} // namespace

HWND CreateNetToolsFeaturePage(HWND parent, const RECT& bounds) {
    if (!parent || !RegisterNetToolsFeatureClass()) {
        return nullptr;
    }

    auto* state = new NetToolsFeaturePageState();
    HWND hwnd = ::CreateWindowExW(
        0,
        kNetToolsFeatureClass,
        L"网络工具",
        WS_CHILD | WS_VISIBLE | WS_CLIPCHILDREN | WS_CLIPSIBLINGS,
        bounds.left,
        bounds.top,
        bounds.right - bounds.left,
        bounds.bottom - bounds.top,
        parent,
        nullptr,
        ::GetModuleHandleW(nullptr),
        state);
    if (!hwnd) {
        delete state;
    }
    return hwnd;
}

} // namespace Ksword::Features::NetTools
