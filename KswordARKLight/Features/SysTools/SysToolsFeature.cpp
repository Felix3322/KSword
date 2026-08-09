#include "SysToolsFeature.h"

#include "ContextMenuView.h"
#include "EventLogView.h"
#include "FileHolderView.h"
#include "SystemTimeView.h"
#include "../../Ui/Controls.h"
#include "../../Ui/TabUtil.h"
#include "../../Ui/Theme.h"

#include <commctrl.h>

#include <algorithm>
#include <array>
#include <vector>

namespace Ksword::Features::SysTools {
namespace {

constexpr wchar_t kSysToolsFeatureClass[] = L"KswordARKLight.SysToolsFeaturePage";

constexpr int kTabControlId = 67001;

constexpr int kFileHolderTabIndex = 0;
constexpr int kEventLogTabIndex = 1;
constexpr int kContextMenuTabIndex = 2;
constexpr int kSystemTimeTabIndex = 3;
constexpr int kTabCount = 4;

constexpr int kMargin = 8;

int Width(const RECT& rc) {
    return rc.right > rc.left ? static_cast<int>(rc.right - rc.left) : 0;
}

int Height(const RECT& rc) {
    return rc.bottom > rc.top ? static_cast<int>(rc.bottom - rc.top) : 0;
}

// SysToolsFeaturePageState owns the tab control and every subview HWND. The
// subviews are created once and only toggled afterwards: each of them owns
// background tasks and a scroll position, and recreating a page on every tab
// switch would restart the work and throw both away.
struct SysToolsFeaturePageState final {
    HWND hwnd = nullptr;
    HWND tab = nullptr;
    std::array<HWND, kTabCount> views{};
    int currentTab = kFileHolderTabIndex;
};

SysToolsFeaturePageState* StateFromWindow(HWND hwnd) {
    return reinterpret_cast<SysToolsFeaturePageState*>(::GetWindowLongPtrW(hwnd, GWLP_USERDATA));
}

void ShowChildPages(SysToolsFeaturePageState& state) {
    for (int index = 0; index < kTabCount; ++index) {
        if (state.views[static_cast<std::size_t>(index)]) {
            ::ShowWindow(state.views[static_cast<std::size_t>(index)],
                index == state.currentTab ? SW_SHOW : SW_HIDE);
        }
    }
}

void LayoutChildren(SysToolsFeaturePageState& state) {
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
    for (HWND view : state.views) {
        if (view) {
            ::MoveWindow(view, pageRect.left, pageRect.top, Width(pageRect), Height(pageRect), TRUE);
        }
    }
    ShowChildPages(state);
}

bool CreateChildControls(SysToolsFeaturePageState& state) {
    state.tab = Ksword::Ui::CreateTabControl(state.hwnd, kTabControlId, 0, 0, 0, 0);
    if (!state.tab) {
        return false;
    }

    Ksword::Ui::AddTabPage(state.tab, kFileHolderTabIndex, { L"文件占用" });
    Ksword::Ui::AddTabPage(state.tab, kEventLogTabIndex, { L"事件日志" });
    Ksword::Ui::AddTabPage(state.tab, kContextMenuTabIndex, { L"右键菜单" });
    Ksword::Ui::AddTabPage(state.tab, kSystemTimeTabIndex, { L"系统时间" });
    ::SendMessageW(state.tab, TCM_SETCURSEL, static_cast<WPARAM>(kFileHolderTabIndex), 0);
    state.currentTab = kFileHolderTabIndex;

    RECT pageRect{ 0, 0, 100, 100 };
    ::GetClientRect(state.tab, &pageRect);
    TabCtrl_AdjustRect(state.tab, FALSE, &pageRect);
    const RECT childBounds{ 0, 0, (std::max)(1, Width(pageRect)), (std::max)(1, Height(pageRect)) };

    state.views[static_cast<std::size_t>(kFileHolderTabIndex)] = CreateFileHolderView(state.tab, childBounds);
    state.views[static_cast<std::size_t>(kEventLogTabIndex)] = CreateEventLogView(state.tab, childBounds);
    state.views[static_cast<std::size_t>(kContextMenuTabIndex)] = CreateContextMenuView(state.tab, childBounds);
    state.views[static_cast<std::size_t>(kSystemTimeTabIndex)] = CreateSystemTimeView(state.tab, childBounds);
    for (HWND view : state.views) {
        if (!view) {
            return false;
        }
    }

    Ksword::Ui::SetWindowFontRecursive(state.hwnd);
    return true;
}

LRESULT CALLBACK SysToolsFeatureProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    SysToolsFeaturePageState* state = StateFromWindow(hwnd);
    if (msg == WM_NCCREATE) {
        auto* create = reinterpret_cast<CREATESTRUCTW*>(lParam);
        state = create ? static_cast<SysToolsFeaturePageState*>(create->lpCreateParams) : nullptr;
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
                if (selected >= 0 && selected < kTabCount) {
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
        // The subviews are children of the tab control and are destroyed by
        // Win32 along with it, so only the page state is released here.
        delete state;
        ::SetWindowLongPtrW(hwnd, GWLP_USERDATA, 0);
        return 0;
    default:
        break;
    }

    return ::DefWindowProcW(hwnd, msg, wParam, lParam);
}

bool RegisterSysToolsFeatureClass() {
    static bool registered = false;
    if (registered) {
        return true;
    }
    WNDCLASSW windowClass{};
    windowClass.lpfnWndProc = SysToolsFeatureProc;
    windowClass.hInstance = ::GetModuleHandleW(nullptr);
    windowClass.hCursor = ::LoadCursorW(nullptr, IDC_ARROW);
    windowClass.hbrBackground = Ksword::Ui::AppTheme().windowBrush();
    windowClass.lpszClassName = kSysToolsFeatureClass;
    if (::RegisterClassW(&windowClass) || ::GetLastError() == ERROR_CLASS_ALREADY_EXISTS) {
        registered = true;
    }
    return registered;
}

} // namespace

HWND CreateSysToolsFeaturePage(HWND parent, const RECT& bounds) {
    if (!parent || !RegisterSysToolsFeatureClass()) {
        return nullptr;
    }

    auto* state = new SysToolsFeaturePageState();
    HWND hwnd = ::CreateWindowExW(
        0,
        kSysToolsFeatureClass,
        L"系统工具",
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

} // namespace Ksword::Features::SysTools
