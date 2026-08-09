#include "WindowToolsFeature.h"

#include "WindowToolsCaptureView.h"
#include "WindowToolsClipboardView.h"
#include "WindowToolsHierarchyView.h"
#include "WindowToolsHotkeyView.h"
#include "../../Ui/Controls.h"
#include "../../Ui/TabUtil.h"
#include "../../Ui/Theme.h"

#include <commctrl.h>

#include <algorithm>

namespace Ksword::Features::WindowTools {
namespace {

constexpr wchar_t kWindowToolsFeatureClass[] = L"KswordARKLight.WindowToolsFeaturePage";

constexpr int kTabControlId = 67401;

constexpr int kClipboardTabIndex = 0;
constexpr int kCaptureTabIndex = 1;
constexpr int kHierarchyTabIndex = 2;
constexpr int kHotkeyTabIndex = 3;

constexpr int kGap = 6;

// WindowToolsFeaturePageState owns the tab control and the four child pages.
// There is no shared toolbar here on purpose: each tab has a different refresh
// cost and a different set of actions -- one is synchronous, two enumerate in
// the background, and one must never run without being asked -- so a single
// "refresh" button at the top would mean four different things.
struct WindowToolsFeaturePageState final {
    HWND hwnd = nullptr;
    HWND tab = nullptr;
    HWND clipboardView = nullptr;
    HWND captureView = nullptr;
    HWND hierarchyView = nullptr;
    HWND hotkeyView = nullptr;
    int currentTab = kClipboardTabIndex;
};

WindowToolsFeaturePageState* StateFromWindow(HWND hwnd) {
    return reinterpret_cast<WindowToolsFeaturePageState*>(::GetWindowLongPtrW(hwnd, GWLP_USERDATA));
}

int Width(const RECT& rc) {
    return rc.right > rc.left ? static_cast<int>(rc.right - rc.left) : 0;
}

int Height(const RECT& rc) {
    return rc.bottom > rc.top ? static_cast<int>(rc.bottom - rc.top) : 0;
}

// ShowChildPages toggles visibility only. Every child page keeps its snapshot,
// scroll position and selection while it is hidden, so switching tabs never
// costs a re-enumeration -- and in the hotkey tab's case, never silently
// re-runs a probe that has side effects.
void ShowChildPages(WindowToolsFeaturePageState& state) {
    const HWND pages[] = { state.clipboardView, state.captureView, state.hierarchyView, state.hotkeyView };
    for (int index = 0; index < static_cast<int>(sizeof(pages) / sizeof(pages[0])); ++index) {
        if (pages[index]) {
            ::ShowWindow(pages[index], state.currentTab == index ? SW_SHOW : SW_HIDE);
        }
    }
}

void LayoutChildren(WindowToolsFeaturePageState& state) {
    if (!state.hwnd || !state.tab) {
        return;
    }

    RECT client{};
    ::GetClientRect(state.hwnd, &client);
    ::MoveWindow(state.tab, kGap, kGap,
        (std::max)(100, Width(client) - kGap * 2),
        (std::max)(100, Height(client) - kGap * 2), TRUE);

    RECT pageRect{};
    ::GetClientRect(state.tab, &pageRect);
    TabCtrl_AdjustRect(state.tab, FALSE, &pageRect);

    const HWND pages[] = { state.clipboardView, state.captureView, state.hierarchyView, state.hotkeyView };
    for (HWND page : pages) {
        if (page) {
            ::MoveWindow(page, pageRect.left, pageRect.top, Width(pageRect), Height(pageRect), TRUE);
        }
    }
    ShowChildPages(state);
}

bool CreateChildControls(WindowToolsFeaturePageState& state) {
    state.tab = Ksword::Ui::CreateTabControl(state.hwnd, kTabControlId, 0, 0, 0, 0);
    if (!state.tab) {
        return false;
    }

    Ksword::Ui::AddTabPage(state.tab, kClipboardTabIndex, { L"剪贴板查看" });
    Ksword::Ui::AddTabPage(state.tab, kCaptureTabIndex, { L"窗口捕获保护" });
    Ksword::Ui::AddTabPage(state.tab, kHierarchyTabIndex, { L"窗口层级诊断" });
    Ksword::Ui::AddTabPage(state.tab, kHotkeyTabIndex, { L"热键占用探测" });
    ::SendMessageW(state.tab, TCM_SETCURSEL, static_cast<WPARAM>(kClipboardTabIndex), 0);
    state.currentTab = kClipboardTabIndex;

    RECT pageRect{ 0, 0, 100, 100 };
    ::GetClientRect(state.tab, &pageRect);
    TabCtrl_AdjustRect(state.tab, FALSE, &pageRect);
    const RECT childBounds{ 0, 0,
        (std::max)(1, Width(pageRect)),
        (std::max)(1, Height(pageRect)) };

    state.clipboardView = CreateClipboardInspectorView(state.tab, childBounds);
    state.captureView = CreateCaptureProtectionView(state.tab, childBounds);
    state.hierarchyView = CreateWindowHierarchyView(state.tab, childBounds);
    state.hotkeyView = CreateHotkeyProbeView(state.tab, childBounds);
    if (!state.clipboardView || !state.captureView || !state.hierarchyView || !state.hotkeyView) {
        return false;
    }

    Ksword::Ui::SetWindowFontRecursive(state.hwnd);
    return true;
}

LRESULT CALLBACK WindowToolsFeatureProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    WindowToolsFeaturePageState* state = StateFromWindow(hwnd);
    if (msg == WM_NCCREATE) {
        auto* create = reinterpret_cast<CREATESTRUCTW*>(lParam);
        state = create ? static_cast<WindowToolsFeaturePageState*>(create->lpCreateParams) : nullptr;
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

bool RegisterWindowToolsFeatureClass() {
    static bool registered = false;
    if (registered) {
        return true;
    }

    WNDCLASSW windowClass{};
    windowClass.lpfnWndProc = WindowToolsFeatureProc;
    windowClass.hInstance = ::GetModuleHandleW(nullptr);
    windowClass.hCursor = ::LoadCursorW(nullptr, IDC_ARROW);
    windowClass.hbrBackground = Ksword::Ui::AppTheme().windowBrush();
    windowClass.lpszClassName = kWindowToolsFeatureClass;
    registered = ::RegisterClassW(&windowClass) != 0 || ::GetLastError() == ERROR_CLASS_ALREADY_EXISTS;
    return registered;
}

} // namespace

HWND CreateWindowToolsFeaturePage(HWND parent, const RECT& bounds) {
    if (!parent || !RegisterWindowToolsFeatureClass()) {
        return nullptr;
    }

    auto* state = new WindowToolsFeaturePageState();
    HWND hwnd = ::CreateWindowExW(
        0,
        kWindowToolsFeatureClass,
        L"窗口扩展",
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

} // namespace Ksword::Features::WindowTools
