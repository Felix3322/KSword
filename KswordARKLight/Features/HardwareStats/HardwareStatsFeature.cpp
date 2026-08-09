#include "HardwareStatsFeature.h"

#include "BusDeviceView.h"
#include "DiskActivityView.h"
#include "PerformanceView.h"
#include "UsbTopologyView.h"
#include "../../Ui/Controls.h"
#include "../../Ui/TabUtil.h"
#include "../../Ui/Theme.h"

#include <commctrl.h>

#include <algorithm>
#include <cstring>
#include <string>

namespace Ksword::Features::HardwareStats {
namespace {

constexpr wchar_t kHardwareStatsFeatureClass[] = L"KswordARKLight.HardwareStatsFeaturePage";

constexpr int kRefreshButtonId = 66001;
constexpr int kExportButtonId = 66002;
constexpr int kTabControlId = 66003;
constexpr int kStatusTextId = 66004;

constexpr int kPerformanceTabIndex = 0;
constexpr int kDiskTabIndex = 1;
constexpr int kUsbTabIndex = 2;
constexpr int kBusTabIndex = 3;

constexpr int kMargin = 8;
constexpr int kToolbarHeight = 30;
constexpr int kButtonWidth = 88;
constexpr int kButtonGap = 6;

// HardwareStatsPageState owns the root page HWND and its four sub-views. Inputs
// arrive through Win32 messages; processing switches visibility on tab change
// and forwards refresh/export to the active sub-view; every child HWND stays
// alive for the lifetime of this dock page so a tab switch never restarts a
// running enumeration.
struct HardwareStatsPageState {
    HWND hwnd = nullptr;
    HWND refreshButton = nullptr;
    HWND exportButton = nullptr;
    HWND statusText = nullptr;
    HWND tab = nullptr;
    HWND performanceView = nullptr;
    HWND diskView = nullptr;
    HWND usbView = nullptr;
    HWND busView = nullptr;
    int currentTab = kPerformanceTabIndex;
};

HardwareStatsPageState* StateFromWindow(HWND hwnd) {
    return reinterpret_cast<HardwareStatsPageState*>(::GetWindowLongPtrW(hwnd, GWLP_USERDATA));
}

int Width(const RECT& rc) {
    return rc.right > rc.left ? static_cast<int>(rc.right - rc.left) : 0;
}

int Height(const RECT& rc) {
    return rc.bottom > rc.top ? static_cast<int>(rc.bottom - rc.top) : 0;
}

void SetStatus(HardwareStatsPageState& state, const std::wstring& text) {
    if (state.statusText) {
        ::SetWindowTextW(state.statusText, text.c_str());
    }
}

// ShowChildPages toggles visibility only. Hiding rather than destroying matters
// here because the two sampling tabs stop collecting while hidden but keep their
// PDH query warm, so returning to a tab shows data on the next tick instead of
// paying the query-open cost again.
void ShowChildPages(HardwareStatsPageState& state) {
    const HWND views[] = { state.performanceView, state.diskView, state.usbView, state.busView };
    for (int index = 0; index < static_cast<int>(std::size(views)); ++index) {
        if (views[index]) {
            ::ShowWindow(views[index], state.currentTab == index ? SW_SHOW : SW_HIDE);
        }
    }
}

void LayoutChildren(HardwareStatsPageState& state) {
    if (!state.hwnd) {
        return;
    }

    RECT rc{};
    ::GetClientRect(state.hwnd, &rc);
    const int width = Width(rc);
    const int height = Height(rc);

    if (state.refreshButton) {
        ::MoveWindow(state.refreshButton, kMargin, kMargin, kButtonWidth, 24, TRUE);
    }
    if (state.exportButton) {
        ::MoveWindow(state.exportButton, kMargin + kButtonWidth + kButtonGap, kMargin, kButtonWidth, 24, TRUE);
    }
    if (state.statusText) {
        ::MoveWindow(state.statusText,
            kMargin + (kButtonWidth + kButtonGap) * 2 + 16,
            kMargin + 2,
            (std::max)(80, width - (kButtonWidth + kButtonGap) * 2 - kMargin * 2 - 16),
            20,
            TRUE);
    }

    const int tabTop = kMargin + kToolbarHeight;
    if (state.tab) {
        ::MoveWindow(state.tab, kMargin, tabTop,
            (std::max)(100, width - kMargin * 2),
            (std::max)(100, height - tabTop - kMargin), TRUE);

        RECT tabRc{};
        ::GetClientRect(state.tab, &tabRc);
        TabCtrl_AdjustRect(state.tab, FALSE, &tabRc);
        const HWND views[] = { state.performanceView, state.diskView, state.usbView, state.busView };
        for (HWND child : views) {
            if (child) {
                ::MoveWindow(child, tabRc.left, tabRc.top, Width(tabRc), Height(tabRc), TRUE);
            }
        }
    }
    ShowChildPages(state);
}

void RefreshCurrentTab(HardwareStatsPageState& state) {
    switch (state.currentTab) {
    case kUsbTabIndex:
        RefreshUsbTopologyView(state.usbView);
        SetStatus(state, L"正在重新枚举 USB 设备树…");
        break;
    case kBusTabIndex:
        RefreshBusDeviceView(state.busView);
        SetStatus(state, L"正在重新枚举总线设备…");
        break;
    default:
        // The sampling tabs own their own cadence; telling the user where the
        // control actually lives is better than silently doing nothing.
        SetStatus(state, L"该页按设定间隔自动采样，可用页内的“立即刷新”按钮取样一次。");
        break;
    }
}

void ExportCurrentTab(HardwareStatsPageState& state) {
    std::wstring tsv;
    switch (state.currentTab) {
    case kPerformanceTabIndex:
        tsv = ExportPerformanceViewTsv(state.performanceView);
        break;
    case kDiskTabIndex:
        tsv = ExportDiskActivityViewTsv(state.diskView);
        break;
    case kUsbTabIndex:
        tsv = ExportUsbTopologyViewTsv(state.usbView);
        break;
    case kBusTabIndex:
        tsv = ExportBusDeviceViewTsv(state.busView);
        break;
    default:
        break;
    }

    if (tsv.empty() || !::OpenClipboard(state.hwnd)) {
        SetStatus(state, L"TSV 导出失败：剪贴板不可用或当前没有可导出的内容。");
        return;
    }
    ::EmptyClipboard();
    const SIZE_T bytes = (tsv.size() + 1) * sizeof(wchar_t);
    HGLOBAL memory = ::GlobalAlloc(GMEM_MOVEABLE, bytes);
    if (!memory) {
        ::CloseClipboard();
        SetStatus(state, L"TSV 导出失败：无法分配剪贴板内存。");
        return;
    }
    void* target = ::GlobalLock(memory);
    if (!target) {
        ::GlobalFree(memory);
        ::CloseClipboard();
        SetStatus(state, L"TSV 导出失败：无法锁定剪贴板内存。");
        return;
    }
    std::memcpy(target, tsv.c_str(), bytes);
    ::GlobalUnlock(memory);
    if (!::SetClipboardData(CF_UNICODETEXT, memory)) {
        ::GlobalFree(memory);
        ::CloseClipboard();
        SetStatus(state, L"TSV 导出失败：写入剪贴板被拒绝。");
        return;
    }
    ::CloseClipboard();
    SetStatus(state, L"已将当前表格导出为 TSV 并复制到剪贴板。");
}

bool CreateChildControls(HardwareStatsPageState& state) {
    state.refreshButton = Ksword::Ui::CreateButton(state.hwnd, kRefreshButtonId, L"刷新当前页", 0, 0, 0, 0);
    state.exportButton = Ksword::Ui::CreateButton(state.hwnd, kExportButtonId, L"导出 TSV", 0, 0, 0, 0);
    state.statusText = Ksword::Ui::CreateText(state.hwnd, kStatusTextId, L"硬件扩展信息已就绪。", 0, 0, 0, 0);
    state.tab = Ksword::Ui::CreateTabControl(state.hwnd, kTabControlId, 0, 0, 0, 0);
    if (!state.refreshButton || !state.exportButton || !state.statusText || !state.tab) {
        return false;
    }

    Ksword::Ui::AddTabPages(state.tab, {
        { L"性能监控" },
        { L"磁盘活动" },
        { L"USB 拓扑" },
        { L"系统总线" },
    });
    ::SendMessageW(state.tab, TCM_SETCURSEL, static_cast<WPARAM>(kPerformanceTabIndex), 0);
    state.currentTab = kPerformanceTabIndex;

    RECT pageRect{ 0, 0, 100, 100 };
    ::GetClientRect(state.tab, &pageRect);
    TabCtrl_AdjustRect(state.tab, FALSE, &pageRect);
    const RECT childBounds{ 0, 0,
        (std::max)(1, Width(pageRect)),
        (std::max)(1, Height(pageRect)) };

    state.performanceView = CreatePerformanceView(state.tab, childBounds);
    state.diskView = CreateDiskActivityView(state.tab, childBounds);
    state.usbView = CreateUsbTopologyView(state.tab, childBounds);
    state.busView = CreateBusDeviceView(state.tab, childBounds);
    if (!state.performanceView || !state.diskView || !state.usbView || !state.busView) {
        return false;
    }

    Ksword::Ui::SetWindowFontRecursive(state.hwnd);
    return true;
}

LRESULT CALLBACK HardwareStatsPageProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    auto* state = StateFromWindow(hwnd);
    if (msg == WM_NCCREATE) {
        auto* create = reinterpret_cast<CREATESTRUCTW*>(lParam);
        state = create ? static_cast<HardwareStatsPageState*>(create->lpCreateParams) : nullptr;
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
    case WM_COMMAND:
        if (state && HIWORD(wParam) == BN_CLICKED) {
            switch (LOWORD(wParam)) {
            case kRefreshButtonId:
                RefreshCurrentTab(*state);
                return 0;
            case kExportButtonId:
                ExportCurrentTab(*state);
                return 0;
            default:
                break;
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

bool RegisterHardwareStatsFeatureClass() {
    static bool registered = false;
    if (registered) {
        return true;
    }
    WNDCLASSW windowClass{};
    windowClass.lpfnWndProc = HardwareStatsPageProc;
    windowClass.hInstance = ::GetModuleHandleW(nullptr);
    windowClass.hCursor = ::LoadCursorW(nullptr, IDC_ARROW);
    windowClass.hbrBackground = Ksword::Ui::AppTheme().windowBrush();
    windowClass.lpszClassName = kHardwareStatsFeatureClass;
    registered = ::RegisterClassW(&windowClass) != 0 || ::GetLastError() == ERROR_CLASS_ALREADY_EXISTS;
    return registered;
}

} // namespace

HWND CreateHardwareStatsFeaturePage(HWND parent, const RECT& bounds) {
    if (!parent || !RegisterHardwareStatsFeatureClass()) {
        return nullptr;
    }

    auto* state = new HardwareStatsPageState();
    HWND hwnd = ::CreateWindowExW(
        0,
        kHardwareStatsFeatureClass,
        L"硬件扩展",
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

} // namespace Ksword::Features::HardwareStats
