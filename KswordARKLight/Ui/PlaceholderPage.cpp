#include "PlaceholderPage.h"

#include "Controls.h"
#include "Theme.h"

#include <algorithm>

namespace Ksword::Ui {
namespace {
constexpr wchar_t kPlaceholderClass[] = L"KswordARKLight.PlaceholderPage";

// kProgressBarWidth / kProgressBarHeight describe the loading bar drawn under
// the status line. It is a fixed width rather than a stretched one because a
// bar spanning a wide dock reads as a layout artifact instead of as progress.
constexpr int kProgressBarWidth = 260;
constexpr int kProgressBarHeight = 6;

struct PlaceholderState final {
    std::wstring title;
    std::wstring summary;
    std::wstring status;
    bool loading = false;
    int progressPercent = 0;
};

LRESULT CALLBACK PlaceholderPageProc(HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam) {
    auto* state = reinterpret_cast<PlaceholderState*>(::GetWindowLongPtrW(hwnd, GWLP_USERDATA));
    switch (message) {
    case WM_NCCREATE: {
        const auto* create = reinterpret_cast<const CREATESTRUCTW*>(lParam);
        state = static_cast<PlaceholderState*>(create->lpCreateParams);
        ::SetWindowLongPtrW(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(state));
        return TRUE;
    }
    case WM_ERASEBKGND:
        return 1;
    case WM_PAINT: {
        PAINTSTRUCT paint{};
        HDC dc = ::BeginPaint(hwnd, &paint);
        RECT rect{};
        ::GetClientRect(hwnd, &rect);
        ::FillRect(dc, &rect, AppTheme().windowBrush());

        const std::wstring title = state ? state->title : L"KswordARKLight";
        const std::wstring status = state && !state->status.empty()
            ? state->status
            : (state && state->loading ? L"正在加载页面…" : L"选择此页面后开始加载。");
        const std::wstring summary = state ? state->summary : L"";
        RECT titleRect{ rect.left + 28, rect.top + 28, rect.right - 28, rect.top + 58 };
        RECT statusRect{ rect.left + 28, rect.top + 66, rect.right - 28, rect.top + 92 };
        // The bar's slot is reserved whether or not it is drawn, so the summary
        // text does not jump down the moment loading starts.
        const LONG progressTop = rect.top + 100;
        RECT summaryRect{ rect.left + 28, progressTop + kProgressBarHeight + 12, rect.right - 28, rect.bottom - 28 };
        DrawTextLine(dc, title, titleRect, AppTheme().textColor, SystemUIFont(), DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS);
        DrawTextLine(dc, status, statusRect, state && state->loading ? AppTheme().accentColor : AppTheme().mutedTextColor,
            SystemUIFont(), DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS);

        // A zero percentage draws nothing at all -- not even the empty slot --
        // so an idle or failed page shows no bar rather than an empty one that
        // would suggest loading is still under way.
        const int progressPercent = state ? std::clamp(state->progressPercent, 0, 100) : 0;
        if (progressPercent > 0) {
            RECT trackRect{
                rect.left + 28,
                progressTop,
                std::min<LONG>(rect.left + 28 + kProgressBarWidth, rect.right - 28),
                progressTop + kProgressBarHeight
            };
            if (trackRect.right > trackRect.left) {
                HBRUSH trackBrush = ::CreateSolidBrush(AppTheme().borderColor);
                if (trackBrush) {
                    ::FillRect(dc, &trackRect, trackBrush);
                    ::DeleteObject(trackBrush);
                }
                RECT fillRect = trackRect;
                fillRect.right = trackRect.left +
                    ::MulDiv(trackRect.right - trackRect.left, progressPercent, 100);
                if (fillRect.right > fillRect.left) {
                    ::FillRect(dc, &fillRect, AppTheme().accentBrush());
                }
            }
        }

        DrawTextLine(dc, summary, summaryRect, AppTheme().mutedTextColor, SystemUIFont(), DT_LEFT | DT_TOP | DT_WORDBREAK | DT_END_ELLIPSIS);
        ::EndPaint(hwnd, &paint);
        return 0;
    }
    case WM_NCDESTROY:
        delete state;
        ::SetWindowLongPtrW(hwnd, GWLP_USERDATA, 0);
        return 0;
    default:
        break;
    }
    return ::DefWindowProcW(hwnd, message, wParam, lParam);
}

void EnsureClass() {
    static bool registered = false;
    if (registered) {
        return;
    }
    WNDCLASSW wc{};
    wc.lpfnWndProc = PlaceholderPageProc;
    wc.hInstance = ::GetModuleHandleW(nullptr);
    wc.hCursor = ::LoadCursorW(nullptr, IDC_ARROW);
    wc.hbrBackground = AppTheme().windowBrush();
    wc.lpszClassName = kPlaceholderClass;
    ::RegisterClassW(&wc);
    registered = true;
}
} // namespace

HWND CreatePlaceholderPage(HWND parent, const ModuleDescriptor& descriptor, const RECT& bounds) {
    EnsureClass();
    auto* state = new PlaceholderState{ descriptor.title, descriptor.summary, L"选择此页面后开始加载。", false, 0 };
    HWND page = ::CreateWindowExW(0, kPlaceholderClass, descriptor.title.c_str(), WS_CHILD | WS_VISIBLE | WS_CLIPCHILDREN,
        bounds.left, bounds.top, bounds.right - bounds.left, bounds.bottom - bounds.top,
        parent, nullptr, ::GetModuleHandleW(nullptr), state);
    if (!page) {
        delete state;
    }
    return page;
}

void UpdatePlaceholderPage(HWND page, const ModuleDescriptor& descriptor) {
    auto* state = page ? reinterpret_cast<PlaceholderState*>(::GetWindowLongPtrW(page, GWLP_USERDATA)) : nullptr;
    if (!page || !state) {
        return;
    }
    state->title = descriptor.title;
    state->summary = descriptor.summary;
    ::SetWindowTextW(page, descriptor.title.c_str());
    ::InvalidateRect(page, nullptr, TRUE);
}

void SetPlaceholderPageLoading(HWND page, const bool loading, const std::wstring& status) {
    auto* state = page ? reinterpret_cast<PlaceholderState*>(::GetWindowLongPtrW(page, GWLP_USERDATA)) : nullptr;
    if (!page || !state) {
        return;
    }
    state->loading = loading;
    state->status = status.empty() ? (loading ? L"正在加载页面…" : L"选择此页面后开始加载。") : status;
    state->progressPercent = 0;
    ::InvalidateRect(page, nullptr, TRUE);
}

void SetPlaceholderPageProgress(HWND page, const std::wstring& status, const int progressPercent) {
    auto* state = page ? reinterpret_cast<PlaceholderState*>(::GetWindowLongPtrW(page, GWLP_USERDATA)) : nullptr;
    if (!page || !state) {
        return;
    }
    const int clampedPercent = std::clamp(progressPercent, 0, 100);
    state->progressPercent = clampedPercent;
    state->loading = clampedPercent > 0;
    if (!status.empty()) {
        state->status = status;
    } else if (clampedPercent == 0) {
        state->status = L"选择此页面后开始加载。";
    }
    ::InvalidateRect(page, nullptr, TRUE);
    // Only a visible placeholder is worth painting synchronously; once the real
    // page is mounted this HWND is already gone from the dock.
    if (::IsWindowVisible(page)) {
        ::UpdateWindow(page);
    }
}

} // namespace Ksword::Ui
