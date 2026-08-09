#include "SystemTimeView.h"

#include "SystemTimeInfo.h"
#include "../../Ui/AsyncTask.h"
#include "../../Ui/Controls.h"
#include "../../Ui/LoadingOverlay.h"
#include "../../Ui/TextFindSupport.h"
#include "../../Ui/Theme.h"

#include <commctrl.h>

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <memory>
#include <optional>
#include <string>
#include <utility>

namespace Ksword::Features::SysTools {
namespace {

constexpr wchar_t kSystemTimeViewClass[] = L"KswordARKLight.SysTools.SystemTimeView";

constexpr int kRefreshButtonId = 67401;
constexpr int kCopyButtonId = 67402;
constexpr int kClockTextId = 67403;
constexpr int kReportEditId = 67404;
constexpr int kLoadingOverlayId = 67405;

constexpr UINT kMsgCollectCompleted = WM_APP + 715;

// kClockTimerId drives the header line only. The full report is not re-rendered
// on the tick because it would fight the user's selection and the find bar in
// the report pane every single second.
constexpr UINT_PTR kClockTimerId = 1;
constexpr UINT kClockIntervalMs = 1000;

constexpr int kGap = 6;
constexpr int kRowHeight = 24;
constexpr int kHeaderHeight = kGap * 3 + kRowHeight * 2;
constexpr int kStatusHeight = 22;

int Width(const RECT& rc) {
    return rc.right > rc.left ? static_cast<int>(rc.right - rc.left) : 0;
}

int Height(const RECT& rc) {
    return rc.bottom > rc.top ? static_cast<int>(rc.bottom - rc.top) : 0;
}

struct SystemTimeViewState final {
    HWND hwnd = nullptr;
    HWND refreshButton = nullptr;
    HWND copyButton = nullptr;
    HWND clockText = nullptr;
    HWND reportEdit = nullptr;
    HWND loadingOverlay = nullptr;
    std::wstring reportText;
    std::wstring statusText = L"该页只读，不会修改系统时间或时间源配置。";
    std::unique_ptr<Ksword::Ui::AsyncSnapshotTask<SystemTimeInfoSnapshot>> collectTask;
};

bool CopyText(HWND owner, const std::wstring& text) {
    if (text.empty() || !::OpenClipboard(owner)) {
        return false;
    }
    ::EmptyClipboard();
    const SIZE_T bytes = (text.size() + 1) * sizeof(wchar_t);
    HGLOBAL memory = ::GlobalAlloc(GMEM_MOVEABLE, bytes);
    if (!memory) {
        ::CloseClipboard();
        return false;
    }
    void* target = ::GlobalLock(memory);
    if (!target) {
        ::GlobalFree(memory);
        ::CloseClipboard();
        return false;
    }
    std::memcpy(target, text.c_str(), bytes);
    ::GlobalUnlock(memory);
    if (!::SetClipboardData(CF_UNICODETEXT, memory)) {
        ::GlobalFree(memory);
        ::CloseClipboard();
        return false;
    }
    ::CloseClipboard();
    return true;
}

void UpdateClockLine(SystemTimeViewState& state) {
    if (state.clockText) {
        ::SetWindowTextW(state.clockText, FormatLiveClockLine().c_str());
    }
}

void BeginCollect(SystemTimeViewState& state) {
    if (!state.collectTask) {
        return;
    }
    if (state.refreshButton) {
        ::EnableWindow(state.refreshButton, FALSE);
    }
    Ksword::Ui::SetLoadingOverlay(state.loadingOverlay, true, L"正在读取时间与 W32Time 配置…");
    state.statusText = L"正在后台读取时区与 NTP 配置…";
    ::InvalidateRect(state.hwnd, nullptr, TRUE);

    state.collectTask->request(
        [] { return CollectSystemTimeInfo(); },
        [&state](std::uint64_t, std::optional<SystemTimeInfoSnapshot>&& snapshot, std::exception_ptr error) {
            if (state.refreshButton) {
                ::EnableWindow(state.refreshButton, TRUE);
            }
            Ksword::Ui::SetLoadingOverlay(state.loadingOverlay, false);
            if (error || !snapshot.has_value()) {
                state.statusText = L"系统时间信息读取异常结束。";
                ::InvalidateRect(state.hwnd, nullptr, TRUE);
                return;
            }
            state.reportText = RenderSystemTimeReport(*snapshot);
            if (state.reportEdit) {
                ::SetWindowTextW(state.reportEdit, state.reportText.c_str());
            }
            state.statusText = L"该页只读，不会修改系统时间或时间源配置。按 Ctrl+F 可在报告中查找。";
            UpdateClockLine(state);
            ::InvalidateRect(state.hwnd, nullptr, TRUE);
        });
}

void LayoutView(SystemTimeViewState& state) {
    RECT client{};
    ::GetClientRect(state.hwnd, &client);
    const int width = Width(client);
    const int height = Height(client);

    const int firstRowY = kGap;
    if (state.refreshButton) {
        ::MoveWindow(state.refreshButton, kGap, firstRowY, 64, kRowHeight, TRUE);
    }
    if (state.copyButton) {
        ::MoveWindow(state.copyButton, kGap * 2 + 64, firstRowY, 96, kRowHeight, TRUE);
    }

    const int secondRowY = firstRowY + kRowHeight + kGap;
    if (state.clockText) {
        ::MoveWindow(state.clockText, kGap, secondRowY + 2, (std::max)(120, width - kGap * 2), kRowHeight - 2, TRUE);
    }

    const int reportTop = kHeaderHeight;
    const int reportHeight = (std::max)(0, height - reportTop - kStatusHeight - kGap);
    if (state.reportEdit) {
        ::MoveWindow(state.reportEdit, kGap, reportTop, (std::max)(0, width - kGap * 2), reportHeight, TRUE);
    }
    if (state.loadingOverlay) {
        ::MoveWindow(state.loadingOverlay, kGap, reportTop, (std::max)(0, width - kGap * 2), reportHeight, TRUE);
    }
}

bool CreateChildControls(SystemTimeViewState& state) {
    HWND hwnd = state.hwnd;
    state.refreshButton = Ksword::Ui::CreateButton(hwnd, kRefreshButtonId, L"刷新", 0, 0, 0, 0);
    state.copyButton = Ksword::Ui::CreateButton(hwnd, kCopyButtonId, L"复制报告", 0, 0, 0, 0);
    state.clockText = Ksword::Ui::CreateText(hwnd, kClockTextId, L"", 0, 0, 0, 0);
    if (!state.refreshButton || !state.copyButton || !state.clockText) {
        return false;
    }

    state.reportEdit = ::CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"正在读取系统时间信息…",
        WS_CHILD | WS_VISIBLE | WS_TABSTOP | WS_VSCROLL | WS_HSCROLL |
            ES_MULTILINE | ES_AUTOVSCROLL | ES_AUTOHSCROLL | ES_READONLY,
        0, 0, 0, 0, hwnd, reinterpret_cast<HMENU>(static_cast<INT_PTR>(kReportEditId)),
        ::GetModuleHandleW(nullptr), nullptr);
    if (!state.reportEdit) {
        return false;
    }
    ::SendMessageW(state.reportEdit, WM_SETFONT, reinterpret_cast<WPARAM>(Ksword::Ui::SystemUIFont()), TRUE);
    // The W32Time parameter block alone can run to dozens of lines, so the pane
    // gets the shared Ctrl+F find bar instead of leaving the reader to scroll.
    Ksword::Ui::AttachTextFindSupport(state.reportEdit);

    state.loadingOverlay = Ksword::Ui::CreateLoadingOverlay(hwnd, kLoadingOverlayId, { 0, 0, 1, 1 });
    if (!state.loadingOverlay) {
        return false;
    }

    Ksword::Ui::SetWindowFontRecursive(hwnd);
    return true;
}

LRESULT CALLBACK SystemTimeViewProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    auto* state = reinterpret_cast<SystemTimeViewState*>(::GetWindowLongPtrW(hwnd, GWLP_USERDATA));
    switch (msg) {
    case WM_NCCREATE: {
        auto owned = std::make_unique<SystemTimeViewState>();
        owned->hwnd = hwnd;
        ::SetWindowLongPtrW(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(owned.release()));
        return TRUE;
    }
    case WM_CREATE:
        if (state) {
            if (!CreateChildControls(*state)) {
                return -1;
            }
            state->collectTask = std::make_unique<Ksword::Ui::AsyncSnapshotTask<SystemTimeInfoSnapshot>>(hwnd, kMsgCollectCompleted);
            LayoutView(*state);
            UpdateClockLine(*state);
            ::SetTimer(hwnd, kClockTimerId, kClockIntervalMs, nullptr);
            BeginCollect(*state);
        }
        return 0;
    case WM_SIZE:
        if (state) {
            LayoutView(*state);
        }
        return 0;
    case WM_TIMER:
        if (state && wParam == kClockTimerId) {
            UpdateClockLine(*state);
            return 0;
        }
        break;
    case WM_COMMAND:
        if (state && HIWORD(wParam) == BN_CLICKED) {
            switch (LOWORD(wParam)) {
            case kRefreshButtonId:
                BeginCollect(*state);
                return 0;
            case kCopyButtonId:
                state->statusText = CopyText(hwnd, state->reportText) ? L"已复制系统时间报告。" : L"复制失败。";
                ::InvalidateRect(hwnd, nullptr, TRUE);
                return 0;
            default:
                break;
            }
        }
        break;
    case WM_ERASEBKGND:
        return 1;
    case WM_PAINT:
        if (state) {
            PAINTSTRUCT paint{};
            HDC dc = ::BeginPaint(hwnd, &paint);
            RECT client{};
            ::GetClientRect(hwnd, &client);
            ::FillRect(dc, &client, Ksword::Ui::AppTheme().windowBrush());
            RECT statusRect{ kGap, client.bottom - kStatusHeight, client.right - kGap, client.bottom };
            Ksword::Ui::DrawTextLine(dc, state->statusText, statusRect,
                Ksword::Ui::AppTheme().mutedTextColor, Ksword::Ui::SystemUIFont(),
                DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS);
            ::EndPaint(hwnd, &paint);
            return 0;
        }
        break;
    case WM_CTLCOLORSTATIC: {
        HDC dc = reinterpret_cast<HDC>(wParam);
        ::SetBkMode(dc, TRANSPARENT);
        ::SetTextColor(dc, Ksword::Ui::AppTheme().textColor);
        return reinterpret_cast<LRESULT>(Ksword::Ui::AppTheme().windowBrush());
    }
    default:
        if (state && msg == kMsgCollectCompleted && state->collectTask) {
            state->collectTask->consume(hwnd, wParam, lParam);
            return 0;
        }
        if (msg == WM_NCDESTROY && state) {
            ::KillTimer(hwnd, kClockTimerId);
            if (state->collectTask) {
                state->collectTask->cancel();
            }
            delete state;
            ::SetWindowLongPtrW(hwnd, GWLP_USERDATA, 0);
        }
        break;
    }
    return ::DefWindowProcW(hwnd, msg, wParam, lParam);
}

bool EnsureSystemTimeViewClass() {
    static bool registered = false;
    if (registered) {
        return true;
    }
    WNDCLASSW windowClass{};
    windowClass.lpfnWndProc = SystemTimeViewProc;
    windowClass.hInstance = ::GetModuleHandleW(nullptr);
    windowClass.hCursor = ::LoadCursorW(nullptr, IDC_ARROW);
    windowClass.hbrBackground = Ksword::Ui::AppTheme().windowBrush();
    windowClass.lpszClassName = kSystemTimeViewClass;
    registered = ::RegisterClassW(&windowClass) != 0 || ::GetLastError() == ERROR_CLASS_ALREADY_EXISTS;
    return registered;
}

} // namespace

HWND CreateSystemTimeView(HWND parent, const RECT& bounds) {
    if (!parent || !EnsureSystemTimeViewClass()) {
        return nullptr;
    }
    return ::CreateWindowExW(
        0, kSystemTimeViewClass, L"", WS_CHILD | WS_VISIBLE | WS_CLIPCHILDREN,
        bounds.left, bounds.top, bounds.right - bounds.left, bounds.bottom - bounds.top,
        parent, nullptr, ::GetModuleHandleW(nullptr), nullptr);
}

} // namespace Ksword::Features::SysTools
