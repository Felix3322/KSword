#include "NetToolsDiagnosticView.h"

#include "NetToolsDiagnostics.h"
#include "../../Ui/AsyncTask.h"
#include "../../Ui/Controls.h"
#include "../../Ui/LoadingOverlay.h"
#include "../../Ui/TextFindSupport.h"
#include "../../Ui/Theme.h"

#include <commctrl.h>
#include <windowsx.h>

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <cwctype>
#include <memory>
#include <string>
#include <utility>
#include <vector>

namespace Ksword::Features::NetTools {
namespace {

constexpr wchar_t kDiagnosticViewClass[] = L"KswordARKLight.NetTools.DiagnosticView";

constexpr int kTargetLabelId = 66201;
constexpr int kTargetEditId = 66202;
constexpr int kPingButtonId = 66203;
constexpr int kTraceButtonId = 66204;
constexpr int kDnsButtonId = 66205;
constexpr int kDnsTypeComboId = 66206;
constexpr int kCopyButtonId = 66207;
constexpr int kClearButtonId = 66208;
constexpr int kOutputEditId = 66209;
constexpr int kLoadingOverlayId = 66210;

constexpr UINT kMsgDiagnosticCompleted = WM_APP + 675;

constexpr int kGap = 6;
constexpr int kRowHeight = 24;
constexpr int kHeaderHeight = kGap * 2 + kRowHeight;
constexpr int kStatusHeight = 22;

// kPingTimeoutMs and kTraceTimeoutMs bound the worst case a user can wait. The
// trace timeout is deliberately shorter: a ping waits four times, a trace waits
// once per hop, so the same value would turn an unreachable target into a
// minute-long run with no output.
constexpr std::uint32_t kPingTimeoutMs = 2000;
constexpr std::uint32_t kTraceTimeoutMs = 1500;
constexpr std::uint32_t kPingEchoCount = 4;
constexpr std::uint32_t kTraceMaxHops = 30;

int Width(const RECT& rc) {
    return rc.right > rc.left ? static_cast<int>(rc.right - rc.left) : 0;
}

int Height(const RECT& rc) {
    return rc.bottom > rc.top ? static_cast<int>(rc.bottom - rc.top) : 0;
}

struct DiagnosticViewState final {
    HWND hwnd = nullptr;
    HWND targetLabel = nullptr;
    HWND targetEdit = nullptr;
    HWND pingButton = nullptr;
    HWND traceButton = nullptr;
    HWND dnsButton = nullptr;
    HWND dnsTypeCombo = nullptr;
    HWND copyButton = nullptr;
    HWND clearButton = nullptr;
    HWND outputEdit = nullptr;
    HWND loadingOverlay = nullptr;
    std::wstring statusText = L"填写目标主机名或 IP 地址后选择一种探测方式。";
    bool probeInProgress = false;
    std::unique_ptr<Ksword::Ui::AsyncSnapshotTask<DiagnosticResult>> probeTask;
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

std::wstring WindowText(HWND control) {
    if (!control) {
        return {};
    }
    const int length = ::GetWindowTextLengthW(control);
    if (length <= 0) {
        return {};
    }
    std::wstring text(static_cast<std::size_t>(length) + 1, L'\0');
    const int copied = ::GetWindowTextW(control, text.data(), length + 1);
    text.resize(copied > 0 ? static_cast<std::size_t>(copied) : 0);
    return text;
}

std::wstring TrimText(std::wstring value) {
    const auto begin = std::find_if_not(value.begin(), value.end(), [](const wchar_t ch) { return std::iswspace(ch) != 0; });
    const auto end = std::find_if_not(value.rbegin(), value.rend(), [](const wchar_t ch) { return std::iswspace(ch) != 0; }).base();
    return begin >= end ? std::wstring{} : std::wstring(begin, end);
}

void UpdateActionButtons(DiagnosticViewState& state) {
    const BOOL enabled = state.probeInProgress ? FALSE : TRUE;
    for (HWND control : { state.pingButton, state.traceButton, state.dnsButton, state.dnsTypeCombo, state.targetEdit }) {
        if (control) {
            ::EnableWindow(control, enabled);
        }
    }
}

void SetOutputText(DiagnosticViewState& state, const std::wstring& text) {
    if (!state.outputEdit) {
        return;
    }
    ::SetWindowTextW(state.outputEdit, text.c_str());
    // Scroll back to the top: the interesting part of a ping or a trace is the
    // first line, and an EDIT keeps whatever caret position it had.
    ::SendMessageW(state.outputEdit, EM_SETSEL, 0, 0);
    ::SendMessageW(state.outputEdit, EM_SCROLLCARET, 0, 0);
}

void BeginProbe(DiagnosticViewState& state, const DiagnosticKind kind) {
    if (!state.probeTask) {
        return;
    }
    if (state.probeInProgress) {
        state.statusText = L"已有网络诊断正在执行，请等待其完成。";
        ::InvalidateRect(state.hwnd, nullptr, TRUE);
        return;
    }

    const std::wstring target = TrimText(WindowText(state.targetEdit));
    if (target.empty()) {
        state.statusText = L"请先填写目标主机名或 IP 地址。";
        ::InvalidateRect(state.hwnd, nullptr, TRUE);
        return;
    }

    DiagnosticRequest request{};
    request.kind = kind;
    request.target = target;
    switch (kind) {
    case DiagnosticKind::Ping:
        request.echoCount = kPingEchoCount;
        request.timeoutMs = kPingTimeoutMs;
        state.statusText = L"正在后台 Ping " + target + L"…";
        break;
    case DiagnosticKind::TraceRoute:
        request.maxHops = kTraceMaxHops;
        request.timeoutMs = kTraceTimeoutMs;
        state.statusText = L"正在后台跟踪到 " + target + L" 的路由，最多 " +
            std::to_wstring(kTraceMaxHops) + L" 跳…";
        break;
    case DiagnosticKind::DnsLookup: {
        const LRESULT selection = state.dnsTypeCombo ? ::SendMessageW(state.dnsTypeCombo, CB_GETCURSEL, 0, 0) : 0;
        const int choice = selection == CB_ERR ? 0 : static_cast<int>(selection);
        request.dnsRecordType = DnsRecordTypeChoiceValue(choice);
        state.statusText = std::wstring(L"正在后台查询 ") + target + L" 的 " +
            DnsRecordTypeChoiceLabel(choice) + L" 记录…";
        break;
    }
    }

    state.probeInProgress = true;
    UpdateActionButtons(state);
    Ksword::Ui::SetLoadingOverlay(state.loadingOverlay, true, L"正在执行网络诊断…");
    ::InvalidateRect(state.hwnd, nullptr, TRUE);
    state.probeTask->request(
        [request] { return RunDiagnostic(request); },
        [&state](std::uint64_t, std::optional<DiagnosticResult>&& result, std::exception_ptr error) {
            state.probeInProgress = false;
            Ksword::Ui::SetLoadingOverlay(state.loadingOverlay, false);
            UpdateActionButtons(state);
            if (error || !result.has_value()) {
                state.statusText = L"网络诊断异常结束。";
                ::InvalidateRect(state.hwnd, nullptr, TRUE);
                return;
            }
            SetOutputText(state, result->text);
            state.statusText = result->summary;
            ::InvalidateRect(state.hwnd, nullptr, TRUE);
        });
}

void LayoutView(DiagnosticViewState& state) {
    RECT client{};
    ::GetClientRect(state.hwnd, &client);
    const int width = Width(client);
    const int height = Height(client);

    const int rowY = kGap;
    int cursorX = kGap;
    const auto place = [&cursorX, rowY](HWND control, int controlWidth, int controlHeight) {
        if (control) {
            ::MoveWindow(control, cursorX, rowY, controlWidth, controlHeight, TRUE);
        }
        cursorX += controlWidth + kGap;
    };

    place(state.targetLabel, 40, kRowHeight);
    // The target box takes whatever is left after the fixed-width controls so a
    // long URL or an IPv6 literal stays readable on a narrow dock.
    const int fixedWidth = 40 + 72 + 88 + 88 + 92 + 64 + 64 + kGap * 8;
    place(state.targetEdit, (std::max)(120, width - fixedWidth), kRowHeight);
    place(state.pingButton, 72, kRowHeight);
    place(state.traceButton, 88, kRowHeight);
    place(state.dnsButton, 88, kRowHeight);
    // The combo needs room for its drop-down list, which Win32 sizes from the
    // control height rather than from the item count.
    if (state.dnsTypeCombo) {
        ::MoveWindow(state.dnsTypeCombo, cursorX, rowY, 92, kRowHeight * 10, TRUE);
    }
    cursorX += 92 + kGap;
    place(state.copyButton, 64, kRowHeight);
    place(state.clearButton, 64, kRowHeight);

    const int outputTop = kHeaderHeight;
    const int outputHeight = (std::max)(0, height - outputTop - kStatusHeight - kGap);
    if (state.outputEdit) {
        ::MoveWindow(state.outputEdit, kGap, outputTop, (std::max)(0, width - kGap * 2), outputHeight, TRUE);
    }
    if (state.loadingOverlay) {
        ::MoveWindow(state.loadingOverlay, kGap, outputTop, (std::max)(0, width - kGap * 2), outputHeight, TRUE);
    }
}

bool CreateChildControls(DiagnosticViewState& state) {
    HWND hwnd = state.hwnd;
    state.targetLabel = Ksword::Ui::CreateText(hwnd, kTargetLabelId, L"目标", 0, 0, 0, 0);
    state.targetEdit = ::CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"",
        WS_CHILD | WS_VISIBLE | WS_TABSTOP | ES_LEFT | ES_AUTOHSCROLL,
        0, 0, 0, 0, hwnd, reinterpret_cast<HMENU>(static_cast<INT_PTR>(kTargetEditId)),
        ::GetModuleHandleW(nullptr), nullptr);
    state.pingButton = Ksword::Ui::CreateButton(hwnd, kPingButtonId, L"Ping", 0, 0, 0, 0);
    state.traceButton = Ksword::Ui::CreateButton(hwnd, kTraceButtonId, L"路由跟踪", 0, 0, 0, 0);
    state.dnsButton = Ksword::Ui::CreateButton(hwnd, kDnsButtonId, L"DNS 查询", 0, 0, 0, 0);
    state.copyButton = Ksword::Ui::CreateButton(hwnd, kCopyButtonId, L"复制", 0, 0, 0, 0);
    state.clearButton = Ksword::Ui::CreateButton(hwnd, kClearButtonId, L"清空", 0, 0, 0, 0);

    state.dnsTypeCombo = ::CreateWindowExW(0, WC_COMBOBOXW, L"",
        WS_CHILD | WS_VISIBLE | WS_TABSTOP | WS_VSCROLL | CBS_DROPDOWNLIST | CBS_HASSTRINGS,
        0, 0, 0, 0, hwnd, reinterpret_cast<HMENU>(static_cast<INT_PTR>(kDnsTypeComboId)),
        ::GetModuleHandleW(nullptr), nullptr);
    if (!state.dnsTypeCombo) {
        return false;
    }
    for (int index = 0; index < DnsRecordTypeChoiceCount(); ++index) {
        ::SendMessageW(state.dnsTypeCombo, CB_ADDSTRING, 0,
            reinterpret_cast<LPARAM>(DnsRecordTypeChoiceLabel(index)));
    }
    ::SendMessageW(state.dnsTypeCombo, CB_SETCURSEL, 0, 0);

    state.outputEdit = ::CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"",
        WS_CHILD | WS_VISIBLE | WS_TABSTOP | WS_VSCROLL | WS_HSCROLL |
            ES_MULTILINE | ES_AUTOVSCROLL | ES_AUTOHSCROLL | ES_READONLY,
        0, 0, 0, 0, hwnd, reinterpret_cast<HMENU>(static_cast<INT_PTR>(kOutputEditId)),
        ::GetModuleHandleW(nullptr), nullptr);
    if (state.outputEdit) {
        // The output routinely runs to dozens of lines, and a read-only EDIT has
        // no way to look through it without the shared find bar.
        Ksword::Ui::AttachTextFindSupport(state.outputEdit);
    }

    state.loadingOverlay = Ksword::Ui::CreateLoadingOverlay(hwnd, kLoadingOverlayId, { 0, 0, 1, 1 });
    if (!state.targetLabel || !state.targetEdit || !state.pingButton || !state.traceButton || !state.dnsButton ||
        !state.copyButton || !state.clearButton || !state.outputEdit || !state.loadingOverlay) {
        return false;
    }

    Ksword::Ui::SetWindowFontRecursive(hwnd);
    return true;
}

LRESULT CALLBACK DiagnosticViewProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    auto* state = reinterpret_cast<DiagnosticViewState*>(::GetWindowLongPtrW(hwnd, GWLP_USERDATA));
    switch (msg) {
    case WM_NCCREATE: {
        auto owned = std::make_unique<DiagnosticViewState>();
        owned->hwnd = hwnd;
        ::SetWindowLongPtrW(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(owned.release()));
        return TRUE;
    }
    case WM_CREATE:
        if (state) {
            if (!CreateChildControls(*state)) {
                return -1;
            }
            state->probeTask =
                std::make_unique<Ksword::Ui::AsyncSnapshotTask<DiagnosticResult>>(hwnd, kMsgDiagnosticCompleted);
            LayoutView(*state);
            UpdateActionButtons(*state);
        }
        return 0;
    case WM_SIZE:
        if (state) {
            LayoutView(*state);
        }
        return 0;
    case WM_COMMAND:
        if (!state) {
            break;
        }
        if (HIWORD(wParam) == BN_CLICKED) {
            switch (LOWORD(wParam)) {
            case kPingButtonId:
                BeginProbe(*state, DiagnosticKind::Ping);
                return 0;
            case kTraceButtonId:
                BeginProbe(*state, DiagnosticKind::TraceRoute);
                return 0;
            case kDnsButtonId:
                BeginProbe(*state, DiagnosticKind::DnsLookup);
                return 0;
            case kCopyButtonId:
                state->statusText = CopyText(hwnd, WindowText(state->outputEdit)) ? L"已复制诊断结果。" : L"复制失败。";
                ::InvalidateRect(hwnd, nullptr, TRUE);
                return 0;
            case kClearButtonId:
                SetOutputText(*state, {});
                state->statusText = L"已清空诊断结果。";
                ::InvalidateRect(hwnd, nullptr, TRUE);
                return 0;
            default:
                break;
            }
        }
        break;
    case WM_CTLCOLORSTATIC:
        // Only the label is themed here. A read-only EDIT also reports through
        // WM_CTLCOLORSTATIC, and forcing a transparent background on it smears
        // the text as soon as the user scrolls.
        if (state && reinterpret_cast<HWND>(lParam) == state->targetLabel) {
            HDC dc = reinterpret_cast<HDC>(wParam);
            ::SetBkMode(dc, TRANSPARENT);
            ::SetTextColor(dc, Ksword::Ui::AppTheme().textColor);
            return reinterpret_cast<LRESULT>(Ksword::Ui::AppTheme().windowBrush());
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
    default:
        if (state && msg == kMsgDiagnosticCompleted && state->probeTask) {
            state->probeTask->consume(hwnd, wParam, lParam);
            return 0;
        }
        if (msg == WM_NCDESTROY && state) {
            // Cancel before destruction so a completion callback cannot run
            // against a half-torn-down state. The worker itself is not
            // interruptible: a running trace finishes into a dropped result.
            if (state->probeTask) {
                state->probeTask->cancel();
            }
            delete state;
            ::SetWindowLongPtrW(hwnd, GWLP_USERDATA, 0);
        }
        break;
    }
    return ::DefWindowProcW(hwnd, msg, wParam, lParam);
}

bool EnsureDiagnosticViewClass() {
    static bool registered = false;
    if (registered) {
        return true;
    }
    WNDCLASSW windowClass{};
    windowClass.lpfnWndProc = DiagnosticViewProc;
    windowClass.hInstance = ::GetModuleHandleW(nullptr);
    windowClass.hCursor = ::LoadCursorW(nullptr, IDC_ARROW);
    windowClass.hbrBackground = Ksword::Ui::AppTheme().windowBrush();
    windowClass.lpszClassName = kDiagnosticViewClass;
    registered = ::RegisterClassW(&windowClass) != 0 || ::GetLastError() == ERROR_CLASS_ALREADY_EXISTS;
    return registered;
}

} // namespace

HWND CreateNetToolsDiagnosticView(HWND parent, const RECT& bounds) {
    if (!parent || !EnsureDiagnosticViewClass()) {
        return nullptr;
    }
    return ::CreateWindowExW(
        0, kDiagnosticViewClass, L"", WS_CHILD | WS_VISIBLE | WS_CLIPCHILDREN | WS_CLIPSIBLINGS,
        bounds.left, bounds.top, bounds.right - bounds.left, bounds.bottom - bounds.top,
        parent, nullptr, ::GetModuleHandleW(nullptr), nullptr);
}

} // namespace Ksword::Features::NetTools
