#include "Launcher.h"

#include "../shared/crash/WinCrashHandler.h"

#include <commctrl.h>
#include <shellapi.h>
#include <sstream>

#pragma comment(lib, "comctl32.lib")

namespace launcher {

namespace {
constexpr int kCrashIgnoreButton = 1201;
constexpr int kCrashOpenDumpFolderButton = 1202;
constexpr int kCrashOpenGitHubIssueButton = 1203;
constexpr int kCrashRestartButton = 1204;
constexpr int kCrashCloseButton = 1205;
constexpr wchar_t kGitHubNewIssueUrl[] = L"https://github.com/KSwordDEV/KSword/issues/new";

struct CrashDialogContext {
    const LauncherOptions* options = nullptr;
};

void OpenCrashDumpFolder(const LauncherOptions& options) {
    if (!options.crashDumpPath.empty()) {
        OpenBundleFolder(options.crashDumpPath);
    }
}

void OpenGitHubIssue() {
    (void)ShellExecuteW(nullptr, L"open", kGitHubNewIssueUrl, nullptr, nullptr, SW_SHOWNORMAL);
}

HRESULT CALLBACK CrashDialogCallback(
    HWND,
    const UINT notification,
    const WPARAM buttonId,
    LPARAM,
    const LONG_PTR callbackData) {
    if (notification != TDN_BUTTON_CLICKED) {
        return S_OK;
    }

    const auto* const context = reinterpret_cast<const CrashDialogContext*>(callbackData);
    if (buttonId == kCrashOpenDumpFolderButton) {
        if (context != nullptr && context->options != nullptr) {
            OpenCrashDumpFolder(*context->options);
        }
        return S_FALSE;
    }
    if (buttonId == kCrashOpenGitHubIssueButton) {
        OpenGitHubIssue();
        return S_FALSE;
    }
    return S_OK;
}

std::wstring ExceptionText(const DWORD code, const bool chinese) {
    if (chinese) {
        switch (code) {
        case EXCEPTION_ACCESS_VIOLATION: return L"访问冲突";
        case EXCEPTION_ILLEGAL_INSTRUCTION: return L"非法指令";
        case EXCEPTION_INT_DIVIDE_BY_ZERO: return L"整数除零";
        case EXCEPTION_STACK_OVERFLOW: return L"栈溢出";
        case STATUS_HEAP_CORRUPTION: return L"堆损坏";
        case 0xE06D7363u: return L"未处理的 C++ 异常";
        default: return L"未处理异常";
        }
    }
    switch (code) {
    case EXCEPTION_ACCESS_VIOLATION: return L"Access violation";
    case EXCEPTION_ILLEGAL_INSTRUCTION: return L"Illegal instruction";
    case EXCEPTION_INT_DIVIDE_BY_ZERO: return L"Integer divide by zero";
    case EXCEPTION_STACK_OVERFLOW: return L"Stack overflow";
    case STATUS_HEAP_CORRUPTION: return L"Heap corruption";
    case 0xE06D7363u: return L"Unhandled C++ exception";
    default: return L"Unhandled exception";
    }
}

std::wstring Hex32(const DWORD value) {
    wchar_t buffer[32] = {};
    swprintf_s(buffer, L"0x%08lX", static_cast<unsigned long>(value));
    return buffer;
}

std::wstring Hex64(const unsigned long long value) {
    wchar_t buffer[32] = {};
    swprintf_s(buffer, L"0x%llX", value);
    return buffer;
}

int ShowCrashDialog(const LauncherOptions& options, const bool chinese) {
    const std::wstring title = chinese ? L"KswordARK 崩溃" : L"KswordARK crashed";
    const std::wstring instruction = chinese
        ? L"KswordARK 因未处理的异常停止运行。"
        : L"KswordARK stopped because of an unhandled exception.";
    const std::wstring dumpLabel = chinese ? L"转储文件" : L"Dump file";
    const std::wstring dumpText = options.crashDumpWritten && !options.crashDumpPath.empty()
        ? options.crashDumpPath
        : (chinese ? L"转储文件未能写入。" : L"The dump file could not be written.");
    const std::wstring repeatText = options.crashRepeat
        ? (chinese
            ? L"\n\n程序刚刚重启后再次崩溃，建议先退出并检查转储文件。"
            : L"\n\nThe program crashed again immediately after a restart. Exit and inspect the dump file.")
        : L"";
    const std::wstring supportText = chinese
        ? L"\n\n反馈 QQ 群：774070323"
        : L"\n\nSupport QQ group: 774070323";
    const std::wstring body = (chinese ? L"异常：" : L"Exception: ")
        + ExceptionText(options.crashExceptionCode, chinese)
        + L" (" + Hex32(options.crashExceptionCode) + L")\n"
        + (chinese ? L"地址：" : L"Address: ") + Hex64(options.crashExceptionAddress) + L"\n"
        + dumpLabel + (chinese ? L"：" : L": ") + dumpText + repeatText + supportText;
    const std::wstring ignoreButton = chinese ? L"忽略错误" : L"Ignore Error";
    const std::wstring openDumpFolderButton = chinese ? L"打开转储文件夹" : L"Open Dump Folder";
    const std::wstring openGitHubIssueButton = chinese ? L"打开 GitHub Issue" : L"Open GitHub Issue";
    const std::wstring restartButton = chinese ? L"重启 KSword" : L"Restart KSword";
    const std::wstring closeButton = chinese ? L"关闭" : L"Close";
    TASKDIALOG_BUTTON restartButtons[] = {
        { kCrashIgnoreButton, ignoreButton.c_str() },
        { kCrashOpenDumpFolderButton, openDumpFolderButton.c_str() },
        { kCrashOpenGitHubIssueButton, openGitHubIssueButton.c_str() },
        { kCrashRestartButton, restartButton.c_str() },
        { kCrashCloseButton, closeButton.c_str() },
    };
    TASKDIALOG_BUTTON repeatedCrashButtons[] = {
        { kCrashIgnoreButton, ignoreButton.c_str() },
        { kCrashOpenDumpFolderButton, openDumpFolderButton.c_str() },
        { kCrashOpenGitHubIssueButton, openGitHubIssueButton.c_str() },
        { kCrashCloseButton, closeButton.c_str() },
    };
    TASKDIALOGCONFIG config = { sizeof(config) };
    config.dwFlags = TDF_ALLOW_DIALOG_CANCELLATION | TDF_POSITION_RELATIVE_TO_WINDOW;
    config.pszWindowTitle = title.c_str();
    config.pszMainInstruction = instruction.c_str();
    config.pszContent = body.c_str();
    config.cButtons = options.crashRepeat
        ? ARRAYSIZE(repeatedCrashButtons)
        : ARRAYSIZE(restartButtons);
    config.pButtons = options.crashRepeat
        ? repeatedCrashButtons
        : restartButtons;
    config.nDefaultButton = options.crashRepeat ? kCrashCloseButton : kCrashRestartButton;
    config.pszMainIcon = TD_ERROR_ICON;
    const CrashDialogContext dialogContext{ &options };
    config.pfCallback = CrashDialogCallback;
    config.lpCallbackData = reinterpret_cast<LONG_PTR>(&dialogContext);
    int result = kCrashCloseButton;
    if (FAILED(TaskDialogIndirect(&config, &result, nullptr, nullptr))) {
        const UINT commonFlags = MB_ICONERROR | MB_SETFOREGROUND | MB_TOPMOST;
        if (options.crashRepeat) {
            (void)MessageBoxW(nullptr, body.c_str(), title.c_str(), MB_OK | commonFlags);
            result = kCrashCloseButton;
        } else {
            const UINT flags = MB_YESNO | MB_DEFBUTTON2 | commonFlags;
            result = MessageBoxW(nullptr, body.c_str(), title.c_str(), flags) == IDYES
                ? kCrashRestartButton
                : kCrashCloseButton;
        }
    }
    return result;
}

}

int HandleCrashReportMode(const RuntimePaths& paths, const LauncherOptions& options, const bool chinese) {
    if (options.crashProcessId == 0 || options.crashReadyEventName.empty()) {
        return 1;
    }

    HANDLE targetProcess = OpenProcess(SYNCHRONIZE, FALSE, options.crashProcessId);
    HANDLE readyEvent = OpenEventW(EVENT_MODIFY_STATE, FALSE, options.crashReadyEventName.c_str());
    if (targetProcess == nullptr || readyEvent == nullptr) {
        if (targetProcess != nullptr) CloseHandle(targetProcess);
        if (readyEvent != nullptr) CloseHandle(readyEvent);
        return 1;
    }

    const BOOL signaled = SetEvent(readyEvent);
    CloseHandle(readyEvent);
    if (signaled == FALSE) {
        CloseHandle(targetProcess);
        return 1;
    }

    const DWORD waitResult = WaitForSingleObject(targetProcess, 30000);
    CloseHandle(targetProcess);
    if (waitResult != WAIT_OBJECT_0) {
        ShowSimpleMessage(
            chinese ? L"崩溃处理失败" : L"Crash handling failed",
            chinese
                ? L"主程序未能在限定时间内退出，已停止自动重启。"
                : L"The main process did not exit within the time limit. Automatic restart was stopped.",
            chinese);
        return 1;
    }

    const int result = ShowCrashDialog(options, chinese);
    if (result != kCrashRestartButton) {
        return 0;
    }

    LauncherOptions restartOptions;
    restartOptions.targetOverride = true;
    restartOptions.useLight = false;
    restartOptions.forwardedArguments.push_back(ks::crash::kCrashRestartedArgument);
    if (LaunchTarget(paths, restartOptions)) {
        return 0;
    }

    ShowSimpleMessage(
        chinese ? L"重新启动失败" : L"Restart failed",
        chinese
            ? L"无法重新启动 KswordARK，程序即将退出。"
            : L"KswordARK could not be restarted and will now exit.",
        chinese);
    return 1;
}

}
