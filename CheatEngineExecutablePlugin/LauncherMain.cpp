#include "../Ksword5.1/Ksword5.1/ArkDriverClient/ArkDriverClient.h"

#include <Windows.h>

#include <algorithm>
#include <cerrno>
#include <chrono>
#include <cstdint>
#include <cwchar>
#include <fstream>
#include <string>
#include <thread>
#include <vector>

namespace
{
    constexpr wchar_t kPluginTitle[] = L"KSword Cheat Engine";
    constexpr wchar_t kTabWindowClass[] = L"KSwordCheatEngineTabSurface";
    constexpr char kProtocol[] = "ksword-plugin/1";
    constexpr char kPluginId[] = "cheat-engine";
    constexpr UINT kInitializeTabMessage = WM_APP + 1U;
    constexpr UINT_PTR kLifecycleTimerId = 1U;

    struct ParsedArguments
    {
        std::wstring command;
        DWORD targetProcessId = 0U;
        HWND parentWindow = nullptr;
        DWORD hostProcessId = 0U;
        bool valid = false;
    };

    enum class BridgeStatus
    {
        ready,
        failed,
        timeout,
        launchFailed
    };

    HWND gTabWindow = nullptr;
    HWND gCheatEngineWindow = nullptr;
    HANDLE gCheatEngineProcess = nullptr;
    DWORD gHostProcessId = 0U;
    int gTabExitCode = 0;

    void emitJsonLine(const std::string& eventName, const std::string& fields)
    {
        std::string line =
            "{\"protocol\":\"" + std::string(kProtocol) +
            "\",\"plugin_id\":\"" + std::string(kPluginId) +
            "\",\"event\":\"" + eventName + "\"";
        if (!fields.empty())
        {
            line += ",";
            line += fields;
        }
        line += "}\n";

        const HANDLE stdoutHandle = ::GetStdHandle(STD_OUTPUT_HANDLE);
        if (stdoutHandle == nullptr || stdoutHandle == INVALID_HANDLE_VALUE)
        {
            return;
        }
        DWORD written = 0U;
        (void)::WriteFile(
            stdoutHandle,
            line.data(),
            static_cast<DWORD>(line.size()),
            &written,
            nullptr);
    }

    void emitError(const char* const code, const char* const message)
    {
        emitJsonLine(
            "error",
            "\"code\":\"" + std::string(code) +
            "\",\"message\":\"" + std::string(message) + "\"");
    }

    bool parseUnsignedProcessId(const std::wstring& text, DWORD* const valueOut)
    {
        if (valueOut == nullptr || text.empty())
        {
            return false;
        }
        wchar_t* end = nullptr;
        errno = 0;
        const unsigned long long value = std::wcstoull(text.c_str(), &end, 10);
        if (errno != 0 || end == text.c_str() || *end != L'\0' ||
            value == 0ULL || value > static_cast<unsigned long long>(MAXDWORD))
        {
            return false;
        }
        *valueOut = static_cast<DWORD>(value);
        return true;
    }

    bool parseWindowHandle(const std::wstring& text, HWND* const valueOut)
    {
        if (valueOut == nullptr || text.empty())
        {
            return false;
        }
        wchar_t* end = nullptr;
        errno = 0;
        const unsigned long long value = std::wcstoull(text.c_str(), &end, 10);
        if (errno != 0 || end == text.c_str() || *end != L'\0' || value == 0ULL)
        {
            return false;
        }
        const auto numericHandle = static_cast<std::uintptr_t>(value);
        if (static_cast<unsigned long long>(numericHandle) != value)
        {
            return false;
        }
        *valueOut = reinterpret_cast<HWND>(numericHandle);
        return true;
    }

    ParsedArguments parseArguments(const int argc, wchar_t* const argv[])
    {
        ParsedArguments parsed;
        if (argc < 3 || std::wstring(argv[1]) != L"--ksword-plugin")
        {
            return parsed;
        }
        parsed.command = argv[2];
        if (parsed.command == L"info" || parsed.command == L"check")
        {
            parsed.valid = true;
            return parsed;
        }
        if (parsed.command != L"launch" && parsed.command != L"tab")
        {
            return parsed;
        }

        for (int index = 3; index + 1 < argc; ++index)
        {
            const std::wstring argument = argv[index];
            if (argument == L"--pid")
            {
                if (!parseUnsignedProcessId(
                        argv[index + 1],
                        &parsed.targetProcessId))
                {
                    return parsed;
                }
                ++index;
            }
            else if (argument == L"--parent-hwnd")
            {
                if (!parseWindowHandle(argv[index + 1], &parsed.parentWindow))
                {
                    return parsed;
                }
                ++index;
            }
            else if (argument == L"--host-pid")
            {
                if (!parseUnsignedProcessId(
                        argv[index + 1],
                        &parsed.hostProcessId))
                {
                    return parsed;
                }
                ++index;
            }
        }
        if (parsed.command == L"launch")
        {
            parsed.valid = parsed.targetProcessId != 0U;
            return parsed;
        }

        DWORD parentOwnerProcessId = 0U;
        if (parsed.parentWindow == nullptr ||
            parsed.hostProcessId == 0U ||
            !::IsWindow(parsed.parentWindow) ||
            ::GetWindowThreadProcessId(
                parsed.parentWindow,
                &parentOwnerProcessId) == 0U ||
            parentOwnerProcessId != parsed.hostProcessId)
        {
            return parsed;
        }
        parsed.valid = true;
        return parsed;
    }

    std::wstring currentExecutablePath()
    {
        std::vector<wchar_t> buffer(32768U, L'\0');
        const DWORD length = ::GetModuleFileNameW(
            nullptr,
            buffer.data(),
            static_cast<DWORD>(buffer.size()));
        if (length == 0U || length >= static_cast<DWORD>(buffer.size()))
        {
            return {};
        }
        return std::wstring(buffer.data(), length);
    }

    std::wstring parentDirectory(const std::wstring& path)
    {
        const std::wstring::size_type separator = path.find_last_of(L"\\/");
        if (separator == std::wstring::npos)
        {
            return {};
        }
        return path.substr(0U, separator);
    }

    std::wstring joinPath(
        const std::wstring& directory,
        const std::wstring& relativePath)
    {
        if (directory.empty())
        {
            return relativePath;
        }
        return directory + L"\\" + relativePath;
    }

    bool isDriverReady()
    {
        const ksword::ark::DriverClient driverClient;
        auto driverHandle = driverClient.open();
        return driverHandle.isValid();
    }

    bool confirmR0OrWarn(bool* const driverReadyOut)
    {
        if (driverReadyOut == nullptr)
        {
            return false;
        }
        *driverReadyOut = isDriverReady();
        if (*driverReadyOut)
        {
            return true;
        }

        const int retryResult = ::MessageBoxW(
            nullptr,
            L"KSword R0 驱动当前不可用。\n\n"
            L"请回到 KSword 启用 R0 模式并加载驱动，然后点击“重试”。",
            kPluginTitle,
            MB_RETRYCANCEL | MB_ICONWARNING | MB_SETFOREGROUND);
        if (retryResult != IDRETRY)
        {
            return false;
        }

        *driverReadyOut = isDriverReady();
        if (*driverReadyOut)
        {
            return true;
        }
        const int warningResult = ::MessageBoxW(
            nullptr,
            L"R0 模式未启用，Cheat Engine 的进程交互无法保证通过 "
            L"KSword 驱动，请小心使用。\n\n是否仍要继续启动？",
            kPluginTitle,
            MB_OKCANCEL | MB_ICONWARNING | MB_DEFBUTTON2 | MB_SETFOREGROUND);
        return warningResult == IDOK;
    }

    std::wstring makeStatusPath()
    {
        std::vector<wchar_t> tempPath(MAX_PATH + 1U, L'\0');
        const DWORD length = ::GetTempPathW(
            static_cast<DWORD>(tempPath.size()),
            tempPath.data());
        if (length == 0U ||
            length >= static_cast<DWORD>(tempPath.size()))
        {
            return {};
        }
        return std::wstring(tempPath.data(), length) +
            L"ksword-ce-bridge-" +
            std::to_wstring(::GetCurrentProcessId()) +
            L".status";
    }

    std::string readStatusFile(const std::wstring& path)
    {
        std::ifstream input(path, std::ios::binary);
        if (!input)
        {
            return {};
        }
        std::string status;
        std::getline(input, status);
        return status;
    }

    BridgeStatus waitForBridgeStatus(const std::wstring& statusPath)
    {
        constexpr std::size_t kAttemptCount = 200U;
        for (std::size_t attempt = 0U; attempt < kAttemptCount; ++attempt)
        {
            const std::string status = readStatusFile(statusPath);
            if (status == "ready")
            {
                return BridgeStatus::ready;
            }
            if (status == "failed")
            {
                return BridgeStatus::failed;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
        return BridgeStatus::timeout;
    }

    BridgeStatus launchCheatEngine(
        const std::wstring& pluginDirectory,
        const DWORD targetProcessId,
        DWORD* const cheatEngineProcessIdOut,
        HANDLE* const cheatEngineProcessHandleOut = nullptr)
    {
        if (cheatEngineProcessIdOut != nullptr)
        {
            *cheatEngineProcessIdOut = 0U;
        }
        if (cheatEngineProcessHandleOut != nullptr)
        {
            *cheatEngineProcessHandleOut = nullptr;
        }
        const std::wstring ceDirectory =
            joinPath(pluginDirectory, L"payload\\Cheat Engine");
        const std::wstring ceExecutable =
            joinPath(ceDirectory, L"cheatengine-x86_64.exe");
        const std::wstring bridgeDll = joinPath(
            pluginDirectory,
            L"bridge\\x64\\KswordCheatEnginePlugin.dll");
        const std::wstring statusPath = makeStatusPath();
        if (::GetFileAttributesW(ceExecutable.c_str()) == INVALID_FILE_ATTRIBUTES ||
            ::GetFileAttributesW(bridgeDll.c_str()) == INVALID_FILE_ATTRIBUTES ||
            statusPath.empty())
        {
            return BridgeStatus::launchFailed;
        }

        (void)::DeleteFileW(statusPath.c_str());
        if (::SetEnvironmentVariableW(
                L"KSWORD_CE_BRIDGE_DLL",
                bridgeDll.c_str()) == FALSE ||
            ::SetEnvironmentVariableW(
                L"KSWORD_CE_BRIDGE_STATUS_FILE",
                statusPath.c_str()) == FALSE ||
            ::SetEnvironmentVariableW(
                L"KSWORD_CE_TARGET_PID",
                std::to_wstring(targetProcessId).c_str()) == FALSE)
        {
            return BridgeStatus::launchFailed;
        }

        std::wstring commandLine = L"\"" + ceExecutable + L"\"";
        std::vector<wchar_t> mutableCommandLine(
            commandLine.begin(),
            commandLine.end());
        mutableCommandLine.push_back(L'\0');
        STARTUPINFOW startupInfo{};
        startupInfo.cb = sizeof(startupInfo);
        PROCESS_INFORMATION processInformation{};

        const BOOL created = ::CreateProcessW(
            ceExecutable.c_str(),
            mutableCommandLine.data(),
            nullptr,
            nullptr,
            FALSE,
            0U,
            nullptr,
            ceDirectory.c_str(),
            &startupInfo,
            &processInformation);
        if (created == FALSE)
        {
            return BridgeStatus::launchFailed;
        }

        if (cheatEngineProcessIdOut != nullptr)
        {
            *cheatEngineProcessIdOut = processInformation.dwProcessId;
        }
        ::CloseHandle(processInformation.hThread);
        if (cheatEngineProcessHandleOut != nullptr)
        {
            *cheatEngineProcessHandleOut = processInformation.hProcess;
        }
        const BridgeStatus status = waitForBridgeStatus(statusPath);
        if (cheatEngineProcessHandleOut == nullptr)
        {
            ::CloseHandle(processInformation.hProcess);
        }
        (void)::DeleteFileW(statusPath.c_str());
        (void)::DeleteFileW((statusPath + L".theme").c_str());
        (void)::DeleteFileW((statusPath + L".theme.log").c_str());
        return status;
    }

    struct WindowSearchContext
    {
        DWORD processId = 0U;
        HWND window = nullptr;
        int score = 0;
    };

    BOOL CALLBACK findCheatEngineWindow(
        const HWND window,
        const LPARAM contextValue)
    {
        auto* const context =
            reinterpret_cast<WindowSearchContext*>(contextValue);
        if (context == nullptr || !::IsWindowVisible(window))
        {
            return TRUE;
        }
        DWORD processId = 0U;
        (void)::GetWindowThreadProcessId(window, &processId);
        if (processId != context->processId)
        {
            return TRUE;
        }

        wchar_t className[128] = {};
        wchar_t title[256] = {};
        (void)::GetClassNameW(window, className, _countof(className));
        (void)::GetWindowTextW(window, title, _countof(title));
        int score = 0;
        if (std::wcscmp(className, L"TCustomForm") == 0)
        {
            score += 1000;
        }
        if (std::wcsstr(title, L"KSword CE") != nullptr ||
            std::wcsstr(title, L"Cheat Engine") != nullptr)
        {
            score += 500;
        }
        if ((::GetWindowLongPtrW(window, GWL_STYLE) & WS_CAPTION) != 0)
        {
            score += 10;
        }
        if (score > context->score)
        {
            context->window = window;
            context->score = score;
        }
        return TRUE;
    }

    HWND waitForCheatEngineWindow(const DWORD processId)
    {
        constexpr std::size_t kAttemptCount = 200U;
        for (std::size_t attempt = 0U; attempt < kAttemptCount; ++attempt)
        {
            WindowSearchContext context{};
            context.processId = processId;
            (void)::EnumWindows(
                findCheatEngineWindow,
                reinterpret_cast<LPARAM>(&context));
            if (context.window != nullptr && context.score >= 1500)
            {
                return context.window;
            }
            if (gCheatEngineProcess != nullptr &&
                ::WaitForSingleObject(gCheatEngineProcess, 0U) ==
                    WAIT_OBJECT_0)
            {
                return nullptr;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
        return nullptr;
    }

    void resizeCheatEngineWindow(const HWND containerWindow)
    {
        if (!::IsWindow(containerWindow) ||
            !::IsWindow(gCheatEngineWindow))
        {
            return;
        }
        RECT clientRectangle{};
        if (::GetClientRect(containerWindow, &clientRectangle) == FALSE)
        {
            return;
        }
        (void)::MoveWindow(
            gCheatEngineWindow,
            0,
            0,
            (std::max)(1L, clientRectangle.right - clientRectangle.left),
            (std::max)(1L, clientRectangle.bottom - clientRectangle.top),
            TRUE);
    }

    bool attachCheatEngineWindow(
        const HWND containerWindow,
        const HWND cheatEngineWindow)
    {
        if (!::IsWindow(containerWindow) ||
            !::IsWindow(cheatEngineWindow))
        {
            return false;
        }

        ::SetLastError(ERROR_SUCCESS);
        const HWND previousParent =
            ::SetParent(cheatEngineWindow, containerWindow);
        if (previousParent == nullptr &&
            ::GetLastError() != ERROR_SUCCESS)
        {
            return false;
        }

        // 只做 Win32 子窗口所需的最小样式转换。CE 自己的标题栏、菜单、
        // 控件和消息处理全部保留，避免再次破坏 Lazarus 的菜单/焦点状态。
        LONG_PTR style = ::GetWindowLongPtrW(cheatEngineWindow, GWL_STYLE);
        style &= ~static_cast<LONG_PTR>(WS_POPUP);
        style |= WS_CHILD | WS_VISIBLE | WS_CLIPCHILDREN | WS_CLIPSIBLINGS;
        (void)::SetWindowLongPtrW(
            cheatEngineWindow,
            GWL_STYLE,
            style);

        LONG_PTR extendedStyle =
            ::GetWindowLongPtrW(cheatEngineWindow, GWL_EXSTYLE);
        extendedStyle &= ~static_cast<LONG_PTR>(WS_EX_APPWINDOW);
        extendedStyle |= WS_EX_CONTROLPARENT;
        (void)::SetWindowLongPtrW(
            cheatEngineWindow,
            GWL_EXSTYLE,
            extendedStyle);
        (void)::SetWindowPos(
            cheatEngineWindow,
            HWND_TOP,
            0,
            0,
            0,
            0,
            SWP_NOACTIVATE | SWP_NOMOVE | SWP_NOSIZE |
                SWP_FRAMECHANGED | SWP_SHOWWINDOW);
        gCheatEngineWindow = cheatEngineWindow;
        resizeCheatEngineWindow(containerWindow);
        return true;
    }

    void closeCheatEngine()
    {
        if (::IsWindow(gCheatEngineWindow))
        {
            (void)::PostMessageW(gCheatEngineWindow, WM_CLOSE, 0U, 0);
        }
        gCheatEngineWindow = nullptr;
        if (gCheatEngineProcess != nullptr)
        {
            ::CloseHandle(gCheatEngineProcess);
            gCheatEngineProcess = nullptr;
        }
    }

    void failTab(
        const HWND window,
        const char* const code,
        const char* const message)
    {
        emitError(code, message);
        gTabExitCode = 2;
        if (::IsWindow(window))
        {
            (void)::DestroyWindow(window);
        }
    }

    LRESULT CALLBACK tabWindowProcedure(
        const HWND window,
        const UINT message,
        const WPARAM wParam,
        const LPARAM lParam)
    {
        switch (message)
        {
        case WM_SIZE:
            resizeCheatEngineWindow(window);
            return 0;
        case WM_SETFOCUS:
            if (::IsWindow(gCheatEngineWindow))
            {
                (void)::SetFocus(gCheatEngineWindow);
            }
            return 0;
        case kInitializeTabMessage:
        {
            bool driverReady = false;
            if (!confirmR0OrWarn(&driverReady))
            {
                failTab(
                    window,
                    "r0_required",
                    "Enable KSword R0 mode and load the driver before launching.");
                return 0;
            }

            DWORD cheatEngineProcessId = 0U;
            const BridgeStatus bridgeStatus = launchCheatEngine(
                parentDirectory(currentExecutablePath()),
                0U,
                &cheatEngineProcessId,
                &gCheatEngineProcess);
            if (bridgeStatus == BridgeStatus::launchFailed)
            {
                failTab(
                    window,
                    "launch_failed",
                    "The bundled Cheat Engine payload is incomplete or failed to start.");
                return 0;
            }
            if (bridgeStatus != BridgeStatus::ready)
            {
                (void)::MessageBoxW(
                    window,
                    L"R0 模式未启用或 KSword 桥接初始化失败，进程交互无法保证"
                    L"通过 KSword 驱动，请小心使用。",
                    kPluginTitle,
                    MB_OK | MB_ICONWARNING | MB_SETFOREGROUND);
                emitJsonLine(
                    "warning",
                    "\"code\":\"bridge_not_ready\","
                    "\"message\":\"R0 mode is not enabled; use carefully.\"");
            }

            const HWND cheatEngineWindow =
                waitForCheatEngineWindow(cheatEngineProcessId);
            if (cheatEngineWindow == nullptr ||
                !attachCheatEngineWindow(window, cheatEngineWindow))
            {
                failTab(
                    window,
                    "embed_failed",
                    "Cheat Engine started but its main window could not be attached.");
                return 0;
            }

            emitJsonLine(
                "tab_embedded",
                "\"cheat_engine_pid\":" +
                    std::to_string(cheatEngineProcessId) +
                    ",\"r0_ready\":" +
                    (driverReady ? "true" : "false") +
                    ",\"bridge_ready\":" +
                    (bridgeStatus == BridgeStatus::ready ? "true" : "false"));
            (void)::SetTimer(window, kLifecycleTimerId, 1000U, nullptr);
            return 0;
        }
        case WM_TIMER:
            if (wParam == kLifecycleTimerId)
            {
                HANDLE hostProcess = ::OpenProcess(
                    SYNCHRONIZE,
                    FALSE,
                    gHostProcessId);
                const bool hostExited =
                    hostProcess == nullptr ||
                    ::WaitForSingleObject(hostProcess, 0U) == WAIT_OBJECT_0;
                if (hostProcess != nullptr)
                {
                    ::CloseHandle(hostProcess);
                }
                const bool cheatEngineExited =
                    gCheatEngineProcess != nullptr &&
                    ::WaitForSingleObject(
                        gCheatEngineProcess,
                        0U) == WAIT_OBJECT_0;
                if (hostExited || cheatEngineExited)
                {
                    gTabExitCode = hostExited ? 0 : 2;
                    (void)::DestroyWindow(window);
                }
            }
            return 0;
        case WM_DESTROY:
            (void)::KillTimer(window, kLifecycleTimerId);
            closeCheatEngine();
            gTabWindow = nullptr;
            ::PostQuitMessage(gTabExitCode);
            return 0;
        default:
            return ::DefWindowProcW(window, message, wParam, lParam);
        }
    }

    int runTab(const ParsedArguments& arguments)
    {
        WNDCLASSEXW windowClass{};
        windowClass.cbSize = sizeof(windowClass);
        windowClass.lpfnWndProc = tabWindowProcedure;
        windowClass.hInstance = ::GetModuleHandleW(nullptr);
        windowClass.hCursor = ::LoadCursorW(nullptr, IDC_ARROW);
        windowClass.hbrBackground =
            reinterpret_cast<HBRUSH>(COLOR_WINDOW + 1);
        windowClass.lpszClassName = kTabWindowClass;
        if (::RegisterClassExW(&windowClass) == 0U &&
            ::GetLastError() != ERROR_CLASS_ALREADY_EXISTS)
        {
            emitError(
                "window_class_failed",
                "The Cheat Engine Tab window class could not be registered.");
            return 2;
        }

        gHostProcessId = arguments.hostProcessId;
        gTabExitCode = 0;
        gTabWindow = ::CreateWindowExW(
            WS_EX_CONTROLPARENT,
            kTabWindowClass,
            kPluginTitle,
            WS_CHILD | WS_VISIBLE | WS_CLIPCHILDREN | WS_CLIPSIBLINGS,
            0,
            0,
            1,
            1,
            arguments.parentWindow,
            nullptr,
            ::GetModuleHandleW(nullptr),
            nullptr);
        if (gTabWindow == nullptr)
        {
            emitError(
                "tab_window_failed",
                "The Cheat Engine Tab child window could not be created.");
            return 2;
        }

        emitJsonLine(
            "tab_ready",
            "\"hwnd\":\"" +
                std::to_string(
                    reinterpret_cast<std::uintptr_t>(gTabWindow)) +
                "\"");
        (void)::PostMessageW(
            gTabWindow,
            kInitializeTabMessage,
            0U,
            0);

        MSG message{};
        while (::GetMessageW(&message, nullptr, 0U, 0U) > 0)
        {
            ::TranslateMessage(&message);
            ::DispatchMessageW(&message);
        }
        return gTabExitCode;
    }

    int runInfo()
    {
        emitJsonLine(
            "info",
            "\"runtime\":\"executable\",\"plugin_type\":\"hybrid\","
            "\"targets\":[\"process\",\"tab\"],"
            "\"commands\":[\"launch\",\"tab\",\"check\",\"info\"],"
            "\"presentation\":\"standalone_or_native_tab\","
            "\"driver_transport\":\"KswordARK\",\"bridge_api\":6");
        return 0;
    }

    int runDriverCheck()
    {
        const bool ready = isDriverReady();
        emitJsonLine(
            "driver_status",
            std::string("\"r0_ready\":") + (ready ? "true" : "false"));
        return ready ? 0 : 2;
    }
}

int wmain(const int argc, wchar_t* const argv[])
{
    const ParsedArguments arguments = parseArguments(argc, argv);
    if (!arguments.valid)
    {
        emitError("invalid_arguments", "Invalid KSword plugin arguments.");
        return 64;
    }
    if (arguments.command == L"info")
    {
        return runInfo();
    }
    if (arguments.command == L"check")
    {
        return runDriverCheck();
    }
    if (arguments.command == L"tab")
    {
        return runTab(arguments);
    }

    emitJsonLine(
        "launch_started",
        "\"target_pid\":" + std::to_string(arguments.targetProcessId));
    bool driverReady = false;
    if (!confirmR0OrWarn(&driverReady))
    {
        emitError(
            "r0_required",
            "Enable KSword R0 mode and load the driver before launching.");
        return 2;
    }

    const std::wstring pluginDirectory =
        parentDirectory(currentExecutablePath());
    DWORD cheatEngineProcessId = 0U;
    const BridgeStatus bridgeStatus = launchCheatEngine(
        pluginDirectory,
        arguments.targetProcessId,
        &cheatEngineProcessId);
    if (bridgeStatus == BridgeStatus::launchFailed)
    {
        ::MessageBoxW(
            nullptr,
            L"Cheat Engine 插件载荷不完整或无法启动，请重新生成插件文件。",
            kPluginTitle,
            MB_OK | MB_ICONERROR | MB_SETFOREGROUND);
        emitError(
            "launch_failed",
            "The bundled Cheat Engine payload is incomplete or failed to start.");
        return 2;
    }
    if (bridgeStatus != BridgeStatus::ready)
    {
        ::MessageBoxW(
            nullptr,
            L"R0 模式未启用或 KSword 桥接初始化失败，进程交互无法保证"
            L"通过 KSword 驱动，请小心使用。",
            kPluginTitle,
            MB_OK | MB_ICONWARNING | MB_SETFOREGROUND);
        emitJsonLine(
            "warning",
            "\"code\":\"bridge_not_ready\","
            "\"message\":\"R0 mode is not enabled; use carefully.\"");
    }

    emitJsonLine(
        "launch_complete",
        "\"target_pid\":" + std::to_string(arguments.targetProcessId) +
        ",\"cheat_engine_pid\":" + std::to_string(cheatEngineProcessId) +
        ",\"r0_ready\":" + (driverReady ? "true" : "false") +
        ",\"bridge_ready\":" +
        (bridgeStatus == BridgeStatus::ready ? "true" : "false"));
    return 0;
}
