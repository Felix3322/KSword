#include "../Ksword5.1/Ksword5.1/ArkDriverClient/ArkDriverClient.h"

#include <Windows.h>

#include <cerrno>
#include <chrono>
#include <cstdint>
#include <cwchar>
#include <fstream>
#include <iterator>
#include <string>
#include <thread>
#include <vector>

namespace
{
    constexpr wchar_t kPluginTitle[] = L"KSword Cheat Engine";
    constexpr wchar_t kTabWindowClass[] = L"KSwordCheatEngineTabWindow";
    constexpr char kProtocol[] = "ksword-plugin/1";
    constexpr char kPluginId[] = "cheat-engine";
    constexpr UINT kInitializeTabMessage = WM_APP + 1U;
    constexpr UINT_PTR kHostWatchTimerId = 1U;

    // ParsedArguments：保存 KSword 插件协议命令及目标进程参数。
    struct ParsedArguments
    {
        std::wstring command;
        DWORD targetProcessId = 0U;
        HWND parentWindow = nullptr;
        DWORD hostProcessId = 0U;
        bool valid = false;
    };

    // BridgeStatus：描述 CE autorun 对桥接 DLL 初始化的回执。
    enum class BridgeStatus
    {
        ready,
        failed,
        timeout,
        launchFailed
    };

    HWND gTabWindow = nullptr;
    HWND gStatusWindow = nullptr;
    HWND gCheatEngineWindow = nullptr;
    HANDLE gCheatEngineProcess = nullptr;
    DWORD gHostProcessId = 0U;
    int gTabExitCode = 0;

    // emitJsonLine：只向 stdout 写入 UTF-8 JSON Lines，供 KSword 宿主解析。
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

        // stdoutHandle 用途：QProcess 为插件入口提供的标准输出管道。
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

    // emitError：输出标准错误事件，并避免把人类横幅混入 stdout。
    void emitError(const char* const code, const char* const message)
    {
        emitJsonLine(
            "error",
            "\"code\":\"" + std::string(code) +
            "\",\"message\":\"" + std::string(message) + "\"");
    }

    // parseUnsignedProcessId：严格解析十进制 PID，拒绝溢出和尾随字符。
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

    // parseWindowHandle：严格解析宿主以十进制传入的 HWND。
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

    // parseArguments：
    // - 输入：wmain 原始参数。
    // - 处理：识别 --ksword-plugin <command> -- 后的稳定目标参数。
    // - 返回：接受 info、check、带有效 PID 的 launch，以及带受校验父窗口的 tab。
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

        // 只消费宿主提供的稳定目标/Tab 上下文字段；其它字段保持向前兼容并忽略。
        for (int index = 3; index + 1 < argc; ++index)
        {
            const std::wstring argument = argv[index];
            if (argument == L"--pid")
            {
                if (!parseUnsignedProcessId(argv[index + 1], &parsed.targetProcessId))
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
                if (!parseUnsignedProcessId(argv[index + 1], &parsed.hostProcessId))
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

    // currentExecutablePath：获取插件入口自身的绝对路径。
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

    // parentDirectory：返回路径的父目录，不依赖当前工作目录。
    std::wstring parentDirectory(const std::wstring& path)
    {
        const std::wstring::size_type separator = path.find_last_of(L"\\/");
        if (separator == std::wstring::npos)
        {
            return {};
        }
        return path.substr(0U, separator);
    }

    // joinPath：组合插件内部的受控相对路径。
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

    // isDriverReady：通过唯一允许的 ArkDriverClient 入口验证 R0 设备。
    bool isDriverReady()
    {
        const ksword::ark::DriverClient driverClient;
        auto driverHandle = driverClient.open();
        return driverHandle.isValid();
    }

    // confirmR0OrWarn：
    // - 首次失败：要求用户回到 KSword 启用 R0 并加载驱动。
    // - 重试仍失败：按需求明确提示 R0 未启用并要求谨慎使用。
    // - 返回：用户是否允许继续启动；driverReadyOut 保存最终探测状态。
    bool confirmR0OrWarn(
        const HWND ownerWindow,
        bool* const driverReadyOut)
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
            ownerWindow,
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
            ownerWindow,
            L"R0 模式未启用，Cheat Engine 的进程交互无法保证通过 "
            L"KSword 驱动，请小心使用。\n\n是否仍要继续启动？",
            kPluginTitle,
            MB_OKCANCEL | MB_ICONWARNING | MB_DEFBUTTON2 | MB_SETFOREGROUND);
        return warningResult == IDOK;
    }

    // makeStatusPath：为本次启动创建唯一的 CE -> launcher 回执文件名。
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

    // readStatusFile：读取 autorun 写入的短状态值。
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

    // waitForBridgeStatus：最多等待 20 秒，确认 DLL 已被 CE 加载并初始化。
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

    // launchCheatEngine：
    // - 设置桥接 DLL、状态文件和目标 PID 环境变量。
    // - 启动插件内置的 64 位 CE，并等待 autorun 确认桥接初始化。
    BridgeStatus launchCheatEngine(
        const std::wstring& pluginDirectory,
        const DWORD targetProcessId,
        DWORD* const cheatEngineProcessIdOut,
        HANDLE* const cheatEngineProcessHandleOut)
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

        // 只修改当前入口进程的环境，CreateProcess 继承后不会污染系统配置。
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
        return status;
    }

    struct WindowSearchContext
    {
        DWORD processId = 0U;
        HWND window = nullptr;
        int score = 0;
    };

    BOOL CALLBACK findProcessTopLevelWindow(
        const HWND window,
        const LPARAM contextValue)
    {
        auto* const context =
            reinterpret_cast<WindowSearchContext*>(contextValue);
        if (context == nullptr || !::IsWindowVisible(window))
        {
            return TRUE;
        }
        DWORD ownerProcessId = 0U;
        (void)::GetWindowThreadProcessId(window, &ownerProcessId);
        if (ownerProcessId != context->processId)
        {
            return TRUE;
        }

        // Cheat Engine/Lazarus 会先创建一个类名为 Window 的应用宿主，再创建真正的
        // TCustomForm 主窗体并把前者设为 owner。只取第一个顶层窗口会嵌入隐藏宿主，
        // 留下带标题栏的真实主窗体悬浮在 Tab 上。这里对真实主窗体进行确定性评分。
        wchar_t className[128] = {};
        wchar_t windowTitle[256] = {};
        (void)::GetClassNameW(
            window,
            className,
            static_cast<int>(std::size(className)));
        (void)::GetWindowTextW(
            window,
            windowTitle,
            static_cast<int>(std::size(windowTitle)));
        int score = 0;
        if (std::wcscmp(className, L"TCustomForm") == 0)
        {
            score += 1000;
        }
        if (std::wcsstr(windowTitle, L"Cheat Engine") != nullptr)
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

    // waitForCheatEngineWindow：等待 CE 创建可见顶层窗口，供 Tab 容器嵌入。
    HWND waitForCheatEngineWindow(const DWORD processId)
    {
        constexpr std::size_t kAttemptCount = 200U;
        for (std::size_t attempt = 0U; attempt < kAttemptCount; ++attempt)
        {
            WindowSearchContext context{};
            context.processId = processId;
            (void)::EnumWindows(
                findProcessTopLevelWindow,
                reinterpret_cast<LPARAM>(&context));
            if (context.window != nullptr && context.score >= 1500)
            {
                return context.window;
            }
            if (gCheatEngineProcess != nullptr &&
                ::WaitForSingleObject(gCheatEngineProcess, 0U) == WAIT_OBJECT_0)
            {
                return nullptr;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
        return nullptr;
    }

    void resizeEmbeddedWindow(const HWND containerWindow)
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
            clientRectangle.right - clientRectangle.left,
            clientRectangle.bottom - clientRectangle.top,
            TRUE);
    }

    bool embedCheatEngineWindow(
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

        LONG_PTR style = ::GetWindowLongPtrW(cheatEngineWindow, GWL_STYLE);
        style &= ~(static_cast<LONG_PTR>(
            WS_POPUP | WS_CAPTION | WS_THICKFRAME |
            WS_MINIMIZEBOX | WS_MAXIMIZEBOX | WS_SYSMENU));
        style |= WS_CHILD | WS_VISIBLE | WS_CLIPCHILDREN | WS_CLIPSIBLINGS;
        (void)::SetWindowLongPtrW(
            cheatEngineWindow,
            GWL_STYLE,
            style);

        LONG_PTR extendedStyle =
            ::GetWindowLongPtrW(cheatEngineWindow, GWL_EXSTYLE);
        extendedStyle &= ~(static_cast<LONG_PTR>(
            WS_EX_APPWINDOW | WS_EX_WINDOWEDGE | WS_EX_CLIENTEDGE |
            WS_EX_DLGMODALFRAME | WS_EX_STATICEDGE));
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
            SWP_NOACTIVATE | SWP_NOMOVE |
            SWP_NOSIZE | SWP_FRAMECHANGED | SWP_SHOWWINDOW);
        gCheatEngineWindow = cheatEngineWindow;
        resizeEmbeddedWindow(containerWindow);
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
        case WM_CREATE:
            gStatusWindow = ::CreateWindowExW(
                0U,
                L"STATIC",
                L"正在初始化 KSword R0 与 Cheat Engine 桥接…",
                WS_CHILD | WS_VISIBLE | SS_CENTER,
                0,
                0,
                1,
                1,
                window,
                nullptr,
                ::GetModuleHandleW(nullptr),
                nullptr);
            if (gStatusWindow != nullptr)
            {
                (void)::SendMessageW(
                    gStatusWindow,
                    WM_SETFONT,
                    reinterpret_cast<WPARAM>(
                        ::GetStockObject(DEFAULT_GUI_FONT)),
                    TRUE);
            }
            return 0;
        case WM_SIZE:
            if (::IsWindow(gStatusWindow))
            {
                (void)::MoveWindow(
                    gStatusWindow,
                    16,
                    16,
                    LOWORD(lParam) > 32U ? LOWORD(lParam) - 32 : 1,
                    48,
                    TRUE);
            }
            resizeEmbeddedWindow(window);
            return 0;
        case kInitializeTabMessage:
        {
            bool driverReady = false;
            if (!confirmR0OrWarn(window, &driverReady))
            {
                failTab(
                    window,
                    "r0_required",
                    "Enable KSword R0 mode and load the driver before launching.");
                return 0;
            }
            const std::wstring pluginDirectory =
                parentDirectory(currentExecutablePath());
            DWORD cheatEngineProcessId = 0U;
            const BridgeStatus bridgeStatus = launchCheatEngine(
                pluginDirectory,
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
                !embedCheatEngineWindow(window, cheatEngineWindow))
            {
                if (gCheatEngineProcess != nullptr)
                {
                    (void)::TerminateProcess(gCheatEngineProcess, 2U);
                }
                failTab(
                    window,
                    "embed_failed",
                    "Cheat Engine started but its main window could not be embedded.");
                return 0;
            }
            if (::IsWindow(gStatusWindow))
            {
                (void)::ShowWindow(gStatusWindow, SW_HIDE);
            }
            emitJsonLine(
                "tab_embedded",
                "\"cheat_engine_pid\":" +
                std::to_string(cheatEngineProcessId) +
                ",\"r0_ready\":" +
                (driverReady ? "true" : "false") +
                ",\"bridge_ready\":" +
                (bridgeStatus == BridgeStatus::ready ? "true" : "false"));
            (void)::SetTimer(
                window,
                kHostWatchTimerId,
                1000U,
                nullptr);
            return 0;
        }
        case WM_TIMER:
            if (wParam == kHostWatchTimerId)
            {
                // Lazarus 可能在窗体初始化或显示状态变化后重新应用顶层样式。
                // 定时重申嵌入关系和客户区尺寸，确保 CE 始终无边框铺满 Tab。
                if (::IsWindow(gCheatEngineWindow))
                {
                    (void)embedCheatEngineWindow(
                        window,
                        gCheatEngineWindow);
                }
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
            (void)::KillTimer(window, kHostWatchTimerId);
            closeCheatEngine();
            gStatusWindow = nullptr;
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

    // runInfo：输出插件能力，便于离线校验入口和协议。
    int runInfo()
    {
        emitJsonLine(
            "info",
            "\"runtime\":\"executable\",\"plugin_type\":\"hybrid\","
            "\"targets\":[\"process\",\"tab\"],"
            "\"commands\":[\"launch\",\"tab\",\"check\",\"info\"],"
            "\"driver_transport\":\"KswordARK\",\"bridge_api\":6");
        return 0;
    }

    // runDriverCheck：无 GUI 地检查驱动，供构建验证和诊断使用。
    int runDriverCheck()
    {
        const bool ready = isDriverReady();
        emitJsonLine(
            "driver_status",
            std::string("\"r0_ready\":") + (ready ? "true" : "false"));
        return ready ? 0 : 2;
    }
}

// wmain：KSword executable 插件入口。
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
    if (!confirmR0OrWarn(nullptr, &driverReady))
    {
        emitError(
            "r0_required",
            "Enable KSword R0 mode and load the driver before launching.");
        return 2;
    }

    // pluginDirectory 用途：锚定 CE 载荷与两个架构的桥接 DLL。
    const std::wstring pluginDirectory =
        parentDirectory(currentExecutablePath());
    DWORD cheatEngineProcessId = 0U;
    const BridgeStatus bridgeStatus = launchCheatEngine(
        pluginDirectory,
        arguments.targetProcessId,
        &cheatEngineProcessId,
        nullptr);
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
