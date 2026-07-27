#include "../Ksword5.1/Ksword5.1/ArkDriverClient/ArkDriverClient.h"

#include <Windows.h>

#include <cerrno>
#include <chrono>
#include <cwchar>
#include <fstream>
#include <string>
#include <thread>
#include <vector>

namespace
{
    constexpr wchar_t kPluginTitle[] = L"KSword Cheat Engine";
    constexpr char kProtocol[] = "ksword-plugin/1";
    constexpr char kPluginId[] = "cheat-engine";

    struct ParsedArguments
    {
        std::wstring command;
        DWORD targetProcessId = 0U;
        bool valid = false;
    };

    enum class BridgeStatus
    {
        ready,
        failed,
        timeout,
        launchFailed
    };

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
        if (parsed.command != L"launch")
        {
            return parsed;
        }

        for (int index = 3; index + 1 < argc; ++index)
        {
            if (std::wstring(argv[index]) == L"--pid")
            {
                parsed.valid =
                    parseUnsignedProcessId(argv[index + 1], &parsed.targetProcessId);
                return parsed;
            }
        }
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
        DWORD* const cheatEngineProcessIdOut)
    {
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
        ::CloseHandle(processInformation.hProcess);
        const BridgeStatus status = waitForBridgeStatus(statusPath);
        (void)::DeleteFileW(statusPath.c_str());
        (void)::DeleteFileW((statusPath + L".theme").c_str());
        (void)::DeleteFileW((statusPath + L".theme.log").c_str());
        return status;
    }

    int runInfo()
    {
        emitJsonLine(
            "info",
            "\"runtime\":\"executable\",\"targets\":[\"process\"],"
            "\"commands\":[\"launch\",\"check\",\"info\"],"
            "\"presentation\":\"standalone_themed_window\","
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
