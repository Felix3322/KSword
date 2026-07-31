#include "pch.h"
#include "MonitorAgent.h"
#include "core/MonitorPipe.h"
#include "hook/HookEngine.h"
#include "hook/HookTargets.h"

namespace apimon
{
    namespace
    {
        std::atomic_bool g_stopRequested{ false };     // g_stopRequested：全局停止标志。
        std::atomic_bool g_processDetachRequested{ false }; // g_processDetachRequested：DLL 正在卸载，worker 不得重新开启会话。
        MonitorConfig g_activeConfig{};                // g_activeConfig：当前已加载的会话配置。
        constexpr DWORD kSessionIdlePollMs = 100;       // kSessionIdlePollMs：等待下一次 UI 会话配置时的低频轮询间隔。
        constexpr DWORD kSessionActivePollMs = 250;     // kSessionActivePollMs：已安装 Hook 后检查停止标记的轮询间隔。

        void TraceAgentFailure(const std::wstring& errorText)
        {
            if (errorText.empty())
            {
                return;
            }

            const std::wstring outputText = L"[APIMonitor_x64] " + errorText + L"\n";
            ::OutputDebugStringW(outputText.c_str());
        }

        // WaitForNextSessionConfig 作用：
        // - 输入：configOut 接收已完整加载且允许启动的下一份会话配置；
        // - 处理：停标记存在时保持 Agent 常驻，等 UI 原子提交新 INI 并清除停标记后才返回；
        // - 返回：获得可启动会话时为 true，DLL 卸载时为 false。
        bool WaitForNextSessionConfig(MonitorConfig* const configOut)
        {
            if (configOut == nullptr)
            {
                return false;
            }

            std::wstring lastErrorText;
            while (!g_processDetachRequested.load())
            {
                MonitorConfig candidateConfig;
                std::wstring errorText;
                if (!LoadMonitorConfigForCurrentProcess(&candidateConfig, &errorText))
                {
                    if (errorText != lastErrorText)
                    {
                        TraceAgentFailure(errorText);
                        lastErrorText = errorText;
                    }
                    ::Sleep(kSessionIdlePollMs);
                    continue;
                }

                lastErrorText.clear();
                if (IsStopFlagPresent(candidateConfig))
                {
                    ::Sleep(kSessionIdlePollMs);
                    continue;
                }

                // 新会话只能在停标记已经撤销后重置停止状态，避免旧会话刚结束就被立即重新启用。
                g_stopRequested.store(false);
                *configOut = candidateConfig;
                return true;
            }
            return false;
        }

        // SessionConfigWasReplaced 作用：
        // - 输入：activeConfigValue 为当前已安装 Hook 的会话配置；
        // - 处理：重新读取原子提交后的 INI，比对 UI 写入的唯一 session_id；
        // - 返回：检测到不同的新会话时为 true，读取失败或旧版无标识配置时为 false。
        bool SessionConfigWasReplaced(const MonitorConfig& activeConfigValue)
        {
            if (activeConfigValue.sessionId.empty())
            {
                return false;
            }

            MonitorConfig observedConfig;
            std::wstring ignoredErrorText;
            if (!LoadMonitorConfigForCurrentProcess(&observedConfig, &ignoredErrorText)
                || observedConfig.sessionId.empty())
            {
                return false;
            }
            return observedConfig.sessionId != activeConfigValue.sessionId;
        }

        // WaitForCurrentSessionStop 作用：
        // - 输入：configValue 为本次已启动会话的稳定配置；
        // - 处理：等待 UI 写入停止标记或 DLL 卸载请求，并把文件标记同步到进程内停止状态；
        // - 返回：无返回值，返回后调用方必须卸载 Hook 并停止管道。
        void WaitForCurrentSessionStop(const MonitorConfig& configValue)
        {
            while (!g_processDetachRequested.load() && !StopRequested())
            {
                if (IsStopFlagPresent(configValue) || SessionConfigWasReplaced(configValue))
                {
                    RequestStop();
                    break;
                }
                ::Sleep(kSessionActivePollMs);
            }
        }

        DWORD WINAPI MonitorWorkerThread(LPVOID parameterValue)
        {
            (void)parameterValue;

            // agentBypassScope：
            // - 输入：无；
            // - 处理：Agent worker 线程自身的会话等待、事件发送和卸载流程不进入监控事件流；
            // - 返回：无返回值，作用域覆盖可重启 worker 的完整生命周期。
            // - 原因：内部控制线程不是被测业务线程，监控它会引入 Wait/File/Loader 自递归噪声，并可能放大为退出期崩溃。
            ScopedInlineHookInternalBypass agentBypassScope;
            while (!g_processDetachRequested.load())
            {
                MonitorConfig configValue;
                if (!WaitForNextSessionConfig(&configValue))
                {
                    break;
                }

                ReplaceActiveConfig(configValue);
                std::wstring errorText;
                if (!StartMonitorPipeServer(configValue, &errorText))
                {
                    if (!g_processDetachRequested.load() && !IsStopFlagPresent(configValue))
                    {
                        TraceAgentFailure(errorText);
                    }
                    // 管道握手失败后保留 worker；UI 可能在下一轮重新建立读取端，不能因为一次 45 秒超时永久失去重启能力。
                    ::Sleep(kSessionIdlePollMs);
                    continue;
                }

                SendMonitorEvent(
                    ks::winapi_monitor::EventCategory::Internal,
                    L"Agent",
                    L"SessionReady",
                    0,
                    L"Agent connected and pipe server is ready.");

                if (!InstallConfiguredHooks(&errorText))
                {
                    SendMonitorEvent(
                        ks::winapi_monitor::EventCategory::Internal,
                        L"Agent",
                        L"InstallHooksFailed",
                        1,
                        errorText);
                    WaitForCurrentSessionStop(configValue);
                    UninstallConfiguredHooks();
                    StopMonitorPipeServer();
                    continue;
                }
                if (!errorText.empty())
                {
                    SendMonitorEvent(
                        ks::winapi_monitor::EventCategory::Internal,
                        L"Agent",
                        L"HooksPartial",
                        0,
                        errorText);
                }

                SendMonitorEvent(
                    ks::winapi_monitor::EventCategory::Internal,
                    L"Agent",
                    L"HooksInstalled",
                    0,
                    L"Configured inline hooks are now active.");

                WaitForCurrentSessionStop(configValue);
                UninstallConfiguredHooks();
                SendMonitorEvent(
                    ks::winapi_monitor::EventCategory::Internal,
                    L"Agent",
                    L"HooksRemoved",
                    0,
                    L"Inline hooks removed and agent is waiting for the next session.");
                StopMonitorPipeServer();
            }
            return 0;
        }
    }

    void OnProcessAttach(const HMODULE moduleHandle)
    {
        ::DisableThreadLibraryCalls(moduleHandle);
        g_processDetachRequested.store(false);
        g_stopRequested.store(false);

        HANDLE workerHandle = ::CreateThread(
            nullptr,
            0,
            &MonitorWorkerThread,
            nullptr,
            0,
            nullptr);
        if (workerHandle != nullptr)
        {
            ::CloseHandle(workerHandle);
        }
        else
        {
            TraceAgentFailure(L"CreateThread for monitor worker failed.");
        }
    }

    void OnProcessDetach()
    {
        g_processDetachRequested.store(true);
        RequestStop();
    }

    const MonitorConfig& ActiveConfig()
    {
        return g_activeConfig;
    }

    void ReplaceActiveConfig(const MonitorConfig& configValue)
    {
        g_activeConfig = configValue;
    }

    bool StopRequested()
    {
        return g_stopRequested.load();
    }

    void RequestStop()
    {
        g_stopRequested.store(true);
    }
}
