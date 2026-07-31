#include "StallDetector.h"

#include "../Internationalization/LanguageManager.h"

#include <QApplication>
#include <QCoreApplication>
#include <QEvent>
#include <QPointer>
#include <QTimer>
#include <QWidget>

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#include <commctrl.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <climits>
#include <mutex>
#include <string>
#include <thread>
#include <utility>

namespace
{
    constexpr char kInstalledProperty[] = "KSWORD_GLOBAL_STALL_DETECTOR_INSTALLED";
    constexpr char kEnabledProperty[] = "ksword_stall_detector_enabled";
    constexpr char kThresholdProperty[] = "ksword_stall_detector_threshold_ms";
    constexpr int kHeartbeatIntervalMs = 50;
    constexpr int kCancellationGraceMs = 5000;
    constexpr int kCancelActionButtonId = 41001;
    constexpr int kContinueWaitingButtonId = 41002;

    struct StallDialogTexts
    {
        std::wstring windowTitle;
        std::wstring mainInstruction;
        std::wstring contentTemplate;
        std::wstring cancelAction;
        std::wstring continueWaiting;
    };

    class GlobalStallDetector;
    QPointer<GlobalStallDetector> g_installedDetector;

    ULONGLONG currentTickMilliseconds()
    {
        return ::GetTickCount64();
    }

    int normalizedThresholdMilliseconds(const int thresholdMs)
    {
        return std::clamp(
            thresholdMs,
            ks::ui::kMinimumUiStallThresholdMs,
            ks::ui::kMaximumUiStallThresholdMs);
    }

    class GlobalStallDetector final : public QObject
    {
    public:
        explicit GlobalStallDetector(QApplication* appInstance)
            : QObject(appInstance)
            , m_appInstance(appInstance)
        {
            m_uiThreadId = ::GetCurrentThreadId();
            m_uiThreadHandle = ::OpenThread(
                THREAD_TERMINATE | THREAD_QUERY_LIMITED_INFORMATION | SYNCHRONIZE,
                FALSE,
                m_uiThreadId);

            m_heartbeatTimer.setParent(this);
            m_heartbeatTimer.setInterval(kHeartbeatIntervalMs);
            m_heartbeatTimer.setTimerType(Qt::PreciseTimer);
            connect(&m_heartbeatTimer, &QTimer::timeout, this, [this]()
                {
                    recordHeartbeat();
                });
            connect(appInstance, &QCoreApplication::aboutToQuit, this, [this]()
                {
                    stop();
                });

            refreshLocalizedTexts();
        }

        ~GlobalStallDetector() override
        {
            stop();
            if (m_uiThreadHandle != nullptr)
            {
                ::CloseHandle(m_uiThreadHandle);
                m_uiThreadHandle = nullptr;
            }
        }

        void start()
        {
            bool expected = false;
            if (!m_running.compare_exchange_strong(expected, true))
            {
                return;
            }

            m_lastHeartbeatTick.store(currentTickMilliseconds());
            m_heartbeatStarted.store(false);
            m_heartbeatTimer.start();
            m_watchdogThread = std::thread([this]()
                {
                    watchdogLoop();
                });
        }

        void stop()
        {
            if (!m_running.exchange(false))
            {
                return;
            }

            m_heartbeatTimer.stop();
            closePromptIfVisible();
            if (m_watchdogThread.joinable())
            {
                m_watchdogThread.join();
            }
            m_cancellationRequested.store(false);
            m_cancellationExpiresTick.store(0);
        }

        void setSettings(const bool enabled, const int thresholdMs)
        {
            m_enabled.store(enabled);
            m_thresholdMs.store(normalizedThresholdMilliseconds(thresholdMs));

            if (!enabled)
            {
                m_promptSuppressedUntilHeartbeat.store(false);
                m_cancellationRequested.store(false);
                m_cancellationExpiresTick.store(0);
                closePromptIfVisible();
            }
        }

        bool enabled() const
        {
            return m_enabled.load();
        }

        int thresholdMilliseconds() const
        {
            return m_thresholdMs.load();
        }

        bool cancellationRequested() const
        {
            if (!m_cancellationRequested.load())
            {
                return false;
            }

            const ULONGLONG expiresTick = m_cancellationExpiresTick.load();
            return expiresTick == 0 || currentTickMilliseconds() <= expiresTick;
        }

        void clearCancellationRequest()
        {
            m_cancellationRequested.store(false);
            m_cancellationExpiresTick.store(0);
        }

    protected:
        bool eventFilter(QObject* watchedObject, QEvent* eventObject) override
        {
            if (eventObject != nullptr && eventObject->type() == QEvent::LanguageChange)
            {
                refreshLocalizedTexts();
            }
            return QObject::eventFilter(watchedObject, eventObject);
        }

    private:
        static HRESULT CALLBACK taskDialogCallback(
            const HWND dialogWindow,
            const UINT notification,
            const WPARAM buttonId,
            const LPARAM,
            const LONG_PTR callbackData)
        {
            auto* detector = reinterpret_cast<GlobalStallDetector*>(callbackData);
            if (detector == nullptr)
            {
                return S_OK;
            }

            if (notification == TDN_CREATED)
            {
                detector->m_promptWindow.store(dialogWindow);
                ::SetWindowPos(
                    dialogWindow,
                    HWND_TOPMOST,
                    0,
                    0,
                    0,
                    0,
                    SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE);

                if (!detector->m_running.load() || !detector->isCurrentlyStalled())
                {
                    ::PostMessageW(
                        dialogWindow,
                        TDM_CLICK_BUTTON,
                        static_cast<WPARAM>(kContinueWaitingButtonId),
                        0);
                }
            }
            else if (notification == TDN_BUTTON_CLICKED &&
                static_cast<int>(buttonId) == kCancelActionButtonId)
            {
                detector->requestCancellation();
            }
            else if (notification == TDN_DESTROYED)
            {
                HWND expectedWindow = dialogWindow;
                detector->m_promptWindow.compare_exchange_strong(
                    expectedWindow,
                    nullptr);
            }
            return S_OK;
        }

        void recordHeartbeat()
        {
            const ULONGLONG currentTick = currentTickMilliseconds();
            m_lastHeartbeatTick.store(currentTick);
            m_heartbeatStarted.store(true);
            m_promptSuppressedUntilHeartbeat.store(false);

            if (m_cancellationRequested.load())
            {
                ULONGLONG expiresTick = m_cancellationExpiresTick.load();
                if (expiresTick == 0)
                {
                    m_cancellationExpiresTick.compare_exchange_strong(
                        expiresTick,
                        currentTick + kCancellationGraceMs);
                }
                else if (currentTick > expiresTick)
                {
                    clearCancellationRequest();
                }
            }

            if (QApplication* appInstance = m_appInstance.data())
            {
                QWidget* activeWindow = appInstance->activeWindow();
                if (activeWindow != nullptr)
                {
                    m_activeWindowHandle.store(
                        reinterpret_cast<HWND>(activeWindow->winId()));
                }
            }
            closePromptIfVisible();
        }

        bool isCurrentlyStalled() const
        {
            if (!m_enabled.load() || !m_heartbeatStarted.load())
            {
                return false;
            }

            const ULONGLONG currentTick = currentTickMilliseconds();
            const ULONGLONG lastHeartbeatTick = m_lastHeartbeatTick.load();
            const ULONGLONG elapsedMilliseconds =
                currentTick >= lastHeartbeatTick
                ? currentTick - lastHeartbeatTick
                : 0;
            return elapsedMilliseconds >=
                static_cast<ULONGLONG>(m_thresholdMs.load());
        }

        void watchdogLoop()
        {
            while (m_running.load())
            {
                std::this_thread::sleep_for(std::chrono::milliseconds(kHeartbeatIntervalMs));
                if (!m_running.load() || !isCurrentlyStalled())
                {
                    continue;
                }

                bool expectedSuppressed = false;
                if (!m_promptSuppressedUntilHeartbeat.compare_exchange_strong(
                    expectedSuppressed,
                    true))
                {
                    continue;
                }

                const ULONGLONG currentTick = currentTickMilliseconds();
                const ULONGLONG lastHeartbeatTick = m_lastHeartbeatTick.load();
                const int elapsedMilliseconds = static_cast<int>(std::min<ULONGLONG>(
                    currentTick >= lastHeartbeatTick
                        ? currentTick - lastHeartbeatTick
                        : 0,
                    static_cast<ULONGLONG>(INT_MAX)));
                showStallPrompt(elapsedMilliseconds, m_thresholdMs.load());
            }
        }

        void showStallPrompt(
            const int elapsedMilliseconds,
            const int thresholdMilliseconds)
        {
            StallDialogTexts dialogTexts;
            {
                std::lock_guard<std::mutex> lockGuard(m_textMutex);
                dialogTexts = m_dialogTexts;
            }

            const QString contentText = QString::fromStdWString(dialogTexts.contentTemplate)
                .arg(elapsedMilliseconds)
                .arg(thresholdMilliseconds);
            const std::wstring contentTextWide = contentText.toStdWString();
            TASKDIALOG_BUTTON dialogButtons[] =
            {
                { kCancelActionButtonId, dialogTexts.cancelAction.c_str() },
                { kContinueWaitingButtonId, dialogTexts.continueWaiting.c_str() }
            };

            TASKDIALOGCONFIG dialogConfig = {};
            dialogConfig.cbSize = sizeof(dialogConfig);
            dialogConfig.hInstance = ::GetModuleHandleW(nullptr);
            dialogConfig.dwFlags =
                TDF_ALLOW_DIALOG_CANCELLATION
                | TDF_SIZE_TO_CONTENT;
            dialogConfig.pszWindowTitle = dialogTexts.windowTitle.c_str();
            dialogConfig.pszMainInstruction = dialogTexts.mainInstruction.c_str();
            dialogConfig.pszContent = contentTextWide.c_str();
            dialogConfig.pszMainIcon = TD_WARNING_ICON;
            dialogConfig.pButtons = dialogButtons;
            dialogConfig.cButtons = ARRAYSIZE(dialogButtons);
            dialogConfig.nDefaultButton = kContinueWaitingButtonId;
            dialogConfig.pfCallback = &GlobalStallDetector::taskDialogCallback;
            dialogConfig.lpCallbackData = reinterpret_cast<LONG_PTR>(this);

            int pressedButtonId = 0;
            ::TaskDialogIndirect(
                &dialogConfig,
                &pressedButtonId,
                nullptr,
                nullptr);
            m_promptWindow.store(nullptr);
        }

        void requestCancellation()
        {
            m_cancellationRequested.store(true);
            // 界面恢复心跳前保持取消请求有效；恢复后再保留一个短暂宽限期，
            // 让刚从阻塞调用返回的业务代码有机会读取并处理。
            m_cancellationExpiresTick.store(0);

            if (m_uiThreadHandle != nullptr)
            {
                // CancelSynchronousIo 只请求取消挂在 UI 线程上的同步 I/O，
                // 不会终止线程或破坏 C++ 栈。
                ::CancelSynchronousIo(m_uiThreadHandle);
            }

            if (HWND activeWindow = m_activeWindowHandle.load();
                activeWindow != nullptr && ::IsWindow(activeWindow))
            {
                ::PostMessageW(activeWindow, WM_CANCELMODE, 0, 0);
            }
        }

        void closePromptIfVisible()
        {
            if (HWND promptWindow = m_promptWindow.load();
                promptWindow != nullptr && ::IsWindow(promptWindow))
            {
                ::PostMessageW(
                    promptWindow,
                    TDM_CLICK_BUTTON,
                    static_cast<WPARAM>(kContinueWaitingButtonId),
                    0);
            }
        }

        void refreshLocalizedTexts()
        {
            StallDialogTexts translatedTexts;
            translatedTexts.windowTitle = ks::i18n::text(
                QStringLiteral("stall_detector.dialog.title"),
                QStringLiteral("KSword 卡顿检测器")).toStdWString();
            translatedTexts.mainInstruction = ks::i18n::text(
                QStringLiteral("stall_detector.dialog.instruction"),
                QStringLiteral("检测到界面动作长时间未响应")).toStdWString();
            translatedTexts.contentTemplate = ks::i18n::text(
                QStringLiteral("stall_detector.dialog.content"),
                QStringLiteral(
                    "主界面已连续 %1 毫秒未响应（阈值 %2 毫秒）。\n\n"
                    "您可以请求取消当前动作，或继续等待。\n\n"
                    "取消采用安全的协作式终止：会设置全局取消标记并尝试中止主线程正在等待的同步 I/O，"
                    "不会强制终止线程。无法安全中断的动作可能仍需等待其返回。")).toStdWString();
            translatedTexts.cancelAction = ks::i18n::text(
                QStringLiteral("stall_detector.dialog.cancel"),
                QStringLiteral("请求取消当前动作")).toStdWString();
            translatedTexts.continueWaiting = ks::i18n::text(
                QStringLiteral("stall_detector.dialog.wait"),
                QStringLiteral("继续等待")).toStdWString();

            std::lock_guard<std::mutex> lockGuard(m_textMutex);
            m_dialogTexts = std::move(translatedTexts);
        }

        QPointer<QApplication> m_appInstance;
        QTimer m_heartbeatTimer;
        std::thread m_watchdogThread;
        std::atomic_bool m_running{ false };
        std::atomic_bool m_enabled{ true };
        std::atomic_bool m_heartbeatStarted{ false };
        std::atomic_bool m_promptSuppressedUntilHeartbeat{ false };
        std::atomic_bool m_cancellationRequested{ false };
        std::atomic_int m_thresholdMs{ ks::ui::kDefaultUiStallThresholdMs };
        std::atomic<ULONGLONG> m_lastHeartbeatTick{ 0 };
        std::atomic<ULONGLONG> m_cancellationExpiresTick{ 0 };
        std::atomic<HWND> m_promptWindow{ nullptr };
        std::atomic<HWND> m_activeWindowHandle{ nullptr };
        DWORD m_uiThreadId = 0;
        HANDLE m_uiThreadHandle = nullptr;
        std::mutex m_textMutex;
        StallDialogTexts m_dialogTexts;
    };

    GlobalStallDetector* installedDetector()
    {
        return g_installedDetector.data();
    }
}

void ks::ui::InstallGlobalStallDetector(QApplication* appInstance)
{
    if (appInstance == nullptr || appInstance->property(kInstalledProperty).toBool())
    {
        return;
    }

    if (!appInstance->property(kEnabledProperty).isValid())
    {
        appInstance->setProperty(kEnabledProperty, true);
    }
    if (!appInstance->property(kThresholdProperty).isValid())
    {
        appInstance->setProperty(
            kThresholdProperty,
            kDefaultUiStallThresholdMs);
    }

    auto* detector = new GlobalStallDetector(appInstance);
    detector->setObjectName(QStringLiteral("KSWORD_GLOBAL_STALL_DETECTOR"));
    detector->setSettings(
        appInstance->property(kEnabledProperty).toBool(),
        appInstance->property(kThresholdProperty).toInt());
    g_installedDetector = detector;
    appInstance->installEventFilter(detector);
    appInstance->setProperty(kInstalledProperty, true);
    detector->start();
}

void ks::ui::SetGlobalStallDetectorSettings(
    const bool enabled,
    const int thresholdMs)
{
    QApplication* appInstance =
        qobject_cast<QApplication*>(QCoreApplication::instance());
    if (appInstance == nullptr)
    {
        return;
    }

    const int normalizedThreshold = normalizedThresholdMilliseconds(thresholdMs);
    appInstance->setProperty(kEnabledProperty, enabled);
    appInstance->setProperty(kThresholdProperty, normalizedThreshold);
    if (GlobalStallDetector* detector = installedDetector())
    {
        detector->setSettings(enabled, normalizedThreshold);
    }
}

bool ks::ui::IsGlobalStallDetectorEnabled()
{
    if (GlobalStallDetector* detector = installedDetector())
    {
        return detector->enabled();
    }
    QApplication* appInstance =
        qobject_cast<QApplication*>(QCoreApplication::instance());
    if (appInstance == nullptr ||
        !appInstance->property(kEnabledProperty).isValid())
    {
        return true;
    }
    return appInstance->property(kEnabledProperty).toBool();
}

int ks::ui::GlobalStallDetectorThresholdMs()
{
    if (GlobalStallDetector* detector = installedDetector())
    {
        return detector->thresholdMilliseconds();
    }
    QApplication* appInstance =
        qobject_cast<QApplication*>(QCoreApplication::instance());
    if (appInstance == nullptr ||
        !appInstance->property(kThresholdProperty).isValid())
    {
        return kDefaultUiStallThresholdMs;
    }
    return normalizedThresholdMilliseconds(
        appInstance->property(kThresholdProperty).toInt());
}

bool ks::ui::IsGlobalStallCancellationRequested()
{
    if (GlobalStallDetector* detector = installedDetector())
    {
        return detector->cancellationRequested();
    }
    return false;
}

void ks::ui::ClearGlobalStallCancellationRequest()
{
    if (GlobalStallDetector* detector = installedDetector())
    {
        detector->clearCancellationRequest();
    }
}
