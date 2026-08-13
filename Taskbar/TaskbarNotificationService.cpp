#include "TaskbarNotificationService.h"

#include <QApplication>
#include <QCoreApplication>
#include <QDateTime>
#include <QGuiApplication>
#include <QSettings>
#include <QWidget>

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#include <dbt.h>

#include <shellapi.h>

namespace
{
    // 包含进入动画预算：频谱淡出 500ms 加通知淡入 500ms 后，正文仍完整显示 5 秒或 2 秒。
    constexpr qint64 kInitialNotificationDurationMs = 6000;
    constexpr qint64 kQueuedNotificationDurationMs = 3000;
    constexpr qint64 kDeviceDeduplicationMs = 500;
    constexpr int kMaximumQueuedNotifications = 32;

    // 三个 GUID 沿用 WindowsMarker 的局部定义，避免引入 SDK 宏定义冲突。
    const GUID kUsbDeviceInterfaceGuid =
        { 0xA5DCBF10, 0x6530, 0x11D2, { 0x90, 0x1F, 0x00, 0xC0, 0x4F, 0xB9, 0x51, 0xED } };
    const GUID kDiskDeviceInterfaceGuid =
        { 0x53F56307, 0xB6BF, 0x11D0, { 0x94, 0xF2, 0x00, 0xA0, 0xC9, 0x1E, 0xFB, 0x8B } };
    const GUID kVolumeDeviceInterfaceGuid =
        { 0x53F5630D, 0xB6BF, 0x11D0, { 0x94, 0xF2, 0x00, 0xA0, 0xC9, 0x1E, 0xFB, 0x8B } };

    // monotonicMilliseconds 返回单调时钟，避免系统校时造成通知轮播突然跳过。
    qint64 monotonicMilliseconds()
    {
        return static_cast<qint64>(::GetTickCount64());
    }

    // truncateText 用 Unicode 字符长度限制剪贴板正文，避免超长内容压垮 32px 高度任务栏。
    QString truncateText(const QString& text, int maximumCharacters)
    {
        if (text.size() <= maximumCharacters)
        {
            return text;
        }
        return text.left(maximumCharacters) + QStringLiteral("...");
    }

    // deviceVolumeDescription 把 DBT_DEVTYP_VOLUME 位图转换为用户可读的盘符列表。
    QString deviceVolumeDescription(ULONG unitMask)
    {
        QStringList drives;
        for (int index = 0; index < 26; ++index)
        {
            if ((unitMask & (1u << index)) != 0)
            {
                drives.push_back(QStringLiteral("%1:").arg(QChar(u'A' + index)));
            }
        }
        return drives.isEmpty() ? QStringLiteral("卷") : QStringLiteral("卷 %1").arg(drives.join(QStringLiteral(", ")));
    }

    // describeDeviceChange 将 Windows 设备广播参数转成紧凑单行文本，适合中间通知栏。
    QString describeDeviceChange(LPARAM lParam)
    {
        if (lParam == 0)
        {
            return QStringLiteral("设备拓扑变化");
        }

        const DEV_BROADCAST_HDR* header = reinterpret_cast<const DEV_BROADCAST_HDR*>(lParam);
        if (header->dbch_devicetype == DBT_DEVTYP_VOLUME)
        {
            const DEV_BROADCAST_VOLUME* volume = reinterpret_cast<const DEV_BROADCAST_VOLUME*>(lParam);
            return deviceVolumeDescription(volume->dbcv_unitmask);
        }

        if (header->dbch_devicetype == DBT_DEVTYP_DEVICEINTERFACE)
        {
            const DEV_BROADCAST_DEVICEINTERFACE_W* device =
                reinterpret_cast<const DEV_BROADCAST_DEVICEINTERFACE_W*>(lParam);
            const QString path = QString::fromWCharArray(device->dbcc_name ? device->dbcc_name : L"");
            const QString kind = path.contains(QStringLiteral("USB"), Qt::CaseInsensitive)
                ? QStringLiteral("USB 设备") : QStringLiteral("设备接口");
            if (path.isEmpty())
            {
                return kind;
            }
            return QStringLiteral("%1 %2").arg(kind, truncateText(path, 96));
        }

        return QStringLiteral("设备拓扑变化");
    }
}

TaskbarNotificationService::TaskbarNotificationService(TaskbarEarthquakeClient* earthquakeClient, QObject* parent)
    : QObject(parent)
    , m_earthquakeClient(earthquakeClient)
{
    // 读取一次持久化开关；这些设置是进程级，因此所有屏幕窗口天然共享同一份配置。
    loadSettings();
    if (m_earthquakeClient != nullptr)
    {
        m_earthquakeClient->setAlertAudioEnabled(m_earthquakeNotificationsEnabled);
    }

    // 创建一个不可见原生窗口作为唯一广播接收点，防止每个屏幕 Taskbar 重复排队同一事件。
    m_messageWindow = new QWidget();
    m_messageWindow->setWindowFlags(Qt::Tool | Qt::FramelessWindowHint | Qt::WindowDoesNotAcceptFocus);
    m_messageWindow->setAttribute(Qt::WA_DontShowOnScreen, true);
    m_messageWindow->setAttribute(Qt::WA_NativeWindow, true);
    m_messageWindow->setGeometry(-10000, -10000, 1, 1);
    const HWND messageWindowHandle = reinterpret_cast<HWND>(m_messageWindow->winId());
    if (messageWindowHandle != nullptr)
    {
        ::AddClipboardFormatListener(messageWindowHandle);
        registerDeviceNotifications();
    }
    qApp->installNativeEventFilter(this);

    // 高优先级地震状态变化直接抢占普通队列；来源状态仅更新设置窗口诊断。
    if (m_earthquakeClient != nullptr)
    {
        connect(m_earthquakeClient, &TaskbarEarthquakeClient::activeWarningsChanged, this,
            &TaskbarNotificationService::refreshEarthquakePresentation);
        connect(m_earthquakeClient, &TaskbarEarthquakeClient::sourceStatusesChanged, this,
            &TaskbarNotificationService::sourceStatusesChanged);
    }

    // 100ms 周期兼顾测试预警到期、网络事件超时和两秒通知轮播，无需后台计时线程。
    m_tickTimer.setInterval(100);
    connect(&m_tickTimer, &QTimer::timeout, this, &TaskbarNotificationService::advancePresentation);
    m_tickTimer.start();
    refreshEarthquakePresentation();
}

TaskbarNotificationService::~TaskbarNotificationService()
{
    // 销毁时先移除原生过滤器，随后注销通知句柄，避免退出过程中回调到已析构服务。
    qApp->removeNativeEventFilter(this);
    unregisterDeviceNotifications();
    if (m_messageWindow != nullptr)
    {
        const HWND messageWindowHandle = reinterpret_cast<HWND>(m_messageWindow->winId());
        if (messageWindowHandle != nullptr)
        {
            ::RemoveClipboardFormatListener(messageWindowHandle);
        }
        delete m_messageWindow;
        m_messageWindow = nullptr;
    }
}

TaskbarNotificationView TaskbarNotificationService::currentNotification() const
{
    // 返回值是轻量 QString 值对象副本，调用者无需同步服务内部队列。
    return m_currentNotification;
}

bool TaskbarNotificationService::hasVisibleNotification() const
{
    // 只要地震或普通通知有标题，Taskbar 中央区域就应显示通知而非时间和频谱。
    return m_earthquakeActive || !m_currentNotification.title.isEmpty();
}

bool TaskbarNotificationService::earthquakeActive() const
{
    // 地震状态独立于当前正文，确保多个来源刷新时背景主题保持稳定。
    return m_earthquakeActive;
}

bool TaskbarNotificationService::clipboardNotificationsEnabled() const
{
    return m_clipboardNotificationsEnabled;
}

bool TaskbarNotificationService::deviceNotificationsEnabled() const
{
    return m_deviceNotificationsEnabled;
}

bool TaskbarNotificationService::earthquakeNotificationsEnabled() const
{
    return m_earthquakeNotificationsEnabled;
}

void TaskbarNotificationService::setClipboardNotificationsEnabled(bool enabled)
{
    // 仅状态真正变化时写盘和发信号，避免设置窗口刷新导致无意义循环。
    if (m_clipboardNotificationsEnabled == enabled)
    {
        return;
    }
    m_clipboardNotificationsEnabled = enabled;
    saveSettings();
    emit settingsChanged();
}

void TaskbarNotificationService::setDeviceNotificationsEnabled(bool enabled)
{
    if (m_deviceNotificationsEnabled == enabled)
    {
        return;
    }
    m_deviceNotificationsEnabled = enabled;
    saveSettings();
    emit settingsChanged();
}

void TaskbarNotificationService::setEarthquakeNotificationsEnabled(bool enabled)
{
    if (m_earthquakeNotificationsEnabled == enabled)
    {
        return;
    }
    m_earthquakeNotificationsEnabled = enabled;
    if (m_earthquakeClient != nullptr)
    {
        m_earthquakeClient->setAlertAudioEnabled(enabled);
    }
    saveSettings();
    refreshEarthquakePresentation();
    emit settingsChanged();
}

void TaskbarNotificationService::injectTestEarthquake()
{
    // 测试按钮仍经由唯一地震客户端，因此所有屏幕同时进入完全相同的警报状态。
    if (m_earthquakeClient != nullptr)
    {
        m_earthquakeClient->injectTestWarning();
    }
}

QList<TaskbarEarthquakeSourceStatus> TaskbarNotificationService::sourceStatuses() const
{
    // 无客户端时返回空列表，设置窗口据此显示连接功能不可用而不是伪造状态。
    return m_earthquakeClient != nullptr ? m_earthquakeClient->sourceStatuses()
        : QList<TaskbarEarthquakeSourceStatus>();
}

bool TaskbarNotificationService::nativeEventFilter(const QByteArray& eventType, void* message, qintptr* result)
{
    // Qt Windows 后端以 windows_generic_MSG 交付 MSG；其它平台或事件类型直接放行。
    if (eventType != QByteArrayLiteral("windows_generic_MSG") && eventType != QByteArrayLiteral("windows_dispatcher_MSG"))
    {
        return false;
    }
    return handleNativeMessage(message, result);
}

bool TaskbarNotificationService::handleNativeMessage(void* message, qintptr* result)
{
    MSG* nativeMessage = static_cast<MSG*>(message);
    if (nativeMessage == nullptr || m_messageWindow == nullptr)
    {
        return false;
    }

    const HWND messageWindowHandle = reinterpret_cast<HWND>(m_messageWindow->winId());
    if (nativeMessage->hwnd != messageWindowHandle)
    {
        return false;
    }

    if (nativeMessage->message == WM_CLIPBOARDUPDATE && m_clipboardNotificationsEnabled)
    {
        enqueueClipboardText();
    }
    else if (nativeMessage->message == WM_DEVICECHANGE)
    {
        handleDeviceChange(nativeMessage->wParam, nativeMessage->lParam);
    }

    if (result != nullptr)
    {
        *result = 0;
    }
    return false;
}

void TaskbarNotificationService::enqueueClipboardText()
{
    // 按用户要求只提取 CF_UNICODETEXT；不读取文件、位图和图标，也不在 Taskbar 中显示图片。
    const HWND messageWindowHandle = m_messageWindow != nullptr ? reinterpret_cast<HWND>(m_messageWindow->winId()) : nullptr;
    if (messageWindowHandle == nullptr || ::OpenClipboard(messageWindowHandle) == FALSE)
    {
        return;
    }

    const HANDLE clipboardData = ::GetClipboardData(CF_UNICODETEXT);
    const wchar_t* source = clipboardData != nullptr ? static_cast<const wchar_t*>(::GlobalLock(clipboardData)) : nullptr;
    if (source == nullptr)
    {
        ::CloseClipboard();
        return;
    }

    QString text = QString::fromWCharArray(source);
    ::GlobalUnlock(clipboardData);
    ::CloseClipboard();
    text.replace(QChar(u'\r'), QChar(u' '));
    text.replace(QChar(u'\n'), QChar(u' '));
    text.replace(QChar(u'\t'), QChar(u' '));
    text = text.simplified();
    if (text.isEmpty())
    {
        return;
    }

    TaskbarNotificationView notification;
    notification.kind = TaskbarNotificationKind::Clipboard;
    notification.source = QStringLiteral("剪贴板");
    notification.title = QStringLiteral("剪贴板新内容");
    notification.body = truncateText(text, 120);
    enqueueNotification(notification);
}

void TaskbarNotificationService::handleDeviceChange(quintptr wParam, qintptr lParam)
{
    // 仅保留 WindowsMarker 关注的接入、移除和拓扑变化消息，避免其它设备广播淹没通知队列。
    if (!m_deviceNotificationsEnabled || (wParam != DBT_DEVICEARRIVAL &&
        wParam != DBT_DEVICEREMOVECOMPLETE && wParam != DBT_DEVNODES_CHANGED))
    {
        return;
    }

    const QString body = describeDeviceChange(static_cast<LPARAM>(lParam));
    const QString key = QStringLiteral("%1|%2").arg(wParam).arg(body);
    const qint64 now = monotonicMilliseconds();
    if (key == m_lastDeviceNotificationKey && now >= m_lastDeviceNotificationMs &&
        now - m_lastDeviceNotificationMs < kDeviceDeduplicationMs)
    {
        return;
    }

    m_lastDeviceNotificationKey = key;
    m_lastDeviceNotificationMs = now;
    TaskbarNotificationView notification;
    notification.kind = TaskbarNotificationKind::Device;
    notification.source = QStringLiteral("设备变化");
    notification.title = wParam == DBT_DEVICEARRIVAL ? QStringLiteral("设备接入")
        : (wParam == DBT_DEVICEREMOVECOMPLETE ? QStringLiteral("设备移除") : QStringLiteral("设备变化"));
    notification.body = body;
    enqueueNotification(notification);
}

void TaskbarNotificationService::enqueueNotification(const TaskbarNotificationView& notification)
{
    // 地震预警出现时普通队列仍可继续累积，但由高优先级状态统一暂停展示。
    if (m_queue.size() >= kMaximumQueuedNotifications)
    {
        m_queue.removeFirst();
    }
    m_queue.push_back(notification);
    if (!m_earthquakeActive && !m_currentNotification.title.isEmpty())
    {
        // 一旦产生积压，正在显示的普通通知也缩短到两秒，保证每条积压消息遵守统一轮播节奏。
        m_currentNormalDurationMs = kQueuedNotificationDurationMs;
    }
    if (!m_earthquakeActive && m_currentNotification.title.isEmpty())
    {
        updateCurrentNormalNotification();
    }
}

void TaskbarNotificationService::updateCurrentNormalNotification()
{
    // 取 FIFO 首项并设置含动画预算的时长：正文完全淡入后分别展示 5 秒或 2 秒。
    if (m_queue.isEmpty())
    {
        const bool changed = !m_currentNotification.title.isEmpty();
        m_currentNotification = TaskbarNotificationView();
        m_currentNormalStartedMs = 0;
        if (changed)
        {
            emit presentationChanged();
        }
        return;
    }

    m_currentNotification = m_queue.takeFirst();
    m_currentNormalStartedMs = monotonicMilliseconds();
    m_currentNormalDurationMs = m_queue.isEmpty() ? kInitialNotificationDurationMs : kQueuedNotificationDurationMs;
    emit presentationChanged();
}

void TaskbarNotificationService::advancePresentation()
{
    // 每个 tick 先检查地震活动是否变化；其为真时刻意不推进普通队列计时。
    refreshEarthquakePresentation();
    if (m_earthquakeActive || m_currentNotification.title.isEmpty() || m_currentNormalStartedMs == 0)
    {
        return;
    }

    const qint64 now = monotonicMilliseconds();
    if (now >= m_currentNormalStartedMs && now - m_currentNormalStartedMs >= m_currentNormalDurationMs)
    {
        updateCurrentNormalNotification();
    }
}

void TaskbarNotificationService::refreshEarthquakePresentation()
{
    // 真实或测试预警只要存在就立即接管，取消/最终报/超时结束后再恢复普通队列。
    const QList<TaskbarEarthquakeEvent> warnings = m_earthquakeClient != nullptr && m_earthquakeNotificationsEnabled
        ? m_earthquakeClient->activeWarnings() : QList<TaskbarEarthquakeEvent>();
    const bool nextEarthquakeActive = !warnings.isEmpty();
    if (nextEarthquakeActive)
    {
        const TaskbarEarthquakeEvent& event = warnings.first();
        TaskbarNotificationView notification;
        notification.kind = TaskbarNotificationKind::Earthquake;
        notification.source = QStringLiteral("地震预警");
        notification.title = QStringLiteral("地震预警 %1").arg(event.hypoCenter.isEmpty() ? QStringLiteral("震源未知") : event.hypoCenter);
        QStringList details;
        if (!event.magnitudeText.isEmpty())
        {
            details.push_back(QStringLiteral("震级 %1").arg(event.magnitudeText));
        }
        if (!event.depthText.isEmpty())
        {
            details.push_back(QStringLiteral("深度 %1 公里").arg(event.depthText));
        }
        if (event.reportNum > 0)
        {
            details.push_back(QStringLiteral("第 %1 报").arg(event.reportNum));
        }
        notification.body = details.isEmpty() ? QStringLiteral("正在接收预警数据") : details.join(QStringLiteral("  |  "));
        notification.earthquake = true;

        const bool contentChanged = !m_earthquakeActive || m_currentNotification.title != notification.title ||
            m_currentNotification.body != notification.body;
        m_earthquakeActive = true;
        m_currentNotification = notification;
        if (contentChanged)
        {
            emit presentationChanged();
        }
        return;
    }

    if (m_earthquakeActive)
    {
        // 离开地震状态时立即发布下一状态；每个 Taskbar UI 负责 0.5 秒淡出警报并再淡入下一页面。
        m_earthquakeActive = false;
        m_currentNotification = TaskbarNotificationView();
        m_currentNormalStartedMs = 0;
        if (!m_queue.isEmpty())
        {
            m_currentNotification = m_queue.takeFirst();
            m_currentNormalStartedMs = monotonicMilliseconds();
            m_currentNormalDurationMs = m_queue.isEmpty()
                ? kInitialNotificationDurationMs : kQueuedNotificationDurationMs;
        }
        emit presentationChanged();
    }
}

void TaskbarNotificationService::loadSettings()
{
    // Taskbar 独立使用 IniFormat，避免主程序全局配置或注册表路径影响这个轻量常驻模块。
    QSettings settings(QCoreApplication::applicationDirPath() + QStringLiteral("/TaskbarNotifications.ini"),
        QSettings::IniFormat);
    m_clipboardNotificationsEnabled = settings.value(QStringLiteral("notifications/clipboardEnabled"), true).toBool();
    m_deviceNotificationsEnabled = settings.value(QStringLiteral("notifications/deviceEnabled"), true).toBool();
    m_earthquakeNotificationsEnabled = settings.value(QStringLiteral("notifications/earthquakeEnabled"), true).toBool();
}

void TaskbarNotificationService::saveSettings() const
{
    // 仅写 TaskbarNotifications.ini 的三个持久化开关，不碰 WindowsMarker 或主程序配置文件。
    QSettings settings(QCoreApplication::applicationDirPath() + QStringLiteral("/TaskbarNotifications.ini"),
        QSettings::IniFormat);
    settings.setValue(QStringLiteral("notifications/clipboardEnabled"), m_clipboardNotificationsEnabled);
    settings.setValue(QStringLiteral("notifications/deviceEnabled"), m_deviceNotificationsEnabled);
    settings.setValue(QStringLiteral("notifications/earthquakeEnabled"), m_earthquakeNotificationsEnabled);
    settings.sync();
}

void TaskbarNotificationService::registerDeviceNotifications()
{
    // 对唯一隐藏窗口注册三类接口及卷广播；Taskbar 每屏窗口本身不直接订阅设备消息。
    const HWND messageWindowHandle = m_messageWindow != nullptr ? reinterpret_cast<HWND>(m_messageWindow->winId()) : nullptr;
    if (messageWindowHandle == nullptr)
    {
        return;
    }

    const GUID* interfaceClasses[] = {
        &kUsbDeviceInterfaceGuid,
        &kDiskDeviceInterfaceGuid,
        &kVolumeDeviceInterfaceGuid
    };
    for (const GUID* interfaceClass : interfaceClasses)
    {
        DEV_BROADCAST_DEVICEINTERFACE_W filter = {};
        filter.dbcc_size = sizeof(filter);
        filter.dbcc_devicetype = DBT_DEVTYP_DEVICEINTERFACE;
        filter.dbcc_classguid = *interfaceClass;
        HDEVNOTIFY handle = ::RegisterDeviceNotificationW(messageWindowHandle, &filter, DEVICE_NOTIFY_WINDOW_HANDLE);
        if (handle != nullptr)
        {
            m_deviceNotificationHandles.push_back(handle);
        }
    }

    DEV_BROADCAST_VOLUME volumeFilter = {};
    volumeFilter.dbcv_size = sizeof(volumeFilter);
    volumeFilter.dbcv_devicetype = DBT_DEVTYP_VOLUME;
    HDEVNOTIFY volumeHandle = ::RegisterDeviceNotificationW(messageWindowHandle, &volumeFilter, DEVICE_NOTIFY_WINDOW_HANDLE);
    if (volumeHandle != nullptr)
    {
        m_deviceNotificationHandles.push_back(volumeHandle);
    }
}

void TaskbarNotificationService::unregisterDeviceNotifications()
{
    // 退出前按注册顺序逐个注销，失败仅代表 Windows 已先行释放了关联设备状态。
    for (void* rawHandle : m_deviceNotificationHandles)
    {
        if (rawHandle != nullptr)
        {
            ::UnregisterDeviceNotification(static_cast<HDEVNOTIFY>(rawHandle));
        }
    }
    m_deviceNotificationHandles.clear();
}
