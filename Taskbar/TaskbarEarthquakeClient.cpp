#include "TaskbarEarthquakeClient.h"
#include "TaskbarEarthquakeAudioPlayer.h"

#include <QJsonDocument>
#include <QJsonObject>
#include <QMetaObject>

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#include <winhttp.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <cmath>
#include <mutex>
#include <thread>

#pragma comment(lib, "winhttp.lib")

namespace
{
    // 地震源定义沿用 WindowsMarker 已验证的多源配置，默认只连接三个中国实时来源。
    enum class WarningProvider
    {
        FanStudio, // FanStudio 聚合源的 update 报文。
        Wolfx      // Wolfx 各区域源的标准 EEW 报文。
    };

    struct SourceConfig
    {
        const char* id;             // 稳定来源标识。
        const char* name;           // 面向设置窗口的来源名称。
        const wchar_t* host;        // WebSocket 主机名。
        const wchar_t* path;        // WebSocket HTTPS 路径。
        WarningProvider provider;   // 当前来源的 JSON 解析器类型。
        bool enabledByDefault;      // 是否默认建立连接。
    };

    constexpr SourceConfig kSources[] = {
        { "fanstudio-cea", "FanStudio CEA", L"ws.fanstudio.tech", L"/all", WarningProvider::FanStudio, true },
        { "wolfx-cenc", "Wolfx CENC", L"ws-api.wolfx.jp", L"/cenc_eew", WarningProvider::Wolfx, true },
        { "wolfx-sc", "Wolfx Sichuan", L"ws-api.wolfx.jp", L"/sc_eew", WarningProvider::Wolfx, true },
        { "wolfx-fj", "Wolfx Fujian", L"ws-api.wolfx.jp", L"/fj_eew", WarningProvider::Wolfx, false },
        { "wolfx-cq", "Wolfx Chongqing", L"ws-api.wolfx.jp", L"/cq_eew", WarningProvider::Wolfx, false },
        { "wolfx-jma", "Wolfx JMA", L"ws-api.wolfx.jp", L"/jma_eew", WarningProvider::Wolfx, false }
    };
    constexpr int kSourceCount = static_cast<int>(std::size(kSources));
    constexpr ULONGLONG kActiveNoUpdateTimeoutMs = 90ull * 1000ull;
    constexpr DWORD kReconnectBaseMs = 2000;
    constexpr DWORD kReconnectMaxMs = 30000;
    constexpr DWORD kServerBusyReconnectMs = 60000;
    constexpr DWORD kKeepalivePingIntervalMs = 30000;

    // ParsedWarningMessage 是不同来源 JSON 统一后的内部报文表示。
    struct ParsedWarningMessage
    {
        bool hasEvent = false;      // 是否包含有效地震事件字段。
        bool heartbeat = false;     // 是否仅为心跳/ping/pong。
        bool finalReport = false;   // 当前来源是否已发布最终报。
        bool canceled = false;      // 当前来源是否已取消该预警。
        QString eventId;            // 原始事件标识，当前仅保留用于诊断。
        QString source;             // 服务端提供的来源文本。
        QString originTime;         // 地震发生时间。
        QString hypoCenter;         // 震中位置文本。
        double magnitude = 0.0;     // 报文震级。
        double depth = 0.0;         // 报文深度，单位公里。
        double latitude = 0.0;      // 震中纬度。
        double longitude = 0.0;     // 震中经度。
        int reportNum = 0;          // 当前报次。
    };

    // 读取 JSON 字符串时按多个候选字段名兼容 WindowsMarker 已支持的服务端变体。
    QString firstStringValue(const QJsonObject& object, std::initializer_list<const char*> keys)
    {
        for (const char* key : keys)
        {
            const QJsonValue value = object.value(QLatin1String(key));
            if (value.isString())
            {
                const QString text = value.toString().trimmed();
                if (!text.isEmpty())
                {
                    return text;
                }
            }
            if (value.isDouble())
            {
                return QString::number(value.toDouble(), 'f', 0);
            }
        }
        return QString();
    }

    // 读取 JSON 数值时保留 0 作为未提供或无效字段，避免用不可靠数据触发高等级音频。
    double firstDoubleValue(const QJsonObject& object, std::initializer_list<const char*> keys)
    {
        for (const char* key : keys)
        {
            const QJsonValue value = object.value(QLatin1String(key));
            if (value.isDouble())
            {
                return value.toDouble();
            }
            if (value.isString())
            {
                bool converted = false;
                const double number = value.toString().toDouble(&converted);
                if (converted)
                {
                    return number;
                }
            }
        }
        return 0.0;
    }

    // 读取 JSON 整数时容忍服务端把报次编码成字符串的情况。
    int firstIntValue(const QJsonObject& object, std::initializer_list<const char*> keys)
    {
        for (const char* key : keys)
        {
            const QJsonValue value = object.value(QLatin1String(key));
            if (value.isDouble())
            {
                return value.toInt();
            }
            if (value.isString())
            {
                bool converted = false;
                const int number = value.toString().toInt(&converted);
                if (converted)
                {
                    return number;
                }
            }
        }
        return 0;
    }

    // 读取 JSON 布尔值时同时识别布尔值和常见文本状态。
    bool firstBoolValue(const QJsonObject& object, std::initializer_list<const char*> keys)
    {
        for (const char* key : keys)
        {
            const QJsonValue value = object.value(QLatin1String(key));
            if (value.isBool())
            {
                return value.toBool();
            }
            if (value.isString())
            {
                const QString text = value.toString().trimmed().toLower();
                if (text == QStringLiteral("true") || text == QStringLiteral("yes") ||
                    text == QStringLiteral("final") || text == QStringLiteral("cancel") ||
                    text == QStringLiteral("cancelled"))
                {
                    return true;
                }
            }
        }
        return false;
    }

    // containsInsensitive 用于识别各种来源自定义的 status/type 字段而不依赖大小写。
    bool containsInsensitive(const QString& text, const QString& needle)
    {
        return text.contains(needle, Qt::CaseInsensitive);
    }

    // parseWolfxMessage 解析 Wolfx CENC、四川、福建、重庆和 JMA 的统一 EEW 报文。
    ParsedWarningMessage parseWolfxMessage(const QByteArray& payload)
    {
        ParsedWarningMessage parsed;
        const QJsonDocument document = QJsonDocument::fromJson(payload);
        if (!document.isObject())
        {
            return parsed;
        }

        const QJsonObject object = document.object();
        const QString type = firstStringValue(object, { "type", "Type" });
        parsed.heartbeat = containsInsensitive(type, QStringLiteral("heart")) ||
            containsInsensitive(type, QStringLiteral("ping")) ||
            containsInsensitive(type, QStringLiteral("pong")) ||
            object.contains(QStringLiteral("heartbeat"));
        parsed.eventId = firstStringValue(object, { "EventID", "EventId", "event_id", "ID", "id" });
        parsed.source = firstStringValue(object, { "Source", "source" });
        parsed.originTime = firstStringValue(object, { "OriginTime", "originTime", "origin_time" });
        parsed.hypoCenter = firstStringValue(object, { "HypoCenter", "Hypocenter", "hypocenter", "placeName" });
        parsed.magnitude = firstDoubleValue(object, { "Magnitude", "Magunitude", "magnitude" });
        parsed.depth = firstDoubleValue(object, { "Depth", "depth" });
        parsed.latitude = firstDoubleValue(object, { "Latitude", "latitude" });
        parsed.longitude = firstDoubleValue(object, { "Longitude", "longitude" });
        parsed.reportNum = firstIntValue(object, { "ReportNum", "Serial", "reportNum", "updates" });
        const QString status = firstStringValue(object, { "ReportStatus", "Status", "status" });
        parsed.finalReport = firstBoolValue(object, { "Final", "isFinal", "is_final" }) ||
            containsInsensitive(status, QStringLiteral("final"));
        parsed.canceled = firstBoolValue(object, { "Cancel", "Canceled", "Cancelled", "isCancel", "is_cancel" }) ||
            containsInsensitive(status, QStringLiteral("cancel"));
        parsed.hasEvent = !parsed.eventId.isEmpty() || !parsed.hypoCenter.isEmpty() || parsed.magnitude > 0.0;
        return parsed;
    }

    // parseFanStudioMessage 只接受 CEA/CEA-PR 的实时 update 数据，过滤其它聚合频道事件。
    ParsedWarningMessage parseFanStudioMessage(const QByteArray& payload)
    {
        ParsedWarningMessage parsed;
        const QJsonDocument document = QJsonDocument::fromJson(payload);
        if (!document.isObject())
        {
            return parsed;
        }

        const QJsonObject object = document.object();
        const QString type = firstStringValue(object, { "type", "Type" });
        parsed.heartbeat = containsInsensitive(type, QStringLiteral("heart")) ||
            containsInsensitive(type, QStringLiteral("ping")) ||
            containsInsensitive(type, QStringLiteral("pong"));
        if (parsed.heartbeat || !containsInsensitive(type, QStringLiteral("update")))
        {
            return parsed;
        }

        parsed.source = firstStringValue(object, { "source", "Source" }).toLower();
        if (parsed.source != QStringLiteral("cea") && parsed.source != QStringLiteral("cea-pr"))
        {
            return parsed;
        }

        parsed.eventId = firstStringValue(object, { "eventId", "id", "EventID" });
        parsed.originTime = firstStringValue(object, { "shockTime", "originTime", "OriginTime" });
        parsed.hypoCenter = firstStringValue(object, { "placeName", "HypoCenter" });
        parsed.magnitude = firstDoubleValue(object, { "magnitude", "Magnitude" });
        parsed.depth = firstDoubleValue(object, { "depth", "Depth" });
        parsed.latitude = firstDoubleValue(object, { "latitude", "Latitude" });
        parsed.longitude = firstDoubleValue(object, { "longitude", "Longitude" });
        parsed.reportNum = firstIntValue(object, { "updates", "ReportNum" });
        const QString status = firstStringValue(object, { "status", "Status" });
        parsed.finalReport = firstBoolValue(object, { "Final", "isFinal", "final" }) ||
            containsInsensitive(status, QStringLiteral("final"));
        parsed.canceled = firstBoolValue(object, { "Cancel", "isCancel", "cancel" }) ||
            containsInsensitive(status, QStringLiteral("cancel"));
        parsed.hasEvent = !parsed.eventId.isEmpty() || !parsed.hypoCenter.isEmpty();
        return parsed;
    }

    // parseMessageForProvider 分派各来源的 JSON 适配器，输出统一的预警字段。
    ParsedWarningMessage parseMessageForProvider(WarningProvider provider, const QByteArray& payload)
    {
        return provider == WarningProvider::FanStudio ? parseFanStudioMessage(payload) : parseWolfxMessage(payload);
    }

    // makeLocationKey 以经纬度 0.01 度精度合并多源的同一震中，缺坐标时回退到地点文本。
    QString makeLocationKey(const ParsedWarningMessage& parsed)
    {
        if (!qFuzzyIsNull(parsed.latitude) || !qFuzzyIsNull(parsed.longitude))
        {
            return QStringLiteral("%1,%2")
                .arg(parsed.latitude, 0, 'f', 2)
                .arg(parsed.longitude, 0, 'f', 2);
        }
        return parsed.hypoCenter.trimmed();
    }

    // sleepUntilStop 将长重连等待分段，以便 stop() 能在一百毫秒量级响应。
    bool sleepUntilStop(const std::atomic_bool& stopRequested, DWORD milliseconds)
    {
        DWORD elapsed = 0;
        while (elapsed < milliseconds && !stopRequested.load())
        {
            const DWORD step = std::min<DWORD>(100, milliseconds - elapsed);
            ::Sleep(step);
            elapsed += step;
        }
        return stopRequested.load();
    }
}

// Private 将 WinHTTP 线程、事件聚合和可选音频队列收束到实现文件，保持 Taskbar 公共头稳定。
class TaskbarEarthquakeClient::Private
{
public:
    struct SourceReading
    {
        bool present = false;      // 该来源是否曾报告该事件。
        bool ended = false;        // 该来源是否发布最终报或取消。
        bool canceled = false;     // 该来源是否明确取消。
        double magnitude = 0.0;    // 该来源的最近震级。
        double depth = 0.0;        // 该来源的最近深度。
        int reportNum = 0;         // 该来源的最近报次。
    };

    struct AggregatedEvent
    {
        QString locationKey;                       // 按震中位置聚合的键。
        QString hypoCenter;                        // 第一个有效位置文本。
        QString originTime;                        // 第一个有效发生时间。
        double latitude = 0.0;                      // 聚合后的纬度。
        double longitude = 0.0;                     // 聚合后的经度。
        ULONGLONG lastUpdateTick = 0;               // 最近有效报文时间。
        bool testEvent = false;                     // true 代表本地设置页测试预警。
        ULONGLONG testExpirationTick = 0;           // 测试预警的自动结束时间。
        std::array<SourceReading, kSourceCount> readings; // 每来源的当前读数。
    };

    struct SourceRuntime
    {
        std::thread thread;                  // 该来源唯一接收线程。
        std::mutex socketMutex;              // 协调 stop 与阻塞 receive 的套接字关闭。
        HINTERNET socket = nullptr;          // 当前已升级的 WebSocket 句柄。
        std::atomic_bool connected{ false }; // 当前连接状态。
        std::atomic_bool everConnected{ false }; // 本进程中至少一次成功连接。
        std::atomic_bool preferDirect{ false }; // 上次直连成功后优先跳过系统代理。
        std::atomic<ULONGLONG> lastMessageTick{ 0 }; // 最近数据/心跳到达时间。
        std::atomic<ULONGLONG> lastPingTick{ 0 }; // 最近发送 ping 的单调时钟。
        std::atomic<ULONGLONG> latencyMs{ 0 }; // ping/pong 的往返延迟。
    };

    // 构造函数：保存外部 QObject，创建运行目录音频播放器但不加载任何嵌入式音频资源。
    explicit Private(TaskbarEarthquakeClient* owner)
        : owner(owner)
        , audioPlayer(new TaskbarEarthquakeAudioPlayer(owner))
    {
    }

    // 析构函数：调用 stop 后释放成员；线程对象均已 join，不存在悬空 WinHTTP 句柄。
    ~Private()
    {
        stop();
    }

    // start：启动默认来源的工作线程；重复调用不创建第二组连接。
    void start()
    {
        if (started.exchange(true))
        {
            return;
        }

        stopRequested.store(false);
        for (int sourceIndex = 0; sourceIndex < kSourceCount; ++sourceIndex)
        {
            if (!kSources[sourceIndex].enabledByDefault)
            {
                continue;
            }
            runtimes[sourceIndex].thread = std::thread(&Private::sourceThreadMain, this, sourceIndex);
        }
        keepaliveThread = std::thread(&Private::keepaliveThreadMain, this);
    }

    // stop：先关闭所有 WebSocket 打断 receive，再等待每个来源线程有序退出。
    void stop()
    {
        if (!started.exchange(false))
        {
            return;
        }

        stopRequested.store(true);
        for (int sourceIndex = 0; sourceIndex < kSourceCount; ++sourceIndex)
        {
            closeSourceSocket(sourceIndex);
        }
        if (keepaliveThread.joinable())
        {
            keepaliveThread.join();
        }
        for (SourceRuntime& runtime : runtimes)
        {
            if (runtime.thread.joinable())
            {
                runtime.thread.join();
            }
        }
    }

    // warningsSnapshot：清理超时事件后构造 UI 不可变快照，调用方不持有锁。
    QList<TaskbarEarthquakeEvent> warningsSnapshot()
    {
        std::lock_guard<std::mutex> lock(eventsMutex);
        const ULONGLONG now = ::GetTickCount64();
        pruneExpiredEventsLocked(now);
        QList<TaskbarEarthquakeEvent> warnings;
        for (const AggregatedEvent& event : events)
        {
            if (!isEventActiveLocked(event, now))
            {
                continue;
            }
            TaskbarEarthquakeEvent view;
            view.locationKey = event.locationKey;
            view.hypoCenter = event.hypoCenter;
            view.originTime = event.originTime;
            view.magnitudeText = combinedReadingText(event, true);
            view.depthText = combinedReadingText(event, false);
            view.sourcesText = activeSourcesText(event);
            view.reportNum = maxActiveReportNumber(event);
            view.sourceCount = activeSourceCount(event);
            warnings.push_back(view);
        }
        return warnings;
    }

    // statusesSnapshot：从原子连接状态读取诊断信息，不需要长期持有网络线程的 socketMutex。
    QList<TaskbarEarthquakeSourceStatus> statusesSnapshot() const
    {
        const ULONGLONG now = ::GetTickCount64();
        QList<TaskbarEarthquakeSourceStatus> statuses;
        for (int sourceIndex = 0; sourceIndex < kSourceCount; ++sourceIndex)
        {
            const SourceRuntime& runtime = runtimes[sourceIndex];
            TaskbarEarthquakeSourceStatus status;
            status.id = QLatin1String(kSources[sourceIndex].id);
            status.name = QLatin1String(kSources[sourceIndex].name);
            status.enabled = kSources[sourceIndex].enabledByDefault;
            status.connected = runtime.connected.load();
            status.everConnected = runtime.everConnected.load();
            const ULONGLONG lastMessage = runtime.lastMessageTick.load();
            status.lastMessageAgeMs = lastMessage != 0 && now >= lastMessage ? now - lastMessage : 0;
            status.latencyMs = runtime.latencyMs.load();
            statuses.push_back(status);
        }
        return statuses;
    }

    // injectTestWarning：创建一条十秒测试预警，刻意绕过网络而复用实际活动态和红色主题路径。
    void injectTestWarning()
    {
        const ULONGLONG now = ::GetTickCount64();
        {
            std::lock_guard<std::mutex> lock(eventsMutex);
            events.erase(std::remove_if(events.begin(), events.end(), [](const AggregatedEvent& event) {
                return event.testEvent;
            }), events.end());

            AggregatedEvent testEvent;
            testEvent.locationKey = QStringLiteral("__taskbar_test_earthquake__");
            testEvent.hypoCenter = QStringLiteral("四川省阿坝州汶川县");
            testEvent.originTime = QStringLiteral("测试预警");
            testEvent.latitude = 31.0;
            testEvent.longitude = 103.4;
            testEvent.lastUpdateTick = now;
            testEvent.testEvent = true;
            testEvent.testExpirationTick = now + 10ull * 1000ull;
            SourceReading& reading = testEvent.readings[0];
            reading.present = true;
            reading.magnitude = 6.0;
            reading.depth = 10.0;
            reading.reportNum = 1;
            events.push_back(std::move(testEvent));
        }
        postWarningChange();
        queueAudioForReport(6.0, false);
    }

    // setAlertAudioEnabled：仅控制可选 sounds/ 播放队列；关闭时清空尚未播放内容并立即静音。
    void setAlertAudioEnabled(bool enabled)
    {
        alertAudioEnabled = enabled;
        if (audioPlayer != nullptr)
        {
            audioPlayer->setEnabled(alertAudioEnabled);
        }
    }

    // sourceThreadMain：维护单个来源的 WinHTTP WebSocket，失败时指数退避重连。
    void sourceThreadMain(int sourceIndex)
    {
        SourceRuntime& runtime = runtimes[sourceIndex];
        const SourceConfig& config = kSources[sourceIndex];
        HINTERNET session = ::WinHttpOpen(L"KSword Taskbar/1.0 EEW", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
            WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
        if (session == nullptr)
        {
            return;
        }

        ::WinHttpSetTimeouts(session, 5000, 5000, 5000, 90000);
        DWORD secureProtocols = WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_2;
#ifdef WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_3
        secureProtocols |= WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_3;
#endif
        ::WinHttpSetOption(session, WINHTTP_OPTION_SECURE_PROTOCOLS, &secureProtocols, sizeof(secureProtocols));

        DWORD reconnectDelayMs = kReconnectBaseMs;
        while (!stopRequested.load())
        {
            DWORD httpStatus = 0;
            DWORD lastError = ERROR_SUCCESS;
            bool usedDirect = runtime.preferDirect.load();
            HINTERNET socket = connectSourceWebSocket(session, config, usedDirect, &httpStatus, &lastError);
            if (socket == nullptr && httpStatus == 0 && lastError != ERROR_WINHTTP_TIMEOUT && !stopRequested.load())
            {
                usedDirect = !usedDirect;
                socket = connectSourceWebSocket(session, config, usedDirect, &httpStatus, &lastError);
            }

            if (socket == nullptr)
            {
                runtime.connected.store(false);
                postSourceStatusChange();
                const bool serverBusy = httpStatus == 429 || httpStatus == 503 || lastError == ERROR_WINHTTP_TIMEOUT;
                const DWORD delay = serverBusy ? kServerBusyReconnectMs : reconnectDelayMs;
                sleepUntilStop(stopRequested, delay);
                reconnectDelayMs = std::min<DWORD>(kReconnectMaxMs, reconnectDelayMs + kReconnectBaseMs);
                continue;
            }

            reconnectDelayMs = kReconnectBaseMs;
            runtime.preferDirect.store(usedDirect);
            {
                std::lock_guard<std::mutex> lock(runtime.socketMutex);
                runtime.socket = socket;
            }
            runtime.connected.store(true);
            runtime.everConnected.store(true);
            postSourceStatusChange();
            receiveSourceMessages(sourceIndex, socket);
            closeSourceSocketIfCurrent(sourceIndex, socket);
            runtime.connected.store(false);
            postSourceStatusChange();
            if (!stopRequested.load())
            {
                sleepUntilStop(stopRequested, reconnectDelayMs);
            }
        }

        ::WinHttpCloseHandle(session);
    }

    // connectSourceWebSocket：完成 HTTPS 升级，返回成功的 WebSocket 或 nullptr，并回传失败类型。
    HINTERNET connectSourceWebSocket(HINTERNET session, const SourceConfig& config, bool bypassProxy,
        DWORD* httpStatus, DWORD* lastError)
    {
        if (httpStatus != nullptr)
        {
            *httpStatus = 0;
        }
        if (lastError != nullptr)
        {
            *lastError = ERROR_SUCCESS;
        }

        HINTERNET connection = ::WinHttpConnect(session, config.host, INTERNET_DEFAULT_HTTPS_PORT, 0);
        if (connection == nullptr)
        {
            if (lastError != nullptr)
            {
                *lastError = ::GetLastError();
            }
            return nullptr;
        }

        HINTERNET request = ::WinHttpOpenRequest(connection, L"GET", config.path, nullptr,
            WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE);
        if (request == nullptr)
        {
            if (lastError != nullptr)
            {
                *lastError = ::GetLastError();
            }
            ::WinHttpCloseHandle(connection);
            return nullptr;
        }

        if (bypassProxy)
        {
            WINHTTP_PROXY_INFO proxyInfo = {};
            proxyInfo.dwAccessType = WINHTTP_ACCESS_TYPE_NO_PROXY;
            proxyInfo.lpszProxy = WINHTTP_NO_PROXY_NAME;
            proxyInfo.lpszProxyBypass = WINHTTP_NO_PROXY_BYPASS;
            ::WinHttpSetOption(request, WINHTTP_OPTION_PROXY, &proxyInfo, sizeof(proxyInfo));
        }

        ::WinHttpSetOption(request, WINHTTP_OPTION_UPGRADE_TO_WEB_SOCKET, nullptr, 0);
        const BOOL sent = ::WinHttpSendRequest(request, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
            WINHTTP_NO_REQUEST_DATA, 0, 0, 0);
        const BOOL received = sent != FALSE && ::WinHttpReceiveResponse(request, nullptr) != FALSE;
        if (received == FALSE)
        {
            if (lastError != nullptr)
            {
                *lastError = ::GetLastError();
            }
            ::WinHttpCloseHandle(request);
            ::WinHttpCloseHandle(connection);
            return nullptr;
        }

        DWORD status = 0;
        DWORD statusSize = sizeof(status);
        ::WinHttpQueryHeaders(request, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
            WINHTTP_HEADER_NAME_BY_INDEX, &status, &statusSize, WINHTTP_NO_HEADER_INDEX);
        if (httpStatus != nullptr)
        {
            *httpStatus = status;
        }
        if (status != 101)
        {
            ::WinHttpCloseHandle(request);
            ::WinHttpCloseHandle(connection);
            return nullptr;
        }

        HINTERNET socket = ::WinHttpWebSocketCompleteUpgrade(request, 0);
        if (socket == nullptr && lastError != nullptr)
        {
            *lastError = ::GetLastError();
        }
        ::WinHttpCloseHandle(request);
        ::WinHttpCloseHandle(connection);
        return socket;
    }

    // receiveSourceMessages：接收分片文本帧，完整报文才交给 JSON 解析和事件聚合。
    void receiveSourceMessages(int sourceIndex, HINTERNET socket)
    {
        SourceRuntime& runtime = runtimes[sourceIndex];
        QByteArray message;
        std::array<unsigned char, 8192> buffer = {};
        while (!stopRequested.load())
        {
            DWORD bytesRead = 0;
            WINHTTP_WEB_SOCKET_BUFFER_TYPE bufferType = WINHTTP_WEB_SOCKET_UTF8_MESSAGE_BUFFER_TYPE;
            const DWORD result = ::WinHttpWebSocketReceive(socket, buffer.data(),
                static_cast<DWORD>(buffer.size()), &bytesRead, &bufferType);
            if (result != ERROR_SUCCESS || bufferType == WINHTTP_WEB_SOCKET_CLOSE_BUFFER_TYPE)
            {
                break;
            }

            const ULONGLONG now = ::GetTickCount64();
            runtime.lastMessageTick.store(now);
            if (runtime.lastPingTick.load() != 0)
            {
                const ULONGLONG lastPing = runtime.lastPingTick.exchange(0);
                if (now >= lastPing)
                {
                    runtime.latencyMs.store(now - lastPing);
                }
            }
            postSourceStatusChange();

            if (bufferType != WINHTTP_WEB_SOCKET_UTF8_FRAGMENT_BUFFER_TYPE &&
                bufferType != WINHTTP_WEB_SOCKET_UTF8_MESSAGE_BUFFER_TYPE)
            {
                continue;
            }

            message.append(reinterpret_cast<const char*>(buffer.data()), static_cast<qsizetype>(bytesRead));
            if (bufferType == WINHTTP_WEB_SOCKET_UTF8_FRAGMENT_BUFFER_TYPE)
            {
                continue;
            }

            const ParsedWarningMessage parsed = parseMessageForProvider(kSources[sourceIndex].provider, message);
            message.clear();
            applySourceEvent(sourceIndex, parsed);
        }
    }

    // applySourceEvent：把来源报文合并至按坐标去重的事件表，并把变化异步通知 GUI 线程。
    void applySourceEvent(int sourceIndex, const ParsedWarningMessage& parsed)
    {
        if (!parsed.hasEvent || parsed.heartbeat)
        {
            return;
        }

        const QString locationKey = makeLocationKey(parsed);
        if (locationKey.isEmpty())
        {
            return;
        }

        const ULONGLONG now = ::GetTickCount64();
        bool stateChanged = false;
        {
            std::lock_guard<std::mutex> lock(eventsMutex);
            auto iterator = std::find_if(events.begin(), events.end(), [&locationKey](const AggregatedEvent& event) {
                return event.locationKey == locationKey;
            });
            if (iterator == events.end())
            {
                if (parsed.canceled)
                {
                    return;
                }
                AggregatedEvent event;
                event.locationKey = locationKey;
                event.hypoCenter = parsed.hypoCenter;
                event.originTime = parsed.originTime;
                event.latitude = parsed.latitude;
                event.longitude = parsed.longitude;
                event.lastUpdateTick = now;
                events.push_back(std::move(event));
                iterator = std::prev(events.end());
            }

            AggregatedEvent& event = *iterator;
            if (event.hypoCenter.isEmpty())
            {
                event.hypoCenter = parsed.hypoCenter;
            }
            if (event.originTime.isEmpty())
            {
                event.originTime = parsed.originTime;
            }
            if (qFuzzyIsNull(event.latitude) && qFuzzyIsNull(event.longitude))
            {
                event.latitude = parsed.latitude;
                event.longitude = parsed.longitude;
            }
            event.lastUpdateTick = now;
            SourceReading& reading = event.readings[sourceIndex];
            reading.present = true;
            reading.ended = parsed.finalReport || parsed.canceled;
            reading.canceled = parsed.canceled;
            reading.magnitude = parsed.magnitude;
            reading.depth = parsed.depth;
            reading.reportNum = parsed.reportNum;
            stateChanged = true;
        }

        if (stateChanged)
        {
            postWarningChange();
            TaskbarEarthquakeClient* target = owner;
            QMetaObject::invokeMethod(target, [target, magnitude = parsed.magnitude, canceled = parsed.canceled]() {
                emit target->reportReceived(magnitude, canceled);
            }, Qt::QueuedConnection);
        }
    }

    // closeSourceSocket：关闭一个当前套接字，WinHTTP receive 将返回并允许对应线程退出或重连。
    void closeSourceSocket(int sourceIndex)
    {
        SourceRuntime& runtime = runtimes[sourceIndex];
        HINTERNET socket = nullptr;
        {
            std::lock_guard<std::mutex> lock(runtime.socketMutex);
            socket = runtime.socket;
            runtime.socket = nullptr;
        }
        if (socket != nullptr)
        {
            ::WinHttpCloseHandle(socket);
        }
    }

    // closeSourceSocketIfCurrent：仅接收线程仍拥有该句柄时关闭，避免 stop() 与接收线程双重关闭。
    void closeSourceSocketIfCurrent(int sourceIndex, HINTERNET socket)
    {
        SourceRuntime& runtime = runtimes[sourceIndex];
        bool ownsSocket = false;
        {
            std::lock_guard<std::mutex> lock(runtime.socketMutex);
            if (runtime.socket == socket)
            {
                runtime.socket = nullptr;
                ownsSocket = true;
            }
        }
        if (ownsSocket)
        {
            ::WinHttpCloseHandle(socket);
        }
    }

    // sendSourcePing：保活线程是唯一发送方；socketMutex 将 send 与 stop() 的关闭操作串行化。
    void sendSourcePing(int sourceIndex)
    {
        // 保活线程是唯一发送方；socketMutex 将 send 与 stop() 的关闭操作串行化。
        SourceRuntime& runtime = runtimes[sourceIndex];
        std::lock_guard<std::mutex> lock(runtime.socketMutex);
        if (runtime.socket == nullptr || !runtime.connected.load())
        {
            return;
        }

        const char ping[] = "ping";
        const ULONGLONG now = ::GetTickCount64();
        const DWORD result = ::WinHttpWebSocketSend(runtime.socket, WINHTTP_WEB_SOCKET_UTF8_MESSAGE_BUFFER_TYPE,
            const_cast<char*>(ping), static_cast<DWORD>(sizeof(ping) - 1));
        if (result == ERROR_SUCCESS)
        {
            runtime.lastPingTick.store(now);
        }
    }

    // keepaliveThreadMain：每 30 秒发送一次轻量 ping，接收线程仍独占 WebSocket receive 调用。
    void keepaliveThreadMain()
    {
        while (!stopRequested.load())
        {
            for (int sourceIndex = 0; sourceIndex < kSourceCount; ++sourceIndex)
            {
                if (stopRequested.load())
                {
                    break;
                }
                if (kSources[sourceIndex].enabledByDefault)
                {
                    sendSourcePing(sourceIndex);
                }
            }
            sleepUntilStop(stopRequested, kKeepalivePingIntervalMs);
        }
    }

    // isEventActiveLocked：明确取消后结束；最终报仍保留至来源取消或九十秒无更新，保持 WindowsMarker 语义。
    bool isEventActiveLocked(const AggregatedEvent& event, ULONGLONG now) const
    {
        if (event.testEvent)
        {
            return now < event.testExpirationTick;
        }
        if (now >= event.lastUpdateTick && now - event.lastUpdateTick > kActiveNoUpdateTimeoutMs)
        {
            return false;
        }
        return activeSourceCount(event) > 0;
    }

    // pruneExpiredEventsLocked：清除超时、测试到期和所有来源终止的事件，控制内存和误报警。
    void pruneExpiredEventsLocked(ULONGLONG now)
    {
        events.erase(std::remove_if(events.begin(), events.end(), [this, now](const AggregatedEvent& event) {
            return !isEventActiveLocked(event, now);
        }), events.end());
    }

    // activeSourceCount：计算未取消来源数量；最终报只标注来源状态，不会提前结束警报。
    int activeSourceCount(const AggregatedEvent& event) const
    {
        int count = 0;
        for (const SourceReading& reading : event.readings)
        {
            if (reading.present && !reading.canceled)
            {
                ++count;
            }
        }
        return count;
    }

    // maxActiveReportNumber：返回活动来源中的最大报次，方便用户判断预警是否已更新。
    int maxActiveReportNumber(const AggregatedEvent& event) const
    {
        int maximum = 0;
        for (const SourceReading& reading : event.readings)
        {
            if (reading.present && !reading.canceled)
            {
                maximum = std::max(maximum, reading.reportNum);
            }
        }
        return maximum;
    }

    // combinedReadingText：合并当前活动来源的震级或深度，去重后以斜杠分隔。
    QString combinedReadingText(const AggregatedEvent& event, bool magnitude) const
    {
        QStringList values;
        for (const SourceReading& reading : event.readings)
        {
            if (!reading.present || reading.canceled)
            {
                continue;
            }
            const double value = magnitude ? reading.magnitude : reading.depth;
            if (value <= 0.0)
            {
                continue;
            }
            const QString text = QString::number(value, 'f', magnitude ? 1 : 0);
            if (!values.contains(text))
            {
                values.push_back(text);
            }
        }
        return values.join(QLatin1Char('/'));
    }

    // activeSourcesText：把所有当前确认来源的名称拼接为紧凑诊断文本。
    QString activeSourcesText(const AggregatedEvent& event) const
    {
        QStringList names;
        for (int sourceIndex = 0; sourceIndex < kSourceCount; ++sourceIndex)
        {
            const SourceReading& reading = event.readings[sourceIndex];
            if (reading.present && !reading.canceled)
            {
                names.push_back(QLatin1String(kSources[sourceIndex].name));
            }
        }
        return names.join(QStringLiteral(" / "));
    }

    // postWarningChange：把来自网络线程的状态变更排队到 owner 所在线程，避免跨线程 Qt UI 访问。
    void postWarningChange()
    {
        TaskbarEarthquakeClient* target = owner;
        QMetaObject::invokeMethod(target, [target]() {
            emit target->activeWarningsChanged();
        }, Qt::QueuedConnection);
    }

    // postSourceStatusChange：把连接状态刷新排队到 GUI 线程，设置窗口可安全读取快照。
    void postSourceStatusChange()
    {
        TaskbarEarthquakeClient* target = owner;
        QMetaObject::invokeMethod(target, [target]() {
            emit target->sourceStatusesChanged();
        }, Qt::QueuedConnection);
    }

    // queueAudioForReport：转发报告给运行目录 sounds/ 播放器，不复制或嵌入 WindowsMarker 音频资源。
    void queueAudioForReport(double magnitude, bool canceled)
    {
        if (!alertAudioEnabled || audioPlayer == nullptr)
        {
            return;
        }
        audioPlayer->enqueueReport(magnitude, canceled);
    }

    TaskbarEarthquakeClient* owner;          // 外部 QObject，用于安全发布信号。
    std::atomic_bool started{ false };       // start/stop 幂等保护。
    std::atomic_bool stopRequested{ false }; // 后台线程退出标记。
    std::array<SourceRuntime, kSourceCount> runtimes; // 每预警源的线程与连接状态。
    std::thread keepaliveThread;             // 唯一保活发送线程，不与接收线程竞争 send 调用。
    mutable std::mutex eventsMutex;          // 保护 events 的合并和清理操作。
    QList<AggregatedEvent> events;           // 当前及等待清理的聚合地震事件。
    TaskbarEarthquakeAudioPlayer* audioPlayer; // 串行播放 exe 同目录 sounds/ 中的存在文件。
    bool alertAudioEnabled = true;            // 地震开关关闭后禁止声音队列播放。
};

TaskbarEarthquakeClient::TaskbarEarthquakeClient(QObject* parent)
    : QObject(parent)
    , m_private(new Private(this))
{
    // reportReceived 在 GUI 线程触发可选音频队列；网络线程本身从不触碰 Qt Multimedia 对象。
    connect(this, &TaskbarEarthquakeClient::reportReceived, this,
        [this](double magnitude, bool canceled) {
            m_private->queueAudioForReport(magnitude, canceled);
        });
}

TaskbarEarthquakeClient::~TaskbarEarthquakeClient()
{
    // 析构顺序先停止所有网络线程，再释放私有状态和其 Qt Multimedia 子对象。
    m_private->stop();
    delete m_private;
    m_private = nullptr;
}

void TaskbarEarthquakeClient::start()
{
    // Taskbar 启动时调用一次；客户端内部负责过滤不默认启用的来源。
    m_private->start();
}

void TaskbarEarthquakeClient::stop()
{
    // Taskbar 进程退出时调用；本方法可在析构前显式调用，也可由析构兜底。
    m_private->stop();
}

QList<TaskbarEarthquakeEvent> TaskbarEarthquakeClient::activeWarnings() const
{
    // UI 读取的列表是深拷贝快照，因此返回后不依赖网络线程或互斥锁。
    return m_private->warningsSnapshot();
}

QList<TaskbarEarthquakeSourceStatus> TaskbarEarthquakeClient::sourceStatuses() const
{
    // 连接诊断同样以快照形式返回，设置窗口不会长期引用网络线程状态。
    return m_private->statusesSnapshot();
}

void TaskbarEarthquakeClient::injectTestWarning()
{
    // 设置页按钮调用此路径，使用真实的事件聚合和警报主题逻辑而不依赖外部网络。
    m_private->injectTestWarning();
}

void TaskbarEarthquakeClient::setAlertAudioEnabled(bool enabled)
{
    // 设置窗口复用地震通知开关控制可选音频；不存在 sounds/ 时仍保持静默。
    m_private->setAlertAudioEnabled(enabled);
}
