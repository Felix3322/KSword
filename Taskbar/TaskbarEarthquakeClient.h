#pragma once

#include <QList>
#include <QObject>
#include <QString>

// TaskbarEarthquakeEvent 表示一个按震中位置合并后的活动地震预警。
// 它只保存 Taskbar 展示和通知调度需要的字段，不携带 WindowsMarker 的渲染或音频资源。
struct TaskbarEarthquakeEvent
{
    QString locationKey;          // 用于跨预警源合并同一震中的稳定键。
    QString hypoCenter;           // 震中位置文本。
    QString originTime;           // 震源发生时间。
    QString magnitudeText;        // 各来源震级的合并文本。
    QString depthText;            // 各来源深度的合并文本。
    QString sourcesText;          // 当前确认该预警的来源名称。
    int reportNum = 0;            // 当前最大报次。
    int sourceCount = 0;          // 当前未取消来源数量。
};

// TaskbarEarthquakeSourceStatus 表示一个 WebSocket 预警源的实时连接状态。
struct TaskbarEarthquakeSourceStatus
{
    QString id;                   // 来源稳定标识。
    QString name;                 // 设置窗口展示名称。
    bool enabled = false;         // 是否按当前配置启动。
    bool connected = false;       // 当前 WebSocket 是否已连接。
    bool everConnected = false;   // 本进程中是否至少连接成功过一次。
    quint64 lastMessageAgeMs = 0; // 距最近数据包的时间；0 代表尚未收到数据。
    quint64 latencyMs = 0;        // ping/pong 往返延迟；0 代表暂未测得。
};

// TaskbarEarthquakeClient 在一个进程中维护 WindowsMarker 同源的多路地震预警 WebSocket。
// 工作线程只处理网络和状态合并；所有 Qt 信号均通过 GUI 线程发布。
class TaskbarEarthquakeClient : public QObject
{
    Q_OBJECT

public:
    // 构造函数：传入 QObject 父对象；初始化连接状态，不立即访问网络。
    explicit TaskbarEarthquakeClient(QObject* parent = nullptr);

    // 析构函数：停止接收线程并关闭 WebSocket，确保没有后台线程访问已释放对象。
    ~TaskbarEarthquakeClient() override;

    // start：无输入；按默认来源启动接收线程；重复调用保持幂等。
    void start();

    // stop：无输入；关闭套接字并等待接收线程退出；可安全重复调用。
    void stop();

    // activeWarnings：无输入；返回当前活动预警的 GUI 线程安全快照。
    QList<TaskbarEarthquakeEvent> activeWarnings() const;

    // sourceStatuses：无输入；返回每个预警源的连接诊断快照。
    QList<TaskbarEarthquakeSourceStatus> sourceStatuses() const;

    // injectTestWarning：无输入；插播一个持续十秒的本地测试预警，不访问网络。
    void injectTestWarning();

    // setAlertAudioEnabled：设置 sounds/ 目录提示音是否可播放；不影响网络接收或预警展示。
    void setAlertAudioEnabled(bool enabled);

signals:
    // activeWarningsChanged：活动预警集变化后发出，接收方重新读取 activeWarnings()。
    void activeWarningsChanged();

    // sourceStatusesChanged：连接诊断刷新后发出，接收方重新读取 sourceStatuses()。
    void sourceStatusesChanged();

    // reportReceived：接收到有效地震报告后发出，供可选 sounds/ 音频队列选择提示音。
    void reportReceived(double magnitude, bool canceled);

private:
    // 实现细节位于 cpp：网络线程、报文解析、事件聚合和状态定时刷新均不暴露给 UI 层。
    class Private;
    Private* m_private;           // 地震客户端私有状态拥有者。
};
