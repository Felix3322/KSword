#pragma once

#include <QObject>
#include <QStringList>

#include <memory>

class QAudioOutput;
class QMediaPlayer;

// TaskbarEarthquakeAudioPlayer 只负责 Taskbar.exe 同目录 sounds/ 内现有地震提示音的顺序播放。
// 它不嵌入或复制 WindowsMarker 音频资源，目录不存在或文件不完整时自动保持静默。
class TaskbarEarthquakeAudioPlayer : public QObject
{
public:
    // 构造函数：传入 QObject 父对象；创建 Qt Multimedia 输出，但不加载任何声音文件。
    explicit TaskbarEarthquakeAudioPlayer(QObject* parent = nullptr);

    // 析构函数：先销毁播放器再销毁音频输出，确保 Qt Multimedia 资源按依赖顺序释放。
    ~TaskbarEarthquakeAudioPlayer() override;

    // setEnabled：设置提示音开关；关闭时立即停止当前声音并丢弃等待队列。
    void setEnabled(bool enabled);

    // enqueueReport：按震级选择 WindowsMarker 同名 WAV；仅队列中实际存在的 sounds/ 文件。
    void enqueueReport(double magnitude, bool canceled);

private:
    // startNext：播放队首文件；无可用文件时无操作，调用方不需要预先检查 sounds/ 目录。
    void startNext();

    std::unique_ptr<QAudioOutput> m_audioOutput; // 当前声音输出设备。
    std::unique_ptr<QMediaPlayer> m_mediaPlayer; // 串行播放 WAV 的 Qt Multimedia 播放器。
    QStringList m_pendingPaths;                  // 等待播放的绝对本地 WAV 路径。
    bool m_enabled = true;                       // 地震通知关闭时禁止播放的状态开关。
};
