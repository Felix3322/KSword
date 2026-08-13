#include "TaskbarEarthquakeAudioPlayer.h"

#include <QAudioOutput>
#include <QCoreApplication>
#include <QDir>
#include <QFileInfo>
#include <QMediaPlayer>
#include <QUrl>

namespace
{
    // runtimeSoundsDirectory：输入无；拼接 Taskbar.exe 同目录 sounds；返回唯一允许读取的运行时音频目录。
    QString runtimeSoundsDirectory()
    {
        const QDir applicationDirectory(QCoreApplication::applicationDirPath());
        return applicationDirectory.filePath(QStringLiteral("sounds"));
    }

    // filesForMagnitude：输入为震级；按 WindowsMarker 同名规则选择可顺序播放的 WAV 文件名；返回候选列表。
    QStringList filesForMagnitude(double magnitude)
    {
        QStringList candidates;
        if (magnitude > 0.0)
        {
            if (magnitude < 3.5)
            {
                candidates.push_back(QStringLiteral("earthquake_magnitude_3_0.wav"));
            }
            else if (magnitude < 4.0)
            {
                candidates.push_back(QStringLiteral("earthquake_magnitude_3_5.wav"));
            }
            else if (magnitude < 4.5)
            {
                candidates.push_back(QStringLiteral("earthquake_magnitude_4_0.wav"));
            }
            else if (magnitude < 5.0)
            {
                candidates.push_back(QStringLiteral("earthquake_magnitude_4_5.wav"));
            }
            else if (magnitude < 5.5)
            {
                candidates.push_back(QStringLiteral("earthquake_magnitude_5_0.wav"));
            }
            else if (magnitude < 6.0)
            {
                candidates.push_back(QStringLiteral("earthquake_magnitude_5_5.wav"));
            }
            else
            {
                candidates.push_back(QStringLiteral("earthquake_magnitude_6_0_plus.wav"));
            }
        }

        const QString receivedFile = magnitude >= 6.0
            ? QStringLiteral("earthquake_message_received_magnitude_6_0_plus.wav")
            : QStringLiteral("earthquake_message_received.wav");
        candidates.push_back(receivedFile);
        return candidates;
    }
}

TaskbarEarthquakeAudioPlayer::TaskbarEarthquakeAudioPlayer(QObject* parent)
    : QObject(parent)
    , m_audioOutput(std::make_unique<QAudioOutput>())
    , m_mediaPlayer(std::make_unique<QMediaPlayer>())
{
    // 音频输出和播放器只属于本对象，析构时按播放器、输出的依赖次序显式释放。
    m_audioOutput->setVolume(0.85f);
    m_mediaPlayer->setAudioOutput(m_audioOutput.get());
    connect(m_mediaPlayer.get(), &QMediaPlayer::mediaStatusChanged, this,
        [this](QMediaPlayer::MediaStatus status) {
            if (status == QMediaPlayer::EndOfMedia || status == QMediaPlayer::InvalidMedia)
            {
                startNext();
            }
        });
}

TaskbarEarthquakeAudioPlayer::~TaskbarEarthquakeAudioPlayer()
{
    // 先解除播放器对输出的引用，再释放音频输出，避免 Qt Multimedia 析构阶段访问失效设备。
    m_mediaPlayer.reset();
    m_audioOutput.reset();
}

void TaskbarEarthquakeAudioPlayer::setEnabled(bool enabled)
{
    // 切换为关闭时立即停止播放并清空等待队列，避免重新开启后播放过期报告。
    if (m_enabled == enabled)
    {
        return;
    }

    m_enabled = enabled;
    if (!m_enabled)
    {
        m_pendingPaths.clear();
        m_mediaPlayer->stop();
        m_mediaPlayer->setSource(QUrl());
    }
}

void TaskbarEarthquakeAudioPlayer::enqueueReport(double magnitude, bool canceled)
{
    // 已取消的报告和关闭状态都保持静默；目录外、嵌入式和 WindowsMarker 资源绝不作为回退来源。
    if (!m_enabled || canceled)
    {
        return;
    }

    const QDir soundsDirectory(runtimeSoundsDirectory());
    const QStringList candidates = filesForMagnitude(magnitude);
    for (const QString& fileName : candidates)
    {
        const QString absolutePath = soundsDirectory.filePath(fileName);
        const QFileInfo fileInfo(absolutePath);
        if (fileInfo.isFile())
        {
            m_pendingPaths.push_back(absolutePath);
        }
    }

    // 空目录或缺少对应文件时没有队列内容，保持静默且不报告错误影响 WebSocket 接收。
    if (m_mediaPlayer->playbackState() != QMediaPlayer::PlayingState)
    {
        startNext();
    }
}

void TaskbarEarthquakeAudioPlayer::startNext()
{
    // 每次只消费一项，EndOfMedia 再递归推进下一项，避免多份预警音同时混播。
    if (!m_enabled || m_pendingPaths.isEmpty())
    {
        return;
    }

    const QString nextPath = m_pendingPaths.takeFirst();
    m_mediaPlayer->setSource(QUrl::fromLocalFile(nextPath));
    m_mediaPlayer->play();
}
