#ifndef AUDIOSPECTRUMANALYZER_H
#define AUDIOSPECTRUMANALYZER_H

#include <QObject>
#include <QVector>
#include <atomic>
#include <memory>
#include <windows.h>
#include <mmdeviceapi.h>
#include <audioclient.h>

class AudioSpectrumAnalyzer : public QObject
{
    Q_OBJECT

public:
    // 构造频谱分析器并初始化不依赖设备的 FFT 数据。
    explicit AudioSpectrumAnalyzer(QObject* parent = nullptr);
    // 销毁分析器；会先等待采集线程退出，再释放 COM 接口。
    ~AudioSpectrumAnalyzer();

    // 释放已初始化的线程、音频接口、格式内存和当前线程 COM 初始化。
    void releaseResources();
    // 初始化默认输出设备的环回采集接口。
    bool initialize();
    // 枚举并尝试初始化可用的输出设备。
    bool enumerateAudioDevices();
    // 启动单一后台采集线程。
    void startCapture();
    // 请求后台采集线程退出并等待它不再访问音频接口。
    void stopCapture();
    // 返回最近一次计算出的频谱快照。
    QVector<float> getSpectrumData() const;

signals:
    void spectrumDataReady(const QVector<float>& spectrumData);

private:
    static constexpr int FFT_SIZE = 1024;
    static constexpr int NUM_BANDS = 16;
    //static constexpr int SAMPLE_RATE = 44100;

    // sample_rate 保存当前设备格式的采样率，用于频段换算。
    int sample_rate = 48000;
    bool initializeAudioDevice();
    bool setupAudioClient();
    void captureAudioData();
    void processAudioData(const BYTE* data, UINT32 framesAvailable);
    void applyFFT(const float* audioData, int size);
    void calculateFrequencyBands();
    void applySmoothing();

    // Windows Core Audio 相关成员；仅在线程完全停止后释放。
    IMMDeviceEnumerator* m_deviceEnumerator = nullptr;
    IMMDevice* m_audioDevice = nullptr;
    IAudioClient* m_audioClient = nullptr;
    IAudioCaptureClient* m_captureClient = nullptr;
    WAVEFORMATEX* m_waveFormat = nullptr;

    // m_comInitialized 表示本对象是否需要在当前线程调用 CoUninitialize。
    bool m_comInitialized = false;

    // 音频处理相关成员
    QVector<float> m_audioBuffer;
    QVector<float> m_spectrumData;
    QVector<float> m_previousSpectrum;
    QVector<float> m_magnitudes;  // 添加缺失的声明

    // 线程控制；m_captureThread 始终保留到采集线程实际退出。
    std::atomic<bool> m_isCapturing{ false };
    HANDLE m_captureThread = nullptr;

    // FFT 窗口函数
    QVector<float> m_hanningWindow;
    void createWindowFunction();
};

#endif // AUDIOSPECTRUMANALYZER_H
