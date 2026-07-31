#include "AudioAnalyze.h"
#include <algorithm>
#include <cmath>
#include <complex>
#include <thread>
#include <vector>
#include <QDebug>

// 简单的复数类型定义
typedef std::complex<double> Complex;

AudioSpectrumAnalyzer::AudioSpectrumAnalyzer(QObject* parent)
    : QObject(parent)
    , m_spectrumData(NUM_BANDS, 0.0f)
    , m_previousSpectrum(NUM_BANDS, 0.0f)
    , m_magnitudes(FFT_SIZE / 2, 0.0f)  // 添加缺失的定义
{
    m_audioBuffer.reserve(FFT_SIZE * 2);
    createWindowFunction();
}

AudioSpectrumAnalyzer::~AudioSpectrumAnalyzer()
{
    // 析构时统一走同一条释放路径，避免线程仍在使用已释放的 COM 接口。
    releaseResources();
}

bool AudioSpectrumAnalyzer::initialize() {
    // 重复初始化前先完整释放旧会话，避免把新的 COM 初始化与旧接口混在一起。
    if (m_comInitialized || m_deviceEnumerator || m_audioClient || m_captureThread) {
        releaseResources();
    }

    // 1. 初始化COM（已修复为STA模式）
    HRESULT hr = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
    if (FAILED(hr)) {
        qWarning() << "COM初始化失败. 错误码:" << hr;
        return false;
    }
    m_comInitialized = true;

    // 2. 创建设备枚举器
    hr = CoCreateInstance(
        __uuidof(MMDeviceEnumerator),
        nullptr,
        CLSCTX_ALL,
        __uuidof(IMMDeviceEnumerator),
        (void**)&m_deviceEnumerator
    );
    if (FAILED(hr)) {
        qWarning() << "创建设备枚举器失败. 错误码:" << hr;
        releaseResources();
        return false;
    }

    // 3. 枚举所有活跃的音频设备（根据需求选择输入/输出）
    IMMDeviceCollection* pDevices = nullptr;
    EDataFlow flow = eRender;  // 若分析扬声器输出，用eRender；若分析麦克风，用eCapture
    hr = m_deviceEnumerator->EnumAudioEndpoints(
        flow,
        DEVICE_STATE_ACTIVE,  // 只枚举活跃设备
        &pDevices
    );
    if (FAILED(hr)) {
        qWarning() << "枚举设备失败. 错误码:" << hr;
        releaseResources();  // 自定义释放资源的函数
        return false;
    }

    // 4. 遍历设备，尝试初始化第一个可用设备
    UINT deviceCount = 0;
    pDevices->GetCount(&deviceCount);
    qDebug() << "找到" << deviceCount << "个活跃音频设备";

    bool foundValidDevice = false;
    for (UINT i = 0; i < deviceCount; ++i) {
        IMMDevice* pDevice = nullptr;
        if (SUCCEEDED(pDevices->Item(i, &pDevice))) {
            qDebug() << "尝试初始化设备" << i;
            m_audioDevice = pDevice;  // 临时使用当前设备

            // 尝试初始化该设备的音频客户端
            if (setupAudioClient()) {
                qDebug() << "设备" << i << "初始化成功！";
                foundValidDevice = true;
                break;  // 找到可用设备，退出循环
            }
            else {
                pDevice->Release();  // 初始化失败，释放设备
                m_audioDevice = nullptr;
            }
        }
    }

    pDevices->Release();  // 释放设备集合

    if (!foundValidDevice) {
        qWarning() << "所有设备均无法初始化（可能被占用或不支持格式）";
        releaseResources();
        return false;
    }

    // setupAudioClient 已为选中的设备完成初始化；不能再次覆盖接口和设备指针。
    return true;
}
void AudioSpectrumAnalyzer::releaseResources() {
    // 先同步停止工作线程，确保下方每个 COM 指针不再被后台读取。
    stopCapture();

    // 释放COM接口
    if (m_captureClient) {
        m_captureClient->Release();
        m_captureClient = nullptr;
    }
    if (m_audioClient) {
        m_audioClient->Release();
        m_audioClient = nullptr;
    }
    if (m_audioDevice) {
        m_audioDevice->Release();
        m_audioDevice = nullptr;
    }
    if (m_deviceEnumerator) {
        m_deviceEnumerator->Release();
        m_deviceEnumerator = nullptr;
    }

    // GetMixFormat 返回的格式内存归 COM 分配器所有，必须与接口一同释放。
    if (m_waveFormat) {
        CoTaskMemFree(m_waveFormat);
        m_waveFormat = nullptr;
    }

    // 仅平衡本对象成功完成的 CoInitializeEx，避免对未初始化的线程反初始化。
    if (m_comInitialized) {
        CoUninitialize();
        m_comInitialized = false;
    }
}
bool AudioSpectrumAnalyzer::enumerateAudioDevices()
{
    IMMDeviceCollection* deviceCollection = nullptr;
    HRESULT hr = m_deviceEnumerator->EnumAudioEndpoints(
        eRender, DEVICE_STATE_ACTIVE, &deviceCollection);

    if (SUCCEEDED(hr) && deviceCollection) {
        UINT count = 0;
        deviceCollection->GetCount(&count);

        for (UINT i = 0; i < count; i++) {
            IMMDevice* device = nullptr;
            hr = deviceCollection->Item(i, &device);
            if (SUCCEEDED(hr)) {
                m_audioDevice = device;
                if (setupAudioClient()) {
                    deviceCollection->Release();
                    return true;
                }
                device->Release();
            }
        }
        deviceCollection->Release();
    }
    return false;
}
bool AudioSpectrumAnalyzer::initializeAudioDevice()
{
    HRESULT hr = m_deviceEnumerator->GetDefaultAudioEndpoint(
        eRender, eConsole, &m_audioDevice);

    if (FAILED(hr)) {
        qWarning() << "Failed to get default audio endpoint, trying loopback...";
        // 尝试枚举设备查找合适的环回设备
        return enumerateAudioDevices();
    }

    return setupAudioClient();
}

bool AudioSpectrumAnalyzer::setupAudioClient()
{
    // 先在局部变量中建立完整会话，失败时不会把半初始化接口留给下一台设备。
    if (!m_audioDevice) {
        return false;
    }

    IAudioClient* audioClient = nullptr;
    IAudioCaptureClient* captureClient = nullptr;
    WAVEFORMATEX* defaultFormat = nullptr;

    HRESULT hr = m_audioDevice->Activate(__uuidof(IAudioClient), CLSCTX_ALL,
        nullptr, reinterpret_cast<void**>(&audioClient));
    if (FAILED(hr)) {
        qWarning() << "Failed to activate audio device";
        return false;
    }

    // pDefaultFormat 是传给 IAudioClient 的唯一格式副本，后续解析也必须使用同一格式。
    hr = audioClient->GetMixFormat(&defaultFormat);
    if (FAILED(hr)) {
        qWarning() << "获取设备默认格式失败. 错误码:" << hr;
        audioClient->Release();
        return false;
    }

    // 打印默认格式（调试用）
    qDebug() << "设备默认格式: " << defaultFormat->nSamplesPerSec << "Hz, "
        << defaultFormat->nChannels << "声道, "
        << defaultFormat->wBitsPerSample << "位";

    // 初始化音频客户端：使用默认格式 + 共享模式
    hr = audioClient->Initialize(
        AUDCLNT_SHAREMODE_SHARED,
        AUDCLNT_STREAMFLAGS_LOOPBACK,  // 捕获扬声器输出（若捕获麦克风则移除）
        50000000,  // 缓冲区时长调整为50ms（增大缓冲区提高兼容性）
        0,
        defaultFormat,
        nullptr
    );

    // 保存实际生效格式的采样率；格式内存会在 releaseResources 中成对释放。
    sample_rate = defaultFormat->nSamplesPerSec;

    if (FAILED(hr)) {
        QString errorMsg;
        if (hr == AUDCLNT_E_DEVICE_IN_USE) {
            errorMsg = "设备被其他程序独占占用（请关闭占用程序）";
        }
        else if (hr == AUDCLNT_E_UNSUPPORTED_FORMAT) {
            errorMsg = "设备不支持默认格式（罕见）";
        }
        else {
            errorMsg = "初始化失败，错误码: " + QString::number(hr, 16);
        }
        qWarning() << "设备初始化失败:" << errorMsg;
        CoTaskMemFree(defaultFormat);
        audioClient->Release();
        return false;
    }

    hr = audioClient->GetService(__uuidof(IAudioCaptureClient),
        reinterpret_cast<void**>(&captureClient));
    if (FAILED(hr)) {
        qWarning() << "Failed to get audio capture client";
        CoTaskMemFree(defaultFormat);
        audioClient->Release();
        return false;
    }

    // 仅在所有步骤成功后发布接口，避免失败重试覆盖仍需释放的成员指针。
    m_audioClient = audioClient;
    m_captureClient = captureClient;
    m_waveFormat = defaultFormat;
    return true;
}

void AudioSpectrumAnalyzer::startCapture()
{
    if (m_isCapturing || !m_audioClient || !m_captureClient) return;

    // 已结束但尚未关闭的旧线程句柄必须先回收，避免覆盖可等待的线程所有权。
    if (m_captureThread) {
        if (WaitForSingleObject(m_captureThread, 0) != WAIT_OBJECT_0) {
            return;
        }
        CloseHandle(m_captureThread);
        m_captureThread = nullptr;
    }

    HRESULT hr = m_audioClient->Start();
    if (FAILED(hr)) {
        qWarning() << "Failed to start audio capture";
        return;
    }

    m_isCapturing = true;

    // 创建捕获线程
    m_captureThread = CreateThread(nullptr, 0, [](LPVOID param) -> DWORD {
        auto analyzer = static_cast<AudioSpectrumAnalyzer*>(param);
        analyzer->captureAudioData();
        return 0;
        }, this, 0, nullptr);

    // 创建失败时没有线程会清理状态，必须立即恢复，保证下次可以重新启动。
    if (!m_captureThread) {
        qWarning() << "创建音频捕获线程失败，错误码:" << GetLastError();
        m_isCapturing = false;
        m_audioClient->Stop();
    }
}

void AudioSpectrumAnalyzer::stopCapture()
{
    m_isCapturing = false;

    if (m_audioClient) {
        m_audioClient->Stop();
    }

    if (m_captureThread) {
        // 不能在超时后释放 COM 接口：线程仍可能在 GetBuffer 或 FFT 中访问它们。
        WaitForSingleObject(m_captureThread, INFINITE);
        CloseHandle(m_captureThread);
        m_captureThread = nullptr;
    }
}

void AudioSpectrumAnalyzer::captureAudioData()
{
    while (m_isCapturing) {
        UINT32 packetSize = 0;
        HRESULT hr = m_captureClient->GetNextPacketSize(&packetSize);

        if (FAILED(hr)) {
            qWarning() << "GetNextPacketSize失败，错误码:" << hr; // 新增日志
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
            continue;
        }

        if (packetSize > 0) {
            BYTE* data = nullptr;
            UINT32 framesAvailable = 0;
            DWORD flags = 0;

            hr = m_captureClient->GetBuffer(&data, &framesAvailable, &flags, nullptr, nullptr);
            if (SUCCEEDED(hr)) {
                // 静音包的 data 可为 nullptr；显式补零可保留时间轴且不会解引用空指针。
                if (framesAvailable > 0) {
                    const BYTE* sampleData = (flags & AUDCLNT_BUFFERFLAGS_SILENT) ? nullptr : data;
                    processAudioData(sampleData, framesAvailable);
                }

                // 只要 GetBuffer 成功就必须配对 ReleaseBuffer，包括零帧包。
                m_captureClient->ReleaseBuffer(framesAvailable);
            }
            else {
                qWarning() << "GetBuffer失败，错误码:" << hr; // 新增日志
            }
        }
        else {
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
    }
    qDebug() << "捕获线程退出"; // 新增日志，确认退出时机
}

void AudioSpectrumAnalyzer::processAudioData(const BYTE* data, UINT32 framesAvailable) {
    // 每次调用只追加本数据包实际产生的单声道样本，并以该精确范围做诊断。
    if (!m_waveFormat || framesAvailable == 0 || m_waveFormat->nChannels == 0) {
        qDebug() << "m_waveFormat is null!";
        return;
    }

    qDebug() << "Processing audio data - Frames:" << framesAvailable
        << "Format:" << m_waveFormat->wFormatTag
        << "Channels:" << m_waveFormat->nChannels
        << "Bits:" << m_waveFormat->wBitsPerSample;

    const UINT16 channelCount = m_waveFormat->nChannels;
    const int bufferStart = m_audioBuffer.size();

    // 把任意声道数的交错帧平均为一个单声道样本，避免双声道专用索引越界。
    const auto appendFloatFrames = [this, framesAvailable, channelCount](const float* samples) {
        for (UINT32 frame = 0; frame < framesAvailable; ++frame) {
            float mixedSample = 0.0f;
            for (UINT16 channel = 0; channel < channelCount; ++channel) {
                mixedSample += samples[static_cast<size_t>(frame) * channelCount + channel];
            }
            m_audioBuffer.append(mixedSample / static_cast<float>(channelCount));
        }
    };

    // 把有符号 PCM 帧按指定比例归一化后再混音，调用方保证样本位宽匹配。
    const auto appendPcm32Frames = [this, framesAvailable, channelCount](const int32_t* samples) {
        for (UINT32 frame = 0; frame < framesAvailable; ++frame) {
            float mixedSample = 0.0f;
            for (UINT16 channel = 0; channel < channelCount; ++channel) {
                mixedSample += static_cast<float>(samples[static_cast<size_t>(frame) * channelCount + channel]) / 2147483648.0f;
            }
            m_audioBuffer.append(mixedSample / static_cast<float>(channelCount));
        }
    };

    // 16 位 PCM 使用独立转换，避免把 16 位缓冲误解释为 32 位数组。
    const auto appendPcm16Frames = [this, framesAvailable, channelCount](const int16_t* samples) {
        for (UINT32 frame = 0; frame < framesAvailable; ++frame) {
            float mixedSample = 0.0f;
            for (UINT16 channel = 0; channel < channelCount; ++channel) {
                mixedSample += static_cast<float>(samples[static_cast<size_t>(frame) * channelCount + channel]) / 32768.0f;
            }
            m_audioBuffer.append(mixedSample / static_cast<float>(channelCount));
        }
    };

    // WASAPI 静音包没有有效 data 指针；按帧补零后仍可让 FFT 平稳衰减。
    if (!data) {
        for (UINT32 frame = 0; frame < framesAvailable; ++frame) {
            m_audioBuffer.append(0.0f);
        }
    }
    else {
    // 根据实际格式解析样本
    qDebug() << "Audio format - Tag:" << m_waveFormat->wFormatTag
        << "Bits:" << m_waveFormat->wBitsPerSample;

    // 根据实际格式解析样本
    if (m_waveFormat->wFormatTag == WAVE_FORMAT_EXTENSIBLE) {
        // 转换为扩展格式结构体
        WAVEFORMATEXTENSIBLE* waveFormatExt = (WAVEFORMATEXTENSIBLE*)m_waveFormat;
        GUID subFormat = waveFormatExt->SubFormat;

        qDebug() << "Extended format - SubFormat:" << subFormat.Data1;

        // 检查是否为IEEE浮点数格式
        if (subFormat.Data1 == WAVE_FORMAT_IEEE_FLOAT) {
            qDebug() << "Detected IEEE FLOAT format";
            appendFloatFrames(reinterpret_cast<const float*>(data));
        }
        // 检查是否为PCM格式
        else if (subFormat.Data1 == WAVE_FORMAT_PCM) {
            qDebug() << "Detected PCM format in extensible wrapper";
            if (m_waveFormat->wBitsPerSample == 32) {
                appendPcm32Frames(reinterpret_cast<const int32_t*>(data));
            }
            else if (m_waveFormat->wBitsPerSample == 16) {
                appendPcm16Frames(reinterpret_cast<const int16_t*>(data));
            }
        }
        else {
            qDebug() << "Unsupported subformat:" << subFormat.Data1;
            return;
        }
    }
    else
        if (m_waveFormat->wFormatTag == WAVE_FORMAT_IEEE_FLOAT && m_waveFormat->wBitsPerSample == 32) {
        // 32位浮点格式（设备返回的格式）
        appendFloatFrames(reinterpret_cast<const float*>(data));
    }
    else if (m_waveFormat->wFormatTag == WAVE_FORMAT_PCM) {
        // PCM格式处理
        if (m_waveFormat->wBitsPerSample == 32) {
            appendPcm32Frames(reinterpret_cast<const int32_t*>(data));
        }
        else if (m_waveFormat->wBitsPerSample == 16) {
            appendPcm16Frames(reinterpret_cast<const int16_t*>(data));
        }
    }
    else {
        qDebug() << "Unsupported format tag:" << m_waveFormat->wFormatTag;
        return;
    }
    }

    const int appendedSampleCount = m_audioBuffer.size() - bufferStart;
    if (appendedSampleCount > 0) {
        // 每帧仅追加一个单声道样本，因此范围起点必须使用 appendedSampleCount 而非声道数。
        const auto firstNewSample = m_audioBuffer.cbegin() + bufferStart;
        const float minSample = *std::min_element(firstNewSample, m_audioBuffer.cend());
        const float maxSample = *std::max_element(firstNewSample, m_audioBuffer.cend());
        qDebug() << "Collected" << framesAvailable << "frames, buffer size:" << m_audioBuffer.size();
        qDebug() << "Sample range: min=" << minSample << "max=" << maxSample;
    }
    else {
        qDebug() << "No data collected! Buffer remains empty.";
    }


    // 逐个消化所有完整窗口；单次大包不再使待处理缓冲无限增长。
    while (m_audioBuffer.size() >= FFT_SIZE) {
        qDebug() << "Performing FFT...";
        applyFFT(m_audioBuffer.constData(), FFT_SIZE);
        m_audioBuffer.remove(0, FFT_SIZE / 2);
        qDebug() << "Buffer after FFT:" << m_audioBuffer.size();
    }
    qDebug() << "Audio buffer size:" << m_audioBuffer.size();
}
void AudioSpectrumAnalyzer::applyFFT(const float* audioData, int size)
{
    std::vector<Complex> complexData(size);

    // 应用汉宁窗并转换为复数
    for (int i = 0; i < size; ++i) {
        float windowedSample = audioData[i] * m_hanningWindow[i];
        complexData[i] = Complex(windowedSample, 0.0);
    }

    // 执行FFT
    for (int i = 1, j = 0; i < size; ++i) {
        int bit = size >> 1;
        for (; j >= bit; bit >>= 1) {
            j -= bit;
        }
        j += bit;
        if (i < j) {
            std::swap(complexData[i], complexData[j]);
        }
    }

    for (int length = 2; length <= size; length <<= 1) {
        double angle = -2.0 * M_PI / length;
        Complex wlen(std::cos(angle), std::sin(angle));

        for (int i = 0; i < size; i += length) {
            Complex w(1.0, 0.0);
            for (int j = 0; j < length / 2; ++j) {
                Complex u = complexData[i + j];
                Complex v = complexData[i + j + length / 2] * w;
                complexData[i + j] = u + v;
                complexData[i + j + length / 2] = u - v;
                w *= wlen;
            }
        }
    }

    // 计算幅度并存储到m_magnitudes
    for (int i = 0; i < size / 2; ++i) {
        m_magnitudes[i] = static_cast<float>(std::abs(complexData[i]));
    }

    calculateFrequencyBands();
}

void AudioSpectrumAnalyzer::calculateFrequencyBands() {
    qDebug() << "Calculating frequency bands...";

    // 重置频带数据
    m_spectrumData.fill(0.0f, NUM_BANDS);

    if (m_magnitudes.isEmpty()) {
        qDebug() << "ERROR: Magnitudes array is empty!";
        return;
    }

    // 计算每个频带的平均幅度
    // 频段索引必须使用当前设备格式，不能假定所有设备均为 48 kHz。
    const int fftSize = m_magnitudes.size();
    const float sampleRate = static_cast<float>(sample_rate);
    if (sampleRate <= 0.0f) {
        return;
    }

    for (int band = 0; band < NUM_BANDS; ++band) {
        // 计算频带对应的频率范围（对数刻度）
        float lowFreq = band == 0 ? 20.0f : (sampleRate / 2) * pow(2.0f, (band - 1) / (NUM_BANDS - 1.0f));
        float highFreq = (sampleRate / 2) * pow(2.0f, band / (NUM_BANDS - 1.0f));

        int lowBin = qMax(0, static_cast<int>(lowFreq * fftSize / sampleRate));
        int highBin = qMin(fftSize - 1, static_cast<int>(highFreq * fftSize / sampleRate));

        if (lowBin >= highBin) {
            lowBin = highBin - 1;
            if (lowBin < 0) lowBin = 0;
        }

        // 计算该频带的平均值
        float sum = 0.0f;
        int count = 0;
        for (int bin = lowBin; bin <= highBin; ++bin) {
            sum += m_magnitudes[bin];
            count++;
        }
        //自定义频谱放缩系数
        if(band < 4){
            sum *= 0.8f; // 低频放大
        } else if(band < 8){
            sum *= 1.5f; // 中低频稍微放大
        } else if(band < 12){
            sum *= 1.5f; // 中高频稍微减小
        } else {
            sum *= 5.0f; // 高频飞起来
		}
        m_spectrumData[band] = count > 0 ? sum / count : 0.0f
            ;


    }

    // 调试输出频带数据
    float maxBand = *std::max_element(m_spectrumData.begin(), m_spectrumData.end());
    qDebug() << "Frequency bands calculated - max band:" << maxBand;

    if (maxBand > 0) {
        qDebug() << "First 5 bands:";
        for (int i = 0; i < 5 && i < NUM_BANDS; ++i) {
            qDebug() << "  Band" << i << ":" << m_spectrumData[i];
        }
    }

    emit spectrumDataReady(m_spectrumData);
    qDebug() << "Spectrum data signal emitted";
}
void AudioSpectrumAnalyzer::createWindowFunction()
{
    m_hanningWindow.resize(FFT_SIZE);
    for (int i = 0; i < FFT_SIZE; ++i) {
        m_hanningWindow[i] = 0.5f * (1.0f - std::cos(2.0f * M_PI * i / (FFT_SIZE - 1)));
    }
}

QVector<float> AudioSpectrumAnalyzer::getSpectrumData() const
{
    return m_spectrumData;
}
