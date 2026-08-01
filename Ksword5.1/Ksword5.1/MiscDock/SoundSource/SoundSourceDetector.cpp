#include "SoundSourceDetector.h"

#include "../../ArkDriverClient/ArkDriverClient.h"

#include <Audioclient.h>
#include <Audiopolicy.h>
#include <Endpointvolume.h>
#include <propkeydef.h>
#include <Functiondiscoverykeys_devpkey.h>
#include <Mmdeviceapi.h>
#include <Propvarutil.h>
#include <QFileInfo>
#include <QHash>
#include <QStringList>
#include <QThread>
#include <wrl/client.h>

#include <algorithm>
#include <map>
#include <set>

// ============================================================
// SoundSourceDetector.cpp
// 作用：
// - 通过 Core Audio 会话级峰值确认输出声音来源；
// - 通过 R3 进程创建时间防止 PID 复用误认；
// - 通过 R0 Cross-View 与 Runtime Detail 独立核验候选 PID。
// ============================================================

namespace
{
    using Microsoft::WRL::ComPtr;

    constexpr float kAudiblePeakThreshold = 0.0005F;
    constexpr float kAudibleVolumeThreshold = 0.0001F;
    constexpr unsigned long kKernelCrossViewNodeBudget = 4096UL;

    // ScopedComInitialization：管理检测工作线程自己的 COM 初始化平衡。
    class ScopedComInitialization final
    {
    public:
        ScopedComInitialization()
            : m_result(::CoInitializeEx(nullptr, COINIT_MULTITHREADED))
            , m_shouldUninitialize(SUCCEEDED(m_result))
        {
        }

        ~ScopedComInitialization()
        {
            if (m_shouldUninitialize)
            {
                ::CoUninitialize();
            }
        }

        // usable：RPC_E_CHANGED_MODE 表示线程已采用其它 apartment，COM 仍可调用。
        bool usable() const
        {
            return SUCCEEDED(m_result) || m_result == RPC_E_CHANGED_MODE;
        }

        HRESULT result() const
        {
            return m_result;
        }

    private:
        HRESULT m_result = E_FAIL;       // CoInitializeEx 返回值。
        bool m_shouldUninitialize = false; // 是否需要由析构函数执行 CoUninitialize。
    };

    // SessionProbe：保存一次采样窗口内仍需调用的会话 meter。
    struct SessionProbe
    {
        std::size_t recordIndex = 0;                // 对应结果记录索引。
        ComPtr<IAudioMeterInformation> meter;       // 会话级峰值接口。
        float peakSum = 0.0F;                       // 所有成功采样峰值之和。
        int successfulSamples = 0;                  // 成功读取峰值次数。
    };

    // EndpointProbe：保存输出端点 meter 以及归属于该端点的会话索引。
    struct EndpointProbe
    {
        ComPtr<IAudioMeterInformation> meter;       // 输出设备总体峰值接口。
        std::vector<std::size_t> recordIndices;     // 该端点包含的结果记录索引。
        float peakMaximum = 0.0F;                   // 采样窗口内设备最大峰值。
    };

    // coTaskMemString：复制 COM 分配的宽字符串并立即释放原始内存。
    QString coTaskMemString(LPWSTR rawText)
    {
        if (rawText == nullptr)
        {
            return QString();
        }

        const QString copiedText = QString::fromWCharArray(rawText);
        ::CoTaskMemFree(rawText);
        return copiedText;
    }

    // queryDeviceFriendlyName：从 MMDevice 属性存储读取用户看到的端点名。
    QString queryDeviceFriendlyName(IMMDevice* const device)
    {
        if (device == nullptr)
        {
            return QString();
        }

        ComPtr<IPropertyStore> propertyStore;
        const HRESULT storeResult = device->OpenPropertyStore(
            STGM_READ,
            propertyStore.GetAddressOf());
        if (FAILED(storeResult))
        {
            return QString();
        }

        PROPVARIANT friendlyNameValue;
        ::PropVariantInit(&friendlyNameValue);
        const HRESULT propertyResult = propertyStore->GetValue(
            PKEY_Device_FriendlyName,
            &friendlyNameValue);
        QString friendlyName;
        if (SUCCEEDED(propertyResult) &&
            friendlyNameValue.vt == VT_LPWSTR &&
            friendlyNameValue.pwszVal != nullptr)
        {
            friendlyName = QString::fromWCharArray(friendlyNameValue.pwszVal);
        }
        ::PropVariantClear(&friendlyNameValue);
        return friendlyName;
    }

    // queryProcessIdentity：用 R3 公共 API 读取路径和创建时间，不请求写权限。
    void queryProcessIdentity(ks::misc::SoundSourceRecord& record)
    {
        if (record.processId == 0U)
        {
            record.processName = QStringLiteral("系统声音");
            return;
        }

        HANDLE processHandle = ::OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION,
            FALSE,
            record.processId);
        if (processHandle == nullptr)
        {
            record.processName = QStringLiteral("PID %1").arg(record.processId);
            return;
        }

        std::wstring imagePathBuffer(32768U, L'\0');
        DWORD imagePathLength = static_cast<DWORD>(imagePathBuffer.size());
        if (::QueryFullProcessImageNameW(
                processHandle,
                0,
                imagePathBuffer.data(),
                &imagePathLength) != FALSE)
        {
            imagePathBuffer.resize(imagePathLength);
            record.imagePath = QString::fromStdWString(imagePathBuffer);
            record.processName = QFileInfo(record.imagePath).fileName();
        }

        FILETIME creationTime{};
        FILETIME exitTime{};
        FILETIME kernelTime{};
        FILETIME userTime{};
        if (::GetProcessTimes(
                processHandle,
                &creationTime,
                &exitTime,
                &kernelTime,
                &userTime) != FALSE)
        {
            record.creationTime100ns =
                (static_cast<std::uint64_t>(creationTime.dwHighDateTime) << 32U) |
                static_cast<std::uint64_t>(creationTime.dwLowDateTime);
        }
        ::CloseHandle(processHandle);

        if (record.processName.trimmed().isEmpty())
        {
            record.processName = QStringLiteral("PID %1").arg(record.processId);
        }
    }

    // sessionStateText：把 Core Audio 状态转换为稳定可见文本。
    QString sessionStateText(const AudioSessionState state)
    {
        switch (state)
        {
        case AudioSessionStateActive:
            return QStringLiteral("活动");
        case AudioSessionStateInactive:
            return QStringLiteral("静默");
        case AudioSessionStateExpired:
            return QStringLiteral("已过期");
        default:
            return QStringLiteral("未知");
        }
    }

    // defaultEndpointIds：读取三个默认输出角色的端点 ID。
    QHash<int, QString> defaultEndpointIds(IMMDeviceEnumerator* const enumerator)
    {
        QHash<int, QString> roleIds;
        if (enumerator == nullptr)
        {
            return roleIds;
        }

        const ERole roles[] = { eConsole, eMultimedia, eCommunications };
        for (const ERole role : roles)
        {
            ComPtr<IMMDevice> defaultDevice;
            if (FAILED(enumerator->GetDefaultAudioEndpoint(
                    eRender,
                    role,
                    defaultDevice.GetAddressOf())))
            {
                continue;
            }

            LPWSTR rawEndpointId = nullptr;
            if (SUCCEEDED(defaultDevice->GetId(&rawEndpointId)))
            {
                roleIds.insert(static_cast<int>(role), coTaskMemString(rawEndpointId));
            }
        }
        return roleIds;
    }

    // endpointRoleText：标明端点是否承担默认控制台/多媒体/通信角色。
    QString endpointRoleText(
        const QString& endpointId,
        const QHash<int, QString>& roleIds)
    {
        QStringList roles;
        if (endpointId.compare(
                roleIds.value(static_cast<int>(eConsole)),
                Qt::CaseInsensitive) == 0)
        {
            roles.push_back(QStringLiteral("默认控制台"));
        }
        if (endpointId.compare(
                roleIds.value(static_cast<int>(eMultimedia)),
                Qt::CaseInsensitive) == 0)
        {
            roles.push_back(QStringLiteral("默认多媒体"));
        }
        if (endpointId.compare(
                roleIds.value(static_cast<int>(eCommunications)),
                Qt::CaseInsensitive) == 0)
        {
            roles.push_back(QStringLiteral("默认通信"));
        }
        return roles.isEmpty() ? QStringLiteral("非默认端点") : roles.join(QStringLiteral(" / "));
    }

    // shortAnsiImageName：安全复制 R0 固定 16 字节 EPROCESS ImageFileName。
    QString shortAnsiImageName(const char* const sourceText, const std::size_t capacity)
    {
        if (sourceText == nullptr || capacity == 0U)
        {
            return QString();
        }

        std::size_t textLength = 0U;
        while (textLength < capacity && sourceText[textLength] != '\0')
        {
            ++textLength;
        }
        return QString::fromLatin1(sourceText, static_cast<qsizetype>(textLength));
    }

    // crossViewSourceText：展开 R0 三源位，避免仅显示难解释的十六进制。
    QString crossViewSourceText(const std::uint32_t sourceMask)
    {
        QStringList sources;
        if ((sourceMask & KSWORD_ARK_CROSSVIEW_SOURCE_PUBLIC_WALK) != 0U)
        {
            sources.push_back(QStringLiteral("Public API"));
        }
        if ((sourceMask & KSWORD_ARK_CROSSVIEW_SOURCE_ACTIVE_LIST) != 0U)
        {
            sources.push_back(QStringLiteral("ActiveProcessLinks"));
        }
        if ((sourceMask & KSWORD_ARK_CROSSVIEW_SOURCE_CID_TABLE) != 0U)
        {
            sources.push_back(QStringLiteral("PspCidTable"));
        }
        return sources.isEmpty() ? QStringLiteral("无") : sources.join(QStringLiteral(" + "));
    }

    // sourceBitCount：统计本功能关心的 R0 进程来源数。
    int sourceBitCount(const std::uint32_t sourceMask)
    {
        int sourceCount = 0;
        if ((sourceMask & KSWORD_ARK_CROSSVIEW_SOURCE_PUBLIC_WALK) != 0U)
        {
            ++sourceCount;
        }
        if ((sourceMask & KSWORD_ARK_CROSSVIEW_SOURCE_ACTIVE_LIST) != 0U)
        {
            ++sourceCount;
        }
        if ((sourceMask & KSWORD_ARK_CROSSVIEW_SOURCE_CID_TABLE) != 0U)
        {
            ++sourceCount;
        }
        return sourceCount;
    }

    // kernelEvidenceForProcess：把 Cross-View 与 Runtime Detail 合成为一条 PID 核验结论。
    ks::misc::SoundSourceKernelEvidence kernelEvidenceForProcess(
        const ks::misc::SoundSourceRecord& record,
        const ksword::ark::ProcessCrossViewEntry* const crossViewEntry,
        const ksword::ark::ProcessRuntimeDetailResult& runtimeDetail)
    {
        ks::misc::SoundSourceKernelEvidence evidence;
        evidence.attempted = true;
        evidence.driverAvailable = true;
        if (crossViewEntry == nullptr && !runtimeDetail.io.ok)
        {
            evidence.statusText = QStringLiteral("R0 查询失败");
            evidence.detailText = QString::fromStdString(runtimeDetail.io.message);
            return evidence;
        }

        if (crossViewEntry != nullptr)
        {
            evidence.processFound = true;
            evidence.sourceMask = crossViewEntry->sourceMask;
            evidence.anomalyFlags = crossViewEntry->anomalyFlags;
            evidence.confidence = crossViewEntry->confidence;
            evidence.processObjectAddress = crossViewEntry->objectAddress;
            evidence.imageName = QString::fromStdString(crossViewEntry->imageName);
        }

        if (runtimeDetail.io.ok)
        {
            const KSWORD_ARK_PROCESS_DETAIL_RESPONSE& response = runtimeDetail.response;
            evidence.runtimeFieldFlags = response.fieldFlags;
            evidence.processObjectAddress = response.processObjectAddress != 0U
                ? response.processObjectAddress
                : evidence.processObjectAddress;
            evidence.objectTableAddress = response.objectTableAddress;

            const bool publicIdentityPresent =
                (response.fieldFlags & KSWORD_ARK_PROCESS_DETAIL_FIELD_PUBLIC_IDENTITY) != 0U;
            const bool uniquePidPresent =
                (response.fieldFlags & KSWORD_ARK_PROCESS_DETAIL_FIELD_UNIQUE_PROCESS_ID) != 0U;
            const bool publicPidMatches =
                response.processId == record.processId;
            const bool uniquePidMatches =
                !uniquePidPresent ||
                response.uniqueProcessIdValue == static_cast<std::uint64_t>(record.processId);
            evidence.processFound =
                evidence.processFound ||
                (publicIdentityPresent && publicPidMatches);
            evidence.identityMatched =
                publicIdentityPresent &&
                publicPidMatches &&
                uniquePidMatches;

            const QString runtimeImageName = shortAnsiImageName(
                response.imageName,
                KSWORD_ARK_RUNTIME_IMAGE_NAME_CHARS);
            if (!runtimeImageName.isEmpty())
            {
                evidence.imageName = runtimeImageName;
            }
        }
        else if (crossViewEntry != nullptr)
        {
            // Runtime Detail 缺失时，至少要求所有已出现的来源 PID 与目标 PID 一致。
            const bool publicPidMatches =
                crossViewEntry->publicProcessId == 0U ||
                crossViewEntry->publicProcessId == record.processId;
            const bool activePidMatches =
                crossViewEntry->activeListProcessId == 0U ||
                crossViewEntry->activeListProcessId == record.processId;
            const bool cidPidMatches =
                crossViewEntry->cidTableProcessId == 0U ||
                crossViewEntry->cidTableProcessId == record.processId;
            evidence.identityMatched =
                publicPidMatches &&
                activePidMatches &&
                cidPidMatches;
        }

        const int sourceCount = sourceBitCount(evidence.sourceMask);
        evidence.corroborated =
            evidence.processFound &&
            evidence.identityMatched &&
            sourceCount >= 2 &&
            evidence.anomalyFlags == 0U;

        if (evidence.corroborated)
        {
            evidence.statusText = QStringLiteral("R0 多源一致");
        }
        else if (evidence.anomalyFlags != 0U)
        {
            evidence.statusText = QStringLiteral("R0 发现异常");
        }
        else if (evidence.processFound)
        {
            evidence.statusText = QStringLiteral("R0 部分佐证");
        }
        else
        {
            evidence.statusText = QStringLiteral("R0 未定位进程");
        }

        evidence.detailText = QStringLiteral(
            "来源=%1；Cross-View异常=0x%2；Runtime字段=0x%3；R0映像=%4")
            .arg(crossViewSourceText(evidence.sourceMask))
            .arg(evidence.anomalyFlags, 0, 16)
            .arg(evidence.runtimeFieldFlags, 0, 16)
            .arg(evidence.imageName.isEmpty() ? QStringLiteral("不可用") : evidence.imageName);
        return evidence;
    }

    // applyKernelEvidence：仅对活动/发声候选 PID 做一次共享句柄的 R0 核验。
    void applyKernelEvidence(
        const ks::misc::SoundSourceScanOptions& options,
        ks::misc::SoundSourceScanResult& scanResult)
    {
        std::set<std::uint32_t> candidateProcessIds;
        for (const ks::misc::SoundSourceRecord& record : scanResult.records)
        {
            const bool processDetailScope = options.processIdFilter != 0U;
            if (record.processId != 0U &&
                (record.currentlyAudible || record.sessionActive || processDetailScope))
            {
                candidateProcessIds.insert(record.processId);
            }
        }
        if (!options.includeKernelEvidence || candidateProcessIds.empty())
        {
            return;
        }

        scanResult.kernelAttempted = true;
        const ksword::ark::DriverClient driverClient;
        ksword::ark::DriverHandle driverHandle = driverClient.open();
        const unsigned long openError = driverHandle.isValid()
            ? ERROR_SUCCESS
            : ::GetLastError();
        if (!driverHandle.isValid())
        {
            scanResult.kernelDiagnosticText =
                QStringLiteral("KswordARK 不可用，Win32=%1").arg(openError);
            for (ks::misc::SoundSourceRecord& record : scanResult.records)
            {
                if (candidateProcessIds.contains(record.processId))
                {
                    record.kernel.attempted = true;
                    record.kernel.statusText = QStringLiteral("R0 不可用");
                    record.kernel.detailText = scanResult.kernelDiagnosticText;
                }
            }
            return;
        }
        scanResult.kernelAvailable = true;

        const std::uint32_t minimumPid = *candidateProcessIds.begin();
        const std::uint32_t maximumPid = *candidateProcessIds.rbegin();
        const ksword::ark::ProcessCrossViewResult crossViewResult =
            driverClient.queryProcessCrossView(
                KSWORD_ARK_PROCESS_CROSSVIEW_FLAG_INCLUDE_ALL,
                minimumPid,
                maximumPid,
                kKernelCrossViewNodeBudget,
                &driverHandle);
        std::map<std::uint32_t, const ksword::ark::ProcessCrossViewEntry*> crossViewByPid;
        if (crossViewResult.io.ok)
        {
            for (const ksword::ark::ProcessCrossViewEntry& entry : crossViewResult.entries)
            {
                if (candidateProcessIds.contains(entry.processId))
                {
                    crossViewByPid[entry.processId] = &entry;
                }
            }
        }
        else
        {
            scanResult.kernelDiagnosticText =
                QString::fromStdString(crossViewResult.io.message);
        }

        for (const std::uint32_t processId : candidateProcessIds)
        {
            const ksword::ark::ProcessRuntimeDetailResult runtimeDetail =
                driverClient.queryProcessRuntimeDetail(
                    processId,
                    KSWORD_ARK_PROCESS_DETAIL_FLAG_INCLUDE_ALL,
                    &driverHandle);
            const auto crossViewIterator = crossViewByPid.find(processId);
            const ksword::ark::ProcessCrossViewEntry* const crossViewEntry =
                crossViewIterator == crossViewByPid.end()
                ? nullptr
                : crossViewIterator->second;

            for (ks::misc::SoundSourceRecord& record : scanResult.records)
            {
                if (record.processId == processId)
                {
                    record.kernel = kernelEvidenceForProcess(
                        record,
                        crossViewEntry,
                        runtimeDetail);
                }
            }
        }
    }
}

namespace ks::misc
{
    SoundSourceScanResult detectSoundSources(const SoundSourceScanOptions& options)
    {
        SoundSourceScanResult scanResult;
        const int sampleCount = std::clamp(options.sampleCount, 1, 20);
        const int sampleIntervalMs = std::clamp(options.sampleIntervalMs, 10, 250);
        scanResult.sampleWindowMs = (sampleCount - 1) * sampleIntervalMs;

        ScopedComInitialization comInitialization;
        if (!comInitialization.usable())
        {
            scanResult.diagnosticText =
                QStringLiteral("Core Audio COM 初始化失败，HRESULT=0x%1")
                .arg(static_cast<unsigned long>(comInitialization.result()), 0, 16);
            return scanResult;
        }

        ComPtr<IMMDeviceEnumerator> deviceEnumerator;
        const HRESULT enumeratorResult = ::CoCreateInstance(
            __uuidof(MMDeviceEnumerator),
            nullptr,
            CLSCTX_ALL,
            IID_PPV_ARGS(deviceEnumerator.GetAddressOf()));
        if (FAILED(enumeratorResult))
        {
            scanResult.diagnosticText =
                QStringLiteral("无法创建 MMDeviceEnumerator，HRESULT=0x%1")
                .arg(static_cast<unsigned long>(enumeratorResult), 0, 16);
            return scanResult;
        }

        const QHash<int, QString> roleIds = defaultEndpointIds(deviceEnumerator.Get());
        ComPtr<IMMDeviceCollection> endpointCollection;
        const HRESULT endpointEnumResult = deviceEnumerator->EnumAudioEndpoints(
            eRender,
            DEVICE_STATE_ACTIVE,
            endpointCollection.GetAddressOf());
        if (FAILED(endpointEnumResult))
        {
            scanResult.diagnosticText =
                QStringLiteral("无法枚举活动输出端点，HRESULT=0x%1")
                .arg(static_cast<unsigned long>(endpointEnumResult), 0, 16);
            return scanResult;
        }

        UINT endpointCount = 0U;
        endpointCollection->GetCount(&endpointCount);
        std::vector<SessionProbe> sessionProbes;
        std::vector<EndpointProbe> endpointProbes;

        for (UINT endpointIndex = 0U; endpointIndex < endpointCount; ++endpointIndex)
        {
            ComPtr<IMMDevice> endpointDevice;
            if (FAILED(endpointCollection->Item(
                    endpointIndex,
                    endpointDevice.GetAddressOf())))
            {
                continue;
            }

            LPWSTR rawEndpointId = nullptr;
            const QString endpointId = SUCCEEDED(endpointDevice->GetId(&rawEndpointId))
                ? coTaskMemString(rawEndpointId)
                : QString();
            const QString endpointName = queryDeviceFriendlyName(endpointDevice.Get());
            const QString endpointRoles = endpointRoleText(endpointId, roleIds);

            ComPtr<IAudioSessionManager2> sessionManager;
            if (FAILED(endpointDevice->Activate(
                    __uuidof(IAudioSessionManager2),
                    CLSCTX_ALL,
                    nullptr,
                    reinterpret_cast<void**>(sessionManager.GetAddressOf()))))
            {
                continue;
            }

            ComPtr<IAudioSessionEnumerator> sessionEnumerator;
            if (FAILED(sessionManager->GetSessionEnumerator(
                    sessionEnumerator.GetAddressOf())))
            {
                continue;
            }

            EndpointProbe endpointProbe;
            endpointDevice->Activate(
                __uuidof(IAudioMeterInformation),
                CLSCTX_ALL,
                nullptr,
                reinterpret_cast<void**>(endpointProbe.meter.GetAddressOf()));

            int sessionCount = 0;
            sessionEnumerator->GetCount(&sessionCount);
            for (int sessionIndex = 0; sessionIndex < sessionCount; ++sessionIndex)
            {
                ComPtr<IAudioSessionControl> baseSessionControl;
                if (FAILED(sessionEnumerator->GetSession(
                        sessionIndex,
                        baseSessionControl.GetAddressOf())))
                {
                    continue;
                }

                ComPtr<IAudioSessionControl2> sessionControl;
                if (FAILED(baseSessionControl.As(&sessionControl)))
                {
                    continue;
                }

                DWORD processId = 0U;
                sessionControl->GetProcessId(&processId);
                if (options.processIdFilter != 0U &&
                    processId != options.processIdFilter)
                {
                    continue;
                }

                SoundSourceRecord record;
                record.processId = static_cast<std::uint32_t>(processId);
                record.endpointId = endpointId;
                record.endpointName = endpointName.isEmpty()
                    ? QStringLiteral("未命名输出端点")
                    : endpointName;
                record.endpointRoleText = endpointRoles;
                record.systemSounds =
                    sessionControl->IsSystemSoundsSession() == S_OK;

                AudioSessionState sessionState = AudioSessionStateInactive;
                if (SUCCEEDED(sessionControl->GetState(&sessionState)))
                {
                    record.sessionActive = sessionState == AudioSessionStateActive;
                    record.stateText = sessionStateText(sessionState);
                }
                else
                {
                    record.stateText = QStringLiteral("状态不可用");
                }

                LPWSTR rawDisplayName = nullptr;
                if (SUCCEEDED(sessionControl->GetDisplayName(&rawDisplayName)))
                {
                    record.sessionName = coTaskMemString(rawDisplayName);
                }
                LPWSTR rawSessionId = nullptr;
                if (SUCCEEDED(sessionControl->GetSessionIdentifier(&rawSessionId)))
                {
                    record.sessionIdentifier = coTaskMemString(rawSessionId);
                }
                LPWSTR rawSessionInstanceId = nullptr;
                if (SUCCEEDED(sessionControl->GetSessionInstanceIdentifier(
                        &rawSessionInstanceId)))
                {
                    record.sessionInstanceId = coTaskMemString(rawSessionInstanceId);
                }

                queryProcessIdentity(record);
                if (options.expectedCreationTime100ns != 0U &&
                    record.creationTime100ns != options.expectedCreationTime100ns)
                {
                    // 进程详情绑定 PID + 创建时间；无法读取创建时间或 PID 已复用时都拒绝归属。
                    continue;
                }
                if (record.systemSounds)
                {
                    record.processName = QStringLiteral("系统声音");
                }
                if (record.sessionName.trimmed().isEmpty())
                {
                    record.sessionName = record.processName;
                }

                ComPtr<ISimpleAudioVolume> simpleVolume;
                if (SUCCEEDED(baseSessionControl.As(&simpleVolume)))
                {
                    simpleVolume->GetMasterVolume(&record.sessionVolume);
                    BOOL muted = FALSE;
                    simpleVolume->GetMute(&muted);
                    record.muted = muted != FALSE;
                    record.volumeAvailable = true;
                }

                SessionProbe sessionProbe;
                sessionProbe.recordIndex = scanResult.records.size();
                if (SUCCEEDED(baseSessionControl.As(&sessionProbe.meter)))
                {
                    record.meterAvailable = true;
                }

                scanResult.records.push_back(std::move(record));
                endpointProbe.recordIndices.push_back(sessionProbe.recordIndex);
                sessionProbes.push_back(std::move(sessionProbe));
            }
            endpointProbes.push_back(std::move(endpointProbe));
        }

        // 峰值采样按“所有会话一轮”执行，保证不同进程使用同一个时间窗口。
        for (int sampleIndex = 0; sampleIndex < sampleCount; ++sampleIndex)
        {
            for (SessionProbe& sessionProbe : sessionProbes)
            {
                if (sessionProbe.meter == nullptr)
                {
                    continue;
                }
                float peakValue = 0.0F;
                if (SUCCEEDED(sessionProbe.meter->GetPeakValue(&peakValue)))
                {
                    SoundSourceRecord& record =
                        scanResult.records[sessionProbe.recordIndex];
                    record.peakMaximum = std::max(record.peakMaximum, peakValue);
                    sessionProbe.peakSum += peakValue;
                    ++sessionProbe.successfulSamples;
                }
            }

            for (EndpointProbe& endpointProbe : endpointProbes)
            {
                if (endpointProbe.meter == nullptr)
                {
                    continue;
                }
                float endpointPeakValue = 0.0F;
                if (SUCCEEDED(endpointProbe.meter->GetPeakValue(
                        &endpointPeakValue)))
                {
                    endpointProbe.peakMaximum = std::max(
                        endpointProbe.peakMaximum,
                        endpointPeakValue);
                }
            }

            if (sampleIndex + 1 < sampleCount)
            {
                QThread::msleep(static_cast<unsigned long>(sampleIntervalMs));
            }
        }

        for (const SessionProbe& sessionProbe : sessionProbes)
        {
            SoundSourceRecord& record = scanResult.records[sessionProbe.recordIndex];
            if (sessionProbe.successfulSamples > 0)
            {
                record.peakAverage =
                    sessionProbe.peakSum /
                    static_cast<float>(sessionProbe.successfulSamples);
            }
            record.currentlyAudible =
                record.meterAvailable &&
                record.sessionActive &&
                !record.muted &&
                (!record.volumeAvailable ||
                 record.sessionVolume > kAudibleVolumeThreshold) &&
                record.peakMaximum >= kAudiblePeakThreshold;

            if (record.currentlyAudible)
            {
                record.verdictText = QStringLiteral("正在发声");
            }
            else if (record.sessionActive && record.muted)
            {
                record.verdictText = QStringLiteral("活动但已静音");
            }
            else if (record.sessionActive)
            {
                record.verdictText = record.meterAvailable
                    ? QStringLiteral("活动，本次未检测到波形")
                    : QStringLiteral("活动，会话峰值不可用");
            }
            else
            {
                record.verdictText = QStringLiteral("静默会话");
            }
        }

        for (const EndpointProbe& endpointProbe : endpointProbes)
        {
            for (const std::size_t recordIndex : endpointProbe.recordIndices)
            {
                if (recordIndex < scanResult.records.size())
                {
                    scanResult.records[recordIndex].endpointPeakMaximum =
                        endpointProbe.peakMaximum;
                }
            }
        }

        std::stable_sort(
            scanResult.records.begin(),
            scanResult.records.end(),
            [](const SoundSourceRecord& left, const SoundSourceRecord& right)
            {
                if (left.currentlyAudible != right.currentlyAudible)
                {
                    return left.currentlyAudible;
                }
                if (left.sessionActive != right.sessionActive)
                {
                    return left.sessionActive;
                }
                return left.peakMaximum > right.peakMaximum;
            });

        scanResult.audioQueryOk = true;
        applyKernelEvidence(options, scanResult);
        return scanResult;
    }
}
