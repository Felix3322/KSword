#pragma once

// ============================================================
// SoundSourceDetector.h
// 作用：
// 1) 定义 Core Audio 声音来源采样结果；
// 2) 定义 R0 进程 Cross-View / Runtime Detail 交叉核验证据；
// 3) 向杂项页和进程详情页提供同一个只读检测入口。
// ============================================================

#include "../../Framework.h"

#include <QString>

#include <cstdint>
#include <vector>

namespace ks::misc
{
    // SoundSourceKernelEvidence：
    // - 输入：Core Audio 会话返回的 PID；
    // - 处理：由 ArkDriverClient 执行 R0 多源进程身份核验；
    // - 返回：仅作为 PID/进程对象佐证，不把它描述成 R0 音频流采样。
    struct SoundSourceKernelEvidence
    {
        bool attempted = false;                 // 是否在本轮请求了 R0 证据。
        bool driverAvailable = false;           // KswordARK 设备是否可打开。
        bool processFound = false;              // R0 至少在一个来源中定位到目标进程。
        bool identityMatched = false;            // R0 PID/映像名与 R3 身份是否一致。
        bool corroborated = false;               // 多个 R0 来源一致且未发现异常。
        std::uint32_t sourceMask = 0;            // Public/ActiveList/CID 来源位。
        std::uint32_t anomalyFlags = 0;          // Cross-View 异常位。
        std::uint32_t confidence = 0;            // R0 Cross-View 置信度。
        std::uint32_t runtimeFieldFlags = 0;     // Runtime Detail 有效字段位。
        std::uint64_t processObjectAddress = 0; // R0 只读返回的 EPROCESS 地址证据。
        std::uint64_t objectTableAddress = 0;    // R0 只读返回的 ObjectTable 地址证据。
        QString imageName;                       // R0 EPROCESS 短映像名。
        QString statusText;                      // 面向表格的核验结论。
        QString detailText;                      // 降级、异常或来源详情。
    };

    // SoundSourceRecord：一次输出音频会话采样记录。
    // 每条记录以 endpointId + sessionInstanceId 为稳定键，PID 仅用于关联进程。
    struct SoundSourceRecord
    {
        std::uint32_t processId = 0;             // Core Audio 会话归属 PID。
        std::uint64_t creationTime100ns = 0;     // R3 读取的进程创建时间，防止 PID 复用误认。
        QString processName;                     // 进程文件名或“系统声音”。
        QString imagePath;                       // R3 QueryFullProcessImageName 路径。
        QString endpointName;                    // 输出端点友好名。
        QString endpointId;                      // MMDevice 端点 ID。
        QString endpointRoleText;                // 默认控制台/多媒体/通信角色。
        QString sessionName;                     // 会话显示名。
        QString sessionIdentifier;               // Core Audio 会话标识。
        QString sessionInstanceId;               // Core Audio 会话实例标识。
        QString stateText;                       // Active/Inactive/Expired 的可见文本。
        QString verdictText;                     // 当前发声、最近发声或静默结论。
        float peakMaximum = 0.0F;                // 采样窗口内会话最大峰值。
        float peakAverage = 0.0F;                // 采样窗口内会话平均峰值。
        float endpointPeakMaximum = 0.0F;        // 同一窗口内输出端点最大峰值。
        float sessionVolume = 0.0F;              // 会话音量 0.0~1.0。
        bool volumeAvailable = false;             // 是否成功读取 ISimpleAudioVolume。
        bool muted = false;                      // 会话是否静音。
        bool systemSounds = false;               // 是否为 Windows 系统声音会话。
        bool sessionActive = false;              // Core Audio 会话状态是否 Active。
        bool meterAvailable = false;             // 是否获得会话级 IAudioMeterInformation。
        bool currentlyAudible = false;           // 多次峰值采样是否确认正在出声。
        bool recentlyAudible = false;            // UI 是否在短时历史窗口内保留该来源。
        std::int64_t lastAudibleUnixMs = 0;      // 最近确认出声的本地时间戳。
        SoundSourceKernelEvidence kernel;        // 对 PID 的 R0 多源交叉核验证据。
    };

    // SoundSourceScanOptions：控制一次后台采样的范围和成本。
    struct SoundSourceScanOptions
    {
        std::uint32_t processIdFilter = 0; // 0 表示全局；非 0 表示进程详情页范围。
        std::uint64_t expectedCreationTime100ns = 0; // 进程详情 identity；0 表示不限制。
        bool includeKernelEvidence = true; // 是否尝试 R0 进程身份核验。
        int sampleCount = 6;               // 峰值采样次数。
        int sampleIntervalMs = 40;         // 相邻峰值采样间隔。
    };

    // SoundSourceScanResult：一次完整后台检测的返回包。
    struct SoundSourceScanResult
    {
        std::vector<SoundSourceRecord> records; // 当前存在的输出音频会话。
        QString diagnosticText;                 // Core Audio 初始化或枚举诊断。
        QString kernelDiagnosticText;           // R0 打开/查询诊断。
        int sampleWindowMs = 0;                  // 实际计划采样窗口长度。
        bool audioQueryOk = false;               // Core Audio 枚举是否完成。
        bool kernelAttempted = false;            // 本轮是否请求过 R0。
        bool kernelAvailable = false;            // 本轮 KswordARK 设备是否可用。
    };

    // detectSoundSources：
    // - 调用：仅在后台线程调用，函数会初始化该线程 COM 并短时等待峰值采样；
    // - 输入：采样范围、次数、间隔与 R0 开关；
    // - 返回：R3 会话归因 + R0 进程身份佐证，不修改音量、会话或内核对象。
    SoundSourceScanResult detectSoundSources(const SoundSourceScanOptions& options);
}
