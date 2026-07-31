#pragma once

class QApplication;

namespace ks::ui
{
    constexpr int kDefaultUiStallThresholdMs = 2000;
    constexpr int kMinimumUiStallThresholdMs = 500;
    constexpr int kMaximumUiStallThresholdMs = 30000;

    // InstallGlobalStallDetector 作用：
    // - 安装一次 Qt 主事件循环心跳检测器；
    // - 独立监控线程可在 UI 线程卡住时继续显示原生取消提示。
    void InstallGlobalStallDetector(QApplication* appInstance);

    // SetGlobalStallDetectorSettings 作用：
    // - 即时启用/关闭卡顿检测并更新阈值；
    // - 阈值会被限制在 kMinimumUiStallThresholdMs 到
    //   kMaximumUiStallThresholdMs 之间。
    void SetGlobalStallDetectorSettings(bool enabled, int thresholdMs);

    bool IsGlobalStallDetectorEnabled();
    int GlobalStallDetectorThresholdMs();

    // IsGlobalStallCancellationRequested 作用：
    // - 供可协作取消的耗时动作查询全局取消请求；
    // - 检测器还会调用 CancelSynchronousIo，尽力中止 UI 线程正在等待的同步 I/O。
    bool IsGlobalStallCancellationRequested();

    // ClearGlobalStallCancellationRequest 作用：
    // - 动作处理完取消请求后主动清除标记；
    // - 未主动清除时，检测器会在界面恢复响应后自动过期该标记。
    void ClearGlobalStallCancellationRequest();
}
