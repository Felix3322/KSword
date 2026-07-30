#pragma once

// ============================================================
// KernelThreadAuditTab.h
// 作用：
// 1) 为驱动 Dock 提供 System(PID 4) 系统线程审计页；
// 2) 为内核 Dock 提供工作队列线程候选审计页；
// 3) 复用公开线程快照、ArkDriverClient R0 扩展和模块归属信息；
// 4) 仅对经过 R3 与 R0 双重保护检查的第三方驱动线程开放管理动作。
// ============================================================

#include "../Framework.h"

#include <QWidget>

#include <cstdint>
#include <vector>

class CodeEditorWidget;
class QEvent;
class QLabel;
class QLineEdit;
class QPushButton;
class QTableWidget;

// KernelThreadAuditTab：
// - Mode::SystemThreads 展示全部 System 线程，落在驱动 Dock；
// - Mode::WorkQueueThreads 只展示可靠证据支持的工作队列候选，落在内核 Dock；
// - 页面不读取未公开队列链表，也不猜测 ETHREAD/WORK_QUEUE_ITEM 偏移。
class KernelThreadAuditTab final : public QWidget
{
public:
    // Mode：决定同一审计组件的筛选范围与说明文本。
    enum class Mode
    {
        SystemThreads,
        WorkQueueThreads
    };

    // 构造函数：
    // - 输入 mode：系统线程总览或工作队列候选模式；
    // - 输入 parent：Qt 父控件；
    // - 输出：完成 UI 和交互连接，首次刷新由 0ms 任务触发。
    explicit KernelThreadAuditTab(Mode mode, QWidget* parent = nullptr);

    // requestRefresh：
    // - 输入：无；
    // - 处理：后台枚举线程、R0 worker 标志和模块快照；
    // - 输出：结果异步回投表格，不阻塞 Dock 初始化。
    void requestRefresh();

protected:
    // changeEvent：
    // - 输入 event：Qt 语言变化事件；
    // - 处理：重建表头、按钮提示和当前详情；
    // - 输出：无。
    void changeEvent(QEvent* event) override;

private:
    // Column：表格稳定列顺序，同时供 A/B 预设与表头菜单使用。
    enum class Column
    {
        ThreadId = 0,
        Category,
        QueueType,
        State,
        WaitReason,
        StartRoutine,
        Parameter,
        Module,
        ModuleBase,
        ModulePath,
        R0Status,
        Protection,
        Count
    };

    // ViewPreset：A 为调度概览，B 为地址与归属证据，Custom 表示手工列布局。
    enum class ViewPreset
    {
        Overview,
        Evidence,
        Custom
    };

    // ModuleRecord：SystemModuleInformation 的边界安全副本。
    struct ModuleRecord
    {
        QString name;                  // name：模块文件名。
        QString path;                  // path：内核模块原始路径。
        std::uint64_t baseAddress = 0; // baseAddress：模块加载基址。
        std::uint32_t imageSize = 0;   // imageSize：模块映像范围大小。
        bool kernelImage = false;      // kernelImage：是否为首个 ntoskrnl 映像。
    };

    // ThreadRow：UI 使用的稳定线程证据行。
    struct ThreadRow
    {
        std::uint32_t threadId = 0;       // threadId：System 线程 ID。
        std::uint64_t startAddress = 0;   // startAddress：R3 线程启动入口。
        int priority = 0;                 // priority：动态优先级。
        int basePriority = 0;             // basePriority：基础优先级。
        std::uint32_t state = 0;          // state：KTHREAD_STATE 数值。
        std::uint32_t waitReason = 0;     // waitReason：KWAIT_REASON 数值。
        std::uint32_t r0Flags = 0;        // r0Flags：KSWORD_ARK_THREAD_FLAG_*。
        std::uint32_t r0FieldFlags = 0;   // r0FieldFlags：R0 字段可用位图。
        std::uint32_t r0Status = 0;       // r0Status：R0 线程扩展状态。
        ModuleRecord module;              // module：启动地址归属模块。
        bool moduleResolved = false;      // moduleResolved：启动地址是否落入已加载模块。
        bool workerKnown = false;         // workerKnown：ActiveExWorker 字段是否可信。
        bool activeWorker = false;        // activeWorker：R0 是否标记 ActiveExWorker。
        bool workerCandidate = false;     // workerCandidate：是否有可靠工作队列证据。
        bool protectedTarget = true;      // protectedTarget：是否禁止危险线程操作。
        QString protectionReason;         // protectionReason：保护原因。
    };

    // Snapshot：后台刷新一次性结果，避免 UI 读取变化中的容器。
    struct Snapshot
    {
        std::vector<ThreadRow> rows; // rows：排序后的 System 线程证据。
        QString diagnosticText;     // diagnosticText：枚举与 R0 降级说明。
        bool usedNtQuery = false;   // usedNtQuery：R3 是否使用 NtQuerySystemInformation。
        bool r0Available = false;   // r0Available：R0 线程扩展是否成功。
    };

    // UI 初始化与翻译函数。
    void initializeUi();
    void applyTranslatedText();
    void applySnapshot(const Snapshot& snapshot);
    void rebuildTable();
    void updateDetail();

    // A/B 视图与列菜单函数。
    void applyColumnPreset(ViewPreset preset);
    void updatePresetButtons();
    void showHeaderMenu(const QPoint& localPosition);
    void showRowMenu(const QPoint& localPosition);

    // 线程动作函数：
    // - suspend/resume/terminate 均通过 ArkDriverClient；
    // - terminate 使用 Normal APC，且 UI 双确认与 R0 保护同时生效。
    void runControlAction(unsigned long action);
    const ThreadRow* selectedRow() const;
    int selectedSourceIndex() const;

    // 纯函数：后台采集、模块匹配和文本映射。
    static Snapshot collectSnapshot(Mode mode);
    static std::vector<ModuleRecord> queryKernelModules(QString* errorTextOut);
    static ModuleRecord findOwnerModule(
        const std::vector<ModuleRecord>& modules,
        std::uint64_t address,
        bool* matchedOut);
    static QString stateText(std::uint32_t stateValue);
    static QString waitReasonText(std::uint32_t waitReasonValue);
    static QString r0StatusText(std::uint32_t statusValue);
    static QString addressText(std::uint64_t addressValue);

    Mode m_mode = Mode::SystemThreads;          // m_mode：当前页面审计范围。
    ViewPreset m_viewPreset = ViewPreset::Overview; // m_viewPreset：当前 A/B/自定义列状态。
    QLineEdit* m_filterEdit = nullptr;          // m_filterEdit：关键字筛选框。
    QPushButton* m_refreshButton = nullptr;     // m_refreshButton：刷新按钮。
    QPushButton* m_suspendButton = nullptr;     // m_suspendButton：挂起第三方驱动线程。
    QPushButton* m_resumeButton = nullptr;      // m_resumeButton：恢复第三方驱动线程。
    QPushButton* m_terminateButton = nullptr;   // m_terminateButton：终止第三方驱动线程。
    QPushButton* m_overviewButton = nullptr;    // m_overviewButton：A 组列按钮。
    QPushButton* m_evidenceButton = nullptr;    // m_evidenceButton：B 组列按钮。
    QLabel* m_statusLabel = nullptr;            // m_statusLabel：刷新与筛选状态。
    QTableWidget* m_table = nullptr;            // m_table：线程证据表格。
    CodeEditorWidget* m_detailEditor = nullptr; // m_detailEditor：选中线程详情。
    std::vector<ThreadRow> m_rows;               // m_rows：最近一次完整快照。
    bool m_refreshRunning = false;               // m_refreshRunning：防止并发重复刷新。
    std::uint64_t m_refreshTicket = 0;           // m_refreshTicket：丢弃过期后台结果。
};
