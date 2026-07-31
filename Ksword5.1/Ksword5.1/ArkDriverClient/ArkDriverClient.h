#pragma once

#include "ArkDriverCapabilities.h"
#include "ArkDriverTypes.h"

#include <functional>

namespace ksword::ark
{
    // Format the immutable R0 evidence packet as a stable diagnostic block.
    // UI layers may prepend localized context, but should not reinterpret a
    // present certificate table as a successful trust-chain validation.
    std::string formatImageSignatureEvidence(const ImageSignatureQueryResult& result);

    // DriverClient centralizes all KswordARK control-device access. Docks should
    // call this class instead of opening \\.\KswordARKLog or invoking
    // DeviceIoControl directly.
    class DriverClient
    {
    public:
        // setR0UnavailableHandler：
        // - 为整个 R0 客户端注册一个“控制设备不存在”的 UI 通知入口；
        // - handler 可能从工作线程调用，接收方必须自行切回 UI 线程；
        // - 仅用于驱动未启用，不把旧驱动/业务 IOCTL 失败误报为“请启用 R0”。
        using R0UnavailableHandler = std::function<void(unsigned long win32Error)>;
        static void setR0UnavailableHandler(R0UnavailableHandler handler);

        // setR0PermissionRequiredHandler：
        // - 统一通知“驱动已存在，但当前用户无权执行该 R0 IOCTL”的情况；
        // - handler 可能从工作线程调用，接收方必须自行切回 UI 线程。
        using R0PermissionRequiredHandler = std::function<void(unsigned long win32Error)>;
        static void setR0PermissionRequiredHandler(R0PermissionRequiredHandler handler);

        // clearR0NotificationHandlersAndWait：
        // - 同时停止两类 R0 全局通知，并等待已经复制到工作线程的回调执行完毕；
        // - 主窗口析构必须先调用本函数，保证返回后不再有回调向该窗口投递事件；
        // - 不得从上述 handler 内部调用，否则调用线程会等待自身结束。
        static void clearR0NotificationHandlersAndWait();

        DriverClient() = default;

        // Best-effort branding upload for the VMware-only bugcheck panel.
        // The driver silently discards a valid packet when that feature is inactive.
        IoResult setBugcheckBitmap(
            std::uint32_t width,
            std::uint32_t height,
            std::uint32_t stride,
            std::uint32_t brandColorRgb,
            const std::vector<std::uint8_t>& bgraPixels) const;

        // Open one synchronous control handle. The returned handle owns CloseHandle.
        DriverHandle open(unsigned long desiredAccess = GENERIC_READ | GENERIC_WRITE) const;

        // Open one overlapped control handle for wait-style callback receivers.
        DriverHandle openOverlapped(unsigned long desiredAccess = GENERIC_READ | GENERIC_WRITE) const;

        // Low-level synchronous IOCTL helper used by narrow advanced UI paths.
        IoResult deviceIoControl(
            unsigned long ioControlCode,
            void* inputBuffer,
            unsigned long inputBytes,
            void* outputBuffer,
            unsigned long outputBytes,
            DriverHandle* existingHandle = nullptr) const;

        // Low-level overlapped IOCTL helper for callback event waiting.
        AsyncIoResult deviceIoControlAsync(
            DriverHandle& handle,
            unsigned long ioControlCode,
            void* inputBuffer,
            unsigned long inputBytes,
            void* outputBuffer,
            unsigned long outputBytes,
            OVERLAPPED* overlapped) const;

        IoResult terminateProcess(std::uint32_t processId, long exitStatus) const;
        IoResult terminateProcess(DriverHandle& handle, std::uint32_t processId, long exitStatus) const;
        IoResult terminateThread(std::uint32_t threadId, std::uint32_t processId, long exitStatus) const;
        IoResult terminateThread(DriverHandle& handle, std::uint32_t threadId, std::uint32_t processId, long exitStatus) const;
        IoResult setThreadSuspended(std::uint32_t threadId, std::uint32_t processId, bool suspended) const;
        IoResult setThreadSuspended(DriverHandle& handle, std::uint32_t threadId, std::uint32_t processId, bool suspended) const;
        IoResult controlDriverThread(std::uint32_t threadId, std::uint64_t expectedStartAddress, std::uint64_t expectedCreateTime100ns, unsigned long action, unsigned long terminateMethod, bool uiConfirmed) const;
        IoResult controlDriverThread(DriverHandle& handle, std::uint32_t threadId, std::uint64_t expectedStartAddress, std::uint64_t expectedCreateTime100ns, unsigned long action, unsigned long terminateMethod, bool uiConfirmed) const;
        IoResult experimentalReturnToFirmware() const;
        IoResult suspendProcess(std::uint32_t processId) const;
        IoResult setProcessProtection(std::uint32_t processId, std::uint8_t protectionLevel) const;
        ProcessVisibilityResult setProcessVisibility(std::uint32_t processId, unsigned long action, unsigned long flags = 0UL) const;
        // setProcessIntegrity：
        // - 输入：PID 和 S-1-16-* mandatory label RID；
        // - 处理：封装 R0 进程完整性 IOCTL；驱动端先走 Zw* token API，
        //   必要时由 R0 DynData/PDB 私有 Token 字段兜底；
        // - 返回：ProcessIntegrityResult；io.ok 与 status/lastStatus 分别表示通信和语义结果。
        ProcessIntegrityResult setProcessIntegrity(std::uint32_t processId, unsigned long integrityRid) const;
        ProcessSpecialFlagsResult setProcessSpecialFlags(std::uint32_t processId, unsigned long action, unsigned long flags = 0UL) const;
        ProcessDkomResult dkomProcess(std::uint32_t processId, unsigned long action, unsigned long flags = 0UL) const;
        ProcessInjectResult injectProcessDll(
            std::uint32_t processId,
            const std::wstring& dllPath,
            unsigned long flags = KSWORD_ARK_PROCESS_INJECT_FLAG_UI_CONFIRMED | KSWORD_ARK_PROCESS_INJECT_FLAG_WAIT_THREAD) const;
        ProcessInjectResult injectProcessShellcode(
            std::uint32_t processId,
            const std::vector<std::uint8_t>& shellcode,
            unsigned long flags = KSWORD_ARK_PROCESS_INJECT_FLAG_UI_CONFIRMED) const;

        ProcessEnumResult enumerateProcesses(unsigned long flags) const;
        ThreadEnumResult enumerateThreads(unsigned long flags, std::uint32_t processId = 0) const;
        WorkQueueEnumResult enumerateWorkQueues(
            unsigned long flags = KSWORD_ARK_WORK_QUEUE_FLAG_INCLUDE_ALL,
            unsigned long maxEntries = KSWORD_ARK_WORK_QUEUE_DEFAULT_MAX_ENTRIES) const;
        HandleEnumResult enumerateProcessHandles(std::uint32_t processId, unsigned long flags = KSWORD_ARK_ENUM_HANDLE_FLAG_INCLUDE_ALL) const;
        HandleObjectQueryResult queryHandleObject(std::uint32_t processId, std::uint64_t handleValue, unsigned long flags = KSWORD_ARK_QUERY_OBJECT_FLAG_INCLUDE_ALL, unsigned long requestedAccess = 0) const;
        AlpcPortQueryResult queryAlpcPort(std::uint32_t processId, std::uint64_t handleValue, unsigned long flags = KSWORD_ARK_ALPC_QUERY_FLAG_INCLUDE_ALL) const;
        ProcessSectionQueryResult queryProcessSection(std::uint32_t processId, unsigned long flags = KSWORD_ARK_SECTION_QUERY_FLAG_INCLUDE_ALL, unsigned long maxMappings = KSWORD_ARK_SECTION_MAPPING_LIMIT_DEFAULT) const;
        FileSectionMappingsQueryResult queryFileSectionMappings(const std::wstring& ntPath, unsigned long flags = KSWORD_ARK_FILE_SECTION_QUERY_FLAG_INCLUDE_ALL, unsigned long maxMappings = KSWORD_ARK_SECTION_MAPPING_LIMIT_DEFAULT) const;
        VirtualMemoryQueryResult queryVirtualMemory(
            std::uint32_t processId,
            std::uint64_t baseAddress,
            unsigned long flags = 0UL,
            DriverHandle* existingHandle = nullptr) const;
        VirtualMemoryReadResult readVirtualMemory(
            std::uint32_t processId,
            std::uint64_t baseAddress,
            std::uint32_t bytesToRead,
            unsigned long flags = KSWORD_ARK_MEMORY_READ_FLAG_ZERO_FILL_UNREADABLE,
            DriverHandle* existingHandle = nullptr) const;
        VirtualMemoryWriteResult writeVirtualMemory(
            std::uint32_t processId,
            std::uint64_t baseAddress,
            const std::vector<std::uint8_t>& bytes,
            unsigned long flags = 0UL,
            DriverHandle* existingHandle = nullptr) const;
        // queryKernelMemoryEvidence：
        // - 输入：只读采集 flags、行数/字节预算和可选地址半开区间。
        // - 处理：封装 IOCTL_KSWORD_ARK_SCAN_KERNEL_MEMORY_EVIDENCE，解析变长 evidence rows。
        // - 返回：KernelMemoryEvidenceResult；旧驱动/能力缺失时 unsupported=true，调用方显示 graceful message。
        KernelMemoryEvidenceResult queryKernelMemoryEvidence(
            unsigned long flags = KSWORD_ARK_MEMORY_EVIDENCE_FLAG_INCLUDE_ALL,
            unsigned long maxRows = KSWORD_ARK_MEMORY_EVIDENCE_DEFAULT_MAX_ROWS,
            std::uint64_t startAddress = 0,
            std::uint64_t endAddress = 0,
            std::uint64_t maxBytes = KSWORD_ARK_MEMORY_EVIDENCE_DEFAULT_MAX_BYTES,
            unsigned long maxBigPoolRows = KSWORD_ARK_MEMORY_EVIDENCE_DEFAULT_BIGPOOL_ROWS,
            unsigned long sampleBytes = KSWORD_ARK_MEMORY_EVIDENCE_DEFAULT_SAMPLE_BYTES) const;
        FileInfoQueryResult queryFileInfo(const std::wstring& ntPath, unsigned long flags = KSWORD_ARK_QUERY_FILE_INFO_FLAG_INCLUDE_ALL) const;
        FileInfoQueryResult queryFileInfo(DriverHandle& handle, const std::wstring& ntPath, unsigned long flags = KSWORD_ARK_QUERY_FILE_INFO_FLAG_INCLUDE_ALL) const;
        // Read Authenticode PE certificate-table structure and cached Code
        // Integrity state through the driver. No WinTrust API is used.
        ImageSignatureQueryResult queryImageSignature(
            const std::wstring& ntPath,
            std::uint64_t expectedModuleBase = 0,
            unsigned long flags = KSWORD_ARK_IMAGE_SIGNATURE_QUERY_FLAG_DEFAULT) const;
        // setFileIntegrity：
        // - 输入：驱动可打开的 NT 路径、目录标志和 S-1-16-* mandatory label RID；
        // - 处理：封装 R0 文件 Mandatory Label IOCTL，驱动端只调用 ZwCreateFile/ZwSetSecurityObject；
        // - 返回：FileIntegrityResult；io.ok 与 status/lastStatus 分别表示通信和语义结果。
        FileIntegrityResult setFileIntegrity(const std::wstring& ntPath, bool isDirectory, unsigned long integrityRid) const;
        IoResult controlFileMonitor(unsigned long action, unsigned long operationMask = KSWORD_ARK_FILE_MONITOR_OPERATION_ALL, unsigned long processId = 0UL, unsigned long flags = 0UL) const;
        FileMonitorStatusResult queryFileMonitorStatus() const;
        FileMonitorDrainResult drainFileMonitor(unsigned long maxEvents = 128UL, unsigned long flags = 0UL) const;
        // controlDebugOutput：注册、注销或查询 DbgSetDebugPrintCallback 捕获状态。
        DebugOutputControlResult controlDebugOutput(unsigned long action) const;
        DebugOutputControlResult controlDebugOutput(DriverHandle& handle, unsigned long action) const;
        // drainDebugOutput：使用单调游标增量读取 R0 固定环形缓冲区。
        DebugOutputDrainResult drainDebugOutput(std::uint64_t afterSequence, unsigned long maxRecords = KSWORD_ARK_DEBUG_OUTPUT_DEFAULT_DRAIN_RECORDS) const;
        DebugOutputDrainResult drainDebugOutput(DriverHandle& handle, std::uint64_t afterSequence, unsigned long maxRecords = KSWORD_ARK_DEBUG_OUTPUT_DEFAULT_DRAIN_RECORDS) const;
        RegistryReadResult readRegistryValue(const std::wstring& kernelKeyPath, const std::wstring& valueName, unsigned long maxDataBytes = KSWORD_ARK_REGISTRY_DATA_MAX_BYTES) const;
        RegistryEnumResult enumerateRegistryKey(const std::wstring& kernelKeyPath, unsigned long flags = KSWORD_ARK_REGISTRY_ENUM_FLAG_INCLUDE_SUBKEYS | KSWORD_ARK_REGISTRY_ENUM_FLAG_INCLUDE_VALUES) const;
        RegistryOperationResult setRegistryValue(const std::wstring& kernelKeyPath, const std::wstring& valueName, std::uint32_t valueType, const std::vector<std::uint8_t>& data) const;
        RegistryOperationResult deleteRegistryValue(const std::wstring& kernelKeyPath, const std::wstring& valueName) const;
        RegistryOperationResult createRegistryKey(const std::wstring& kernelKeyPath) const;
        RegistryOperationResult deleteRegistryKey(const std::wstring& kernelKeyPath) const;
        RegistryOperationResult renameRegistryValue(const std::wstring& kernelKeyPath, const std::wstring& oldValueName, const std::wstring& newValueName) const;
        RegistryOperationResult renameRegistryKey(const std::wstring& kernelKeyPath, const std::wstring& newKeyName) const;
        IoResult deletePath(const std::wstring& ntPath, bool isDirectory) const;
        IoResult deletePath(DriverHandle& handle, const std::wstring& ntPath, bool isDirectory) const;

        SsdtEnumResult enumerateSsdt(unsigned long flags) const;
        SsdtEnumResult enumerateShadowSsdt(unsigned long flags = KSWORD_ARK_ENUM_SSDT_FLAG_INCLUDE_UNRESOLVED) const;
        // queryProcessCrossView：
        // - 输入：进程 cross-view 采集 flags、PID 半开/闭合过滤和节点预算。
        // - 处理：只通过 ArkDriverClient 调用 R0，不让 Dock 直接 DeviceIoControl。
        // - existingHandle：可复用已打开的设备句柄，批量只读查询时避免重复打开驱动。
        // - 返回：ProcessCrossViewResult，包含 source matrix、anomaly flags 和 DynData 缺口。
        ProcessCrossViewResult queryProcessCrossView(
            unsigned long flags = KSWORD_ARK_PROCESS_CROSSVIEW_FLAG_INCLUDE_ALL,
            std::uint32_t startPid = 0,
            std::uint32_t endPid = 0,
            unsigned long maxNodes = KSWORD_ARK_CROSSVIEW_DEFAULT_MAX_NODES,
            DriverHandle* existingHandle = nullptr) const;
        // queryThreadCrossView：
        // - 输入：线程 cross-view 采集 flags、可选 PID/TID 过滤和节点预算。
        // - 处理：解析 ETHREAD/KTHREAD 来源矩阵，只读展示线程 DKOM 证据。
        // - 返回：ThreadCrossViewResult；不返回可用于写操作的对象凭据。
        ThreadCrossViewResult queryThreadCrossView(
            unsigned long flags = KSWORD_ARK_THREAD_CROSSVIEW_FLAG_INCLUDE_ALL,
            std::uint32_t processId = 0,
            std::uint32_t startTid = 0,
            std::uint32_t endTid = 0,
            unsigned long maxNodes = KSWORD_ARK_CROSSVIEW_DEFAULT_MAX_NODES) const;
        // query*RuntimeDetail：
        // - 输入：PID/TID 和只读字段组 flags。
        // - 处理：封装 R0 PDB/DynData detail IOCTL，失败时返回 unsupported/unavailable。
        // - existingHandle：可选共享设备句柄；为空时保持原有按调用打开行为。
        // - 返回：固定响应结构；不把对象地址作为后续写操作凭据。
        ProcessRuntimeDetailResult queryProcessRuntimeDetail(
            std::uint32_t processId,
            unsigned long flags = KSWORD_ARK_PROCESS_DETAIL_FLAG_INCLUDE_ALL,
            DriverHandle* existingHandle = nullptr) const;
        ThreadRuntimeDetailResult queryThreadRuntimeDetail(std::uint32_t threadId, std::uint32_t processId = 0, unsigned long flags = KSWORD_ARK_THREAD_DETAIL_FLAG_INCLUDE_ALL) const;
        // query*RuntimeFieldSamples：
        // - 输入：deep PDB catalog 选出的字段 offset/size 列表。
        // - 处理：封装只读小字段采样 IOCTL，R0 不接受对象地址。
        // - 返回：每字段状态、字节样本和 U64 摘要，旧驱动返回 unsupported。
        RuntimeFieldSampleResult queryProcessRuntimeFieldSamples(std::uint32_t processId, const std::vector<RuntimeFieldSampleRequestItem>& items, unsigned long flags = 0UL) const;
        RuntimeFieldSampleResult queryThreadRuntimeFieldSamples(std::uint32_t threadId, std::uint32_t processId, const std::vector<RuntimeFieldSampleRequestItem>& items, unsigned long flags = 0UL) const;
        KernelInlineHookScanResult scanInlineHooks(unsigned long flags = 0UL, unsigned long maxEntries = KSWORD_ARK_KERNEL_HOOK_DEFAULT_MAX_ENTRIES, const std::wstring& moduleName = std::wstring()) const;
        // scanKernelExecutableMemory：
        // - 作用：调用 Prompt 1 定义的内核可执行页扫描 IOCTL，并解析变长响应为 R3 模型。
        // - 参数 flags：扫描开关位，通常由 UI 传入 INCLUDE_ALL。
        // - 参数 maxEntries：单次最大返回条数，0 表示使用默认值。
        // - 参数 modulePathFilter：R3 预留筛选参数，当前由 UI 在本地完成过滤。
        // - 返回：KernelExecutableMemoryScanResult，io.ok 表示传输和协议解析成功。
        KernelExecutableMemoryScanResult scanKernelExecutableMemory(unsigned long flags = 0UL, unsigned long maxEntries = 4096UL, const std::wstring& modulePathFilter = std::wstring()) const;
        KernelInlinePatchResult patchInlineHook(std::uint64_t functionAddress, unsigned long mode, unsigned long patchBytes, const std::vector<std::uint8_t>& expectedCurrentBytes, const std::vector<std::uint8_t>& restoreBytes = std::vector<std::uint8_t>(), unsigned long flags = 0UL) const;
        KernelIatEatHookScanResult enumerateIatEatHooks(unsigned long flags = KSWORD_ARK_KERNEL_SCAN_FLAG_INCLUDE_IMPORTS | KSWORD_ARK_KERNEL_SCAN_FLAG_INCLUDE_EXPORTS, unsigned long maxEntries = KSWORD_ARK_KERNEL_HOOK_DEFAULT_MAX_ENTRIES, const std::wstring& moduleName = std::wstring()) const;
        // enumerateKernelTimerDpc：只读查询每 CPU TimerTable，返回 KTIMER/KDPC 快照及 partial/corrupt 诊断。
        KernelTimerDpcEnumResult enumerateKernelTimerDpc(
            unsigned long maxEntries = KSWORD_ARK_TIMER_DPC_DEFAULT_MAX_ENTRIES,
            unsigned long maxEntriesPerBucket = KSWORD_ARK_TIMER_DPC_DEFAULT_BUCKET_BUDGET) const;
        DriverObjectQueryResult queryDriverObject(const std::wstring& driverName, unsigned long flags = KSWORD_ARK_DRIVER_OBJECT_QUERY_FLAG_INCLUDE_ALL, unsigned long maxDevices = KSWORD_ARK_DRIVER_DEVICE_LIMIT_DEFAULT, unsigned long maxAttachedDevices = KSWORD_ARK_DRIVER_ATTACHED_LIMIT_DEFAULT) const;
        // queryIoctlRegistry：查询 KswordARK 统一 dispatch 注册表，只读返回元数据。
        IoctlRegistryQueryResult queryIoctlRegistry(unsigned long flags = KSWORD_ARK_IOCTL_REGISTRY_FLAG_INCLUDE_HANDLER, unsigned long maxEntries = KSWORD_ARK_IOCTL_REGISTRY_MAX_ENTRIES) const;
        // queryDriverIntegrity：
        // - 输入：可选 DriverObject 名称、模块基址和采集预算。
        // - 处理：调用统一驱动完整性 IOCTL，聚合 DriverObject/LDR/FastIo/CPU/IDT 证据。
        // - 返回：DriverIntegrityResult；unsupported=true 表示 R0 尚未集成或驱动过旧。
        DriverIntegrityResult queryDriverIntegrity(
            const std::wstring& driverName = std::wstring(),
            std::uint64_t targetModuleBase = 0,
            unsigned long flags = KSWORD_ARK_DRIVER_INTEGRITY_FLAG_DEFAULT,
            unsigned long maxRows = KSWORD_ARK_DRIVER_INTEGRITY_DEFAULT_MAX_ROWS,
            unsigned long maxIdtVectorsPerCpu = KSWORD_ARK_DRIVER_INTEGRITY_DEFAULT_IDT_VECTORS) const;
        // queryUnloadedDrivers：
        // - 输入：MmUnloadedDrivers、PiDDBCacheTable 或 g_KernelHashBucketList 来源及行数预算；
        // - 处理：调用统一只读 IOCTL，并按 HAS_* 标志保留各来源真实支持的列；
        // - 返回：UnloadedDriverQueryResult；不会删除、清理或修改任何内核缓存。
        UnloadedDriverQueryResult queryUnloadedDrivers(
            std::uint32_t source,
            unsigned long maxRows = KSWORD_ARK_UNLOADED_DRIVER_DEFAULT_ROWS) const;
        // queryKernelCpuIntegrity：
        // - 输入：CPU/IDT 采集 flags 与预算。
        // - 处理：复用 queryDriverIntegrity 的协议，只请求 CPU entry evidence。
        // - 返回：DriverIntegrityResult；不执行任何 MSR/IDT/GDT 写操作。
        DriverIntegrityResult queryKernelCpuIntegrity(
            unsigned long flags = KSWORD_ARK_DRIVER_INTEGRITY_FLAG_CPU | KSWORD_ARK_DRIVER_INTEGRITY_FLAG_IDT_ENTRIES,
            unsigned long maxRows = KSWORD_ARK_DRIVER_INTEGRITY_DEFAULT_MAX_ROWS,
            unsigned long maxIdtVectorsPerCpu = KSWORD_ARK_DRIVER_INTEGRITY_DEFAULT_IDT_VECTORS) const;
        // restoreIdtBaseline：对指定 CPU/向量执行不可变启动期基线的只读预检或原子恢复。
        // force=false 只返回 FORCE_REQUIRED/当前状态；force=true 时调用方还必须显式传入 uiConfirmed。
        IdtBaselineRestoreResult restoreIdtBaseline(
            std::uint16_t processorGroup,
            std::uint8_t processorNumber,
            std::uint8_t vector,
            std::uint64_t expectedRawLow,
            std::uint64_t expectedRawHigh,
            bool force,
            bool uiConfirmed) const;
        PiDdbQueryResult queryPiDdb(
            unsigned long maxRows = KSWORD_ARK_PIDDB_DEFAULT_ROWS) const;
        PiDdbDeleteResult deletePiDdbEntry(
            const PiDdbEntry& expectedEntry,
            bool force,
            bool uiConfirmed) const;
        // queryHvmStatus/controlHvm：读取 VT-x/EPT 能力并执行准备、自检、
        // 一次性 VMCALL 来宾、VM-exit 采集或资源释放。
        HvmStatusResult queryHvmStatus() const;
        HvmControlResult controlHvm(
            unsigned long command,
            unsigned long expectedGeneration,
            bool force,
            bool allowNested,
            bool uiConfirmed) const;
        // queryCpuHardwareSnapshot：
        // - 输入：无；R0 只执行 CPUID 与处理器数量查询。
        // - 处理：封装 IOCTL_KSWORD_ARK_QUERY_CPU_HARDWARE，解析 vendor/brand/family/model/feature mask。
        // - 返回：CpuHardwareSnapshotResult；旧驱动未注册 IOCTL 时 unsupported=true。
        CpuHardwareSnapshotResult queryCpuHardwareSnapshot() const;
        // queryPhysicalMemoryLayout：
        // - 输入：无；R0 只读取 MmGetPhysicalMemoryRanges 聚合结果。
        // - 处理：封装 IOCTL_KSWORD_ARK_QUERY_PHYSICAL_MEMORY_LAYOUT，解析物理内存范围统计。
        // - 返回：PhysicalMemoryLayoutResult；不返回任何内存内容。
        PhysicalMemoryLayoutResult queryPhysicalMemoryLayout() const;
        DriverForceUnloadResult forceUnloadDriver(const std::wstring& driverName, unsigned long flags = 0UL, unsigned long timeoutMilliseconds = 3000UL) const;
        DriverForceUnloadResult forceUnloadDriverByModuleBase(std::uint64_t moduleBase, const std::wstring& fallbackDriverName = std::wstring(), unsigned long flags = 0UL, unsigned long timeoutMilliseconds = 3000UL) const;
        // controlDriverCommunication：
        // - 输入：精确模块基址、canonical 名称、证据扫描返回的 DriverObject 地址和 action；
        // - 处理：统一封装独立通信控制 IOCTL，Dock UI 不直接访问 KswordARK 设备；
        // - 返回：状态、MajorFunction 掩码、冲突信息和 canonical DriverObject 名称。
        DriverCommunicationControlResult controlDriverCommunication(
            std::uint64_t moduleBase,
            const std::wstring& canonicalDriverName,
            unsigned long action,
            std::uint64_t expectedDriverObjectAddress = 0U) const;
        DriverCommunicationControlResult queryDriverCommunication(
            std::uint64_t moduleBase,
            const std::wstring& displayName = std::wstring()) const;
        DriverCommunicationControlResult blindDriverCommunication(
            std::uint64_t moduleBase,
            const std::wstring& canonicalDriverName,
            std::uint64_t expectedDriverObjectAddress) const;
        DriverCommunicationControlResult restoreDriverCommunication(
            std::uint64_t moduleBase,
            const std::wstring& displayName = std::wstring()) const;
        // prepareMutation / commitMutation / rollbackMutation / queryMutationAudit：
        // - 输入：受控 transaction 参数或只读 audit 查询参数。
        // - 处理：仅在 ArkDriverClient 内封装 mutation IOCTL；Dock UI 不直接调用 DeviceIoControl。
        // - 返回：固定响应或 audit rows；UI 只能展示 dry-run/audit/rollback，不暴露任意写按钮。
        MutationResponseResult prepareMutation(const MutationPrepareInput& input) const;
        MutationResponseResult commitMutation(std::uint64_t transactionId, unsigned long flags = KSWORD_ARK_MUTATION_FLAG_DRY_RUN) const;
        MutationResponseResult rollbackMutation(std::uint64_t transactionId, unsigned long flags = KSWORD_ARK_MUTATION_FLAG_DRY_RUN) const;
        MutationAuditResult queryMutationAudit(unsigned long flags = 0, unsigned long maxEntries = KSWORD_ARK_MUTATION_AUDIT_RING_CAPACITY, std::uint64_t startSequence = 0) const;
        IoResult setCallbackRules(const void* blobBytes, unsigned long blobSize) const;
        AsyncIoResult waitCallbackEventAsync(
            DriverHandle& handle,
            KSWORD_ARK_CALLBACK_WAIT_REQUEST& request,
            KSWORD_ARK_CALLBACK_EVENT_PACKET& eventPacket,
            OVERLAPPED* overlapped) const;
        CallbackRuntimeResult queryCallbackRuntimeState() const;
        IoResult setMinifilterBypassPids(const std::vector<std::uint32_t>& processIds) const;
        MinifilterBypassPidResult queryMinifilterBypassPids() const;
        IoResult answerCallbackEvent(const KSWORD_ARK_CALLBACK_ANSWER_REQUEST& request) const;
        IoResult cancelAllPendingCallbackDecisions() const;
        CallbackRemoveResult removeExternalCallback(const KSWORD_ARK_REMOVE_EXTERNAL_CALLBACK_REQUEST& request) const;
        CallbackRemoveExResult removeExternalCallbackEx(const KSWORD_ARK_REMOVE_EXTERNAL_CALLBACK_EX_REQUEST& request) const;
        bool supportsExternalCallbackExperimentalUnlink() const;
        CallbackEnumResult enumerateCallbacks(unsigned long flags = KSWORD_ARK_ENUM_CALLBACK_FLAG_INCLUDE_ALL) const;
        KeyboardHotkeyEnumResult enumerateKeyboardHotkeys(std::uint32_t processId = 0, unsigned long flags = KSWORD_ARK_KEYBOARD_ENUM_FLAG_INCLUDE_SYSTEM | KSWORD_ARK_KEYBOARD_ENUM_FLAG_INCLUDE_DIAGNOSTICS, unsigned long maxEntries = 2048UL) const;
        KeyboardHookEnumResult enumerateKeyboardHooks(std::uint32_t processId = 0, unsigned long flags = KSWORD_ARK_KEYBOARD_ENUM_FLAG_INCLUDE_THREAD_HOOKS | KSWORD_ARK_KEYBOARD_ENUM_FLAG_INCLUDE_GLOBAL_HOOKS | KSWORD_ARK_KEYBOARD_ENUM_FLAG_INCLUDE_DIAGNOSTICS, unsigned long maxEntries = 2048UL) const;
        DriverCapabilitiesQueryResult queryDriverCapabilities() const;
        DynDataStatusResult queryDynDataStatus() const;
        DynDataFieldsResult queryDynDataFields() const;
        DynDataCapabilitiesResult queryDynDataCapabilities() const;
        DynDataProfileApplyResult applyDynDataProfile(const DynDataProfileApplyInput& profile) const;
        DynDataProfileApplyExResult applyDynDataProfileEx(const DynDataProfileApplyExInput& profile) const;
        // applyDynDataProfileV4 / queryDynDataV4*：
        // - 输入：PDB extractor 生成的 v4 profile 或只读查询预算；
        // - 处理：封装 DynData v4 IOCTL，验证固定/变长响应头；
        // - 返回：R3 友好结果；unsupported=true 表示旧驱动未注册 v4 IOCTL。
        DynDataV4ApplyResult applyDynDataProfileV4(const DynDataV4ApplyInput& profile) const;
        DynDataV4ModulesResult queryDynDataV4Modules(unsigned long maxRows = KSW_DYN_V4_MAX_MODULES) const;
        DynDataV4CapabilityGroupsResult queryDynDataV4CapabilityGroups(unsigned long maxRows = KSW_DYN_V4_MAX_MODULES * KSW_DYN_V4_MAX_CAPABILITY_GROUPS_PER_MODULE) const;
        DynDataV4MissingItemsResult queryDynDataV4MissingItems(unsigned long maxRows = KSW_DYN_V4_MAX_MISSING_SUMMARY) const;
        DynDataV4ItemsResult queryDynDataV4Items(unsigned long maxRows = KSW_DYN_V4_MAX_MODULES * KSW_DYN_V4_MAX_ITEMS_PER_MODULE) const;
        // queryNetwork*：
        // - 输入：只读网络审计 flags 和最大行数；
        // - 处理：封装 TCP/UDP/WFP/NDIS PDB-backed 审计 IOCTL；
        // - 返回：变长审计行；不执行断连、禁用、detach 或规则修改。
        NetworkEndpointAuditResult queryNetworkTcpEndpoints(unsigned long flags = KSWORD_ARK_NETWORK_AUDIT_QUERY_FLAG_INCLUDE_ALL, unsigned long maxRows = KSWORD_ARK_NETWORK_AUDIT_MAX_REQUESTED_ROWS) const;
        NetworkEndpointAuditResult queryNetworkUdpEndpoints(unsigned long flags = KSWORD_ARK_NETWORK_AUDIT_QUERY_FLAG_INCLUDE_ALL, unsigned long maxRows = KSWORD_ARK_NETWORK_AUDIT_MAX_REQUESTED_ROWS) const;
        NetworkWfpInventoryResult queryNetworkWfpInventory(unsigned long flags = KSWORD_ARK_NETWORK_AUDIT_QUERY_FLAG_INCLUDE_ALL, unsigned long maxRows = KSWORD_ARK_NETWORK_AUDIT_MAX_REQUESTED_ROWS) const;
        NetworkWfpEventResult queryNetworkWfpEvents(std::uint64_t afterSequence, unsigned long maxRows = KSWORD_ARK_NETWORK_WFP_EVENT_DEFAULT_REQUESTED_ROWS) const;
        NetworkNdisChainResult queryNetworkNdisChain(unsigned long flags = KSWORD_ARK_NETWORK_AUDIT_QUERY_FLAG_INCLUDE_ALL, unsigned long maxRows = KSWORD_ARK_NETWORK_AUDIT_MAX_REQUESTED_ROWS) const;
        // File/filter/storage audit wrappers：
        // - 输入：只读 flags、预算和可选卷路径；
        // - 处理：封装 Minifilter/Storage/BitLocker/MountMgr/Filesystem integrity IOCTL；
        // - 返回：协议行数组；BitLocker wrapper 不返回密钥材料。
        MinifilterInventoryResult queryMinifilterInventory(unsigned long flags = KSWORD_ARK_MINIFILTER_INVENTORY_FLAG_INCLUDE_ALL, unsigned long maxRows = 256UL) const;
        StorageVolumeStackAuditResult queryVolumeStackAudit(const std::wstring& volumePath = std::wstring(), unsigned long flags = KSWORD_ARK_STORAGE_AUDIT_FLAG_INCLUDE_DEFAULT, unsigned long maxRows = KSWORD_ARK_STORAGE_DEFAULT_MAX_ROWS, unsigned long maxDepth = KSWORD_ARK_STORAGE_DEFAULT_STACK_DEPTH) const;
        StorageBitlockerFveAuditResult queryBitlockerFveAudit(const std::wstring& volumePath = std::wstring(), unsigned long flags = KSWORD_ARK_STORAGE_AUDIT_FLAG_INCLUDE_DEFAULT, unsigned long maxRows = KSWORD_ARK_STORAGE_DEFAULT_MAX_ROWS, unsigned long maxDepth = KSWORD_ARK_STORAGE_DEFAULT_STACK_DEPTH) const;
        StorageMountMgrMappingAuditResult queryMountMgrMappingAudit(const std::wstring& volumePath = std::wstring(), unsigned long flags = KSWORD_ARK_STORAGE_AUDIT_FLAG_INCLUDE_DEFAULT, unsigned long maxRows = KSWORD_ARK_STORAGE_DEFAULT_MAX_ROWS, unsigned long maxDepth = KSWORD_ARK_STORAGE_DEFAULT_STACK_DEPTH) const;
        StorageFilesystemIntegrityAuditResult queryFilesystemIntegrityAudit(const std::wstring& volumePath = std::wstring(), unsigned long flags = KSWORD_ARK_STORAGE_AUDIT_FLAG_INCLUDE_DEFAULT, unsigned long maxRows = KSWORD_ARK_STORAGE_DEFAULT_MAX_ROWS, unsigned long maxDepth = KSWORD_ARK_STORAGE_DEFAULT_STACK_DEPTH) const;
        // query/read/writeRawDisk：
        // - 输入：物理磁盘号、显式后端、对齐偏移/长度和安全确认标志；
        // - 处理：只在 ArkDriverClient 内封装三层磁盘 IOCTL，不在 Dock 中直接访问控制设备；
        // - 返回：R0 能力、读取字节或安全策略审计后的写入结果。
        RawDiskBackendResult queryRawDiskBackend(
            unsigned long diskNumber,
            unsigned long requestedBackend = 0UL,
            unsigned long flags = 0UL) const;
        RawDiskReadResult readRawDisk(
            unsigned long diskNumber,
            unsigned long backend,
            std::uint64_t offset,
            unsigned long length,
            unsigned long flags = 0UL) const;
        RawDiskWriteResult writeRawDisk(
            unsigned long diskNumber,
            unsigned long backend,
            std::uint64_t offset,
            const std::vector<std::uint8_t>& bytes,
            unsigned long flags) const;
        // Security audit wrappers：
        // - 输入：只读 flags 或行预算；
        // - 处理：封装 Security/CI/VBS/Hyper-V/AppControl IOCTL；
        // - 返回：固定或变长结果，不修改任何安全策略。
        SecurityStatusAuditResult querySecurityStatus(unsigned long flags = 0UL) const;
        DriverTrustViewAuditResult queryDriverTrustView(unsigned long flags = KSWORD_ARK_DRIVER_TRUST_QUERY_FLAG_DEFAULT, unsigned long maxEntries = KSWORD_ARK_SECURITY_AUDIT_DEFAULT_DRIVER_ROWS) const;
        HyperVSummaryAuditResult queryHyperVSummary() const;
        AppControlStatusAuditResult queryAppControlStatus() const;
        // Win32K GUI audit wrappers：
        // - 输入：session/pid/tid 过滤和最大行数；
        // - 处理：封装 win32k PDB 只读快照 IOCTL；
        // - 返回：窗口、GUI 线程、hotkey、hook 诊断行；不安装或移除 hook。
        Win32kProfileStatusResult queryWin32kProfileStatus(unsigned long flags = KSWORD_ARK_WIN32K_QUERY_FLAG_INCLUDE_ALL, unsigned long sessionId = 0UL, unsigned long maxEntries = KSWORD_ARK_WIN32K_DEFAULT_MAX_ENTRIES) const;
        Win32kWindowsResult queryWin32kWindows(unsigned long flags = KSWORD_ARK_WIN32K_QUERY_FLAG_INCLUDE_ALL, unsigned long sessionId = 0UL, unsigned long processId = 0UL, unsigned long threadId = 0UL, unsigned long maxEntries = KSWORD_ARK_WIN32K_DEFAULT_MAX_ENTRIES) const;
        Win32kGuiThreadsResult queryWin32kGuiThreads(unsigned long flags = KSWORD_ARK_WIN32K_QUERY_FLAG_INCLUDE_ALL, unsigned long sessionId = 0UL, unsigned long processId = 0UL, unsigned long threadId = 0UL, unsigned long maxEntries = KSWORD_ARK_WIN32K_DEFAULT_MAX_ENTRIES) const;
        Win32kHotkeysPdbResult queryWin32kHotkeysPdb(unsigned long flags = KSWORD_ARK_WIN32K_QUERY_FLAG_INCLUDE_ALL, unsigned long sessionId = 0UL, unsigned long processId = 0UL, unsigned long threadId = 0UL, unsigned long maxEntries = KSWORD_ARK_WIN32K_DEFAULT_MAX_ENTRIES) const;
        Win32kHooksPdbResult queryWin32kHooksPdb(unsigned long flags = KSWORD_ARK_WIN32K_QUERY_FLAG_INCLUDE_ALL, unsigned long sessionId = 0UL, unsigned long processId = 0UL, unsigned long threadId = 0UL, unsigned long maxEntries = KSWORD_ARK_WIN32K_DEFAULT_MAX_ENTRIES) const;
        Win32kTimersResult queryWin32kTimers(unsigned long flags = KSWORD_ARK_WIN32K_QUERY_FLAG_INCLUDE_ALL, unsigned long sessionId = 0UL, unsigned long processId = 0UL, unsigned long threadId = 0UL, unsigned long maxEntries = KSWORD_ARK_WIN32K_DEFAULT_MAX_ENTRIES) const;
        Win32kEventHooksResult queryWin32kEventHooks(unsigned long flags = KSWORD_ARK_WIN32K_QUERY_FLAG_INCLUDE_ALL, unsigned long sessionId = 0UL, unsigned long processId = 0UL, unsigned long threadId = 0UL, unsigned long maxEntries = KSWORD_ARK_WIN32K_DEFAULT_MAX_ENTRIES) const;
        Win32kWindowRuntimeDetailResult queryWin32kWindowDetail(std::uint64_t hwnd, unsigned long processId = 0UL, unsigned long threadId = 0UL, unsigned long flags = KSWORD_ARK_WIN32K_QUERY_FLAG_INCLUDE_DIAGNOSTICS) const;
        // Device/kernel-object audit wrappers：
        // - 输入：只读 profile、目标名或 CID/IPC 参数；
        // - 处理：封装 DeviceAudit、CID、KernelObjectSummary、IPCSummary IOCTL；
        // - 返回：诊断行或固定摘要，不执行 DKOM/卸载/解绑。
        DeviceAuditResult queryDeviceStackAudit(const std::wstring& targetName = std::wstring(), unsigned long maxRows = KSWORD_ARK_DEVICE_AUDIT_DEFAULT_MAX_ROWS, unsigned long maxAttachedDepth = KSWORD_ARK_DEVICE_AUDIT_DEFAULT_MAX_ATTACHED_DEPTH) const;
        DeviceAuditResult queryInputStackAudit(const std::wstring& targetName = std::wstring(), unsigned long maxRows = KSWORD_ARK_DEVICE_AUDIT_DEFAULT_MAX_ROWS, unsigned long maxAttachedDepth = KSWORD_ARK_DEVICE_AUDIT_DEFAULT_MAX_ATTACHED_DEPTH) const;
        DeviceAuditResult queryUsbTopologyAudit(const std::wstring& targetName = std::wstring(), unsigned long maxRows = KSWORD_ARK_DEVICE_AUDIT_DEFAULT_MAX_ROWS, unsigned long maxAttachedDepth = KSWORD_ARK_DEVICE_AUDIT_DEFAULT_MAX_ATTACHED_DEPTH) const;
        DeviceAuditResult queryGpuDisplayWatchdogAudit(const std::wstring& targetName = std::wstring(), unsigned long maxRows = KSWORD_ARK_DEVICE_AUDIT_DEFAULT_MAX_ROWS, unsigned long maxAttachedDepth = KSWORD_ARK_DEVICE_AUDIT_DEFAULT_MAX_ATTACHED_DEPTH) const;
        // queryPlatformAudit：
        // - 输入：HAL/WDF scope 和最大行数；
        // - 处理：只通过受控 IOCTL 获取结构签名与模块边界验证后的证据；
        // - 返回：未知系统布局显式 unsupported/partial，不尝试裸偏移扫描。
        PlatformAuditResult queryPlatformAudit(unsigned long scopeMask = KSWORD_ARK_PLATFORM_AUDIT_SCOPE_ALL, unsigned long maxRows = KSWORD_ARK_PLATFORM_DEFAULT_MAX_ROWS) const;
        // queryI8042Audit：
        // - 输入：最大行预算；
        // - 处理：通过专用只读 IOCTL 获取精确版本描述符验证后的键鼠端点；
        // - 返回：未知 i8042prt 映像显式 unsupported，不回退到 CallbackEnum。
        I8042AuditResult queryI8042Audit(unsigned long maxRows = KSWORD_ARK_I8042_DEFAULT_MAX_ROWS) const;
        // queryHwidDispatchState / controlHwidDispatch：
        // - 输入：无输入查询或完整 HWID Dispatch 控制包；
        // - 处理：只通过 ArkDriverClient 访问新增 IOCTL，Dock 不直接 DeviceIoControl；
        // - 返回：HwidDispatchResult，保留 R0 原始状态和 unsupported 标记。
        HwidDispatchResult queryHwidDispatchState() const;
        HwidDispatchResult controlHwidDispatch(const KSWORD_ARK_HWID_DISPATCH_CONTROL_REQUEST& request) const;
        CidTableAuditResult enumCidTable(unsigned long flags = KSWORD_ARK_CID_ENUM_FLAG_INCLUDE_ALL, unsigned long maxEntries = 4096UL, unsigned long maxVisitCount = 65536UL, unsigned long startCid = 0UL, unsigned long endCid = 0UL) const;
        KernelObjectSummaryAuditResult queryKernelObjectSummary(unsigned long targetKind, unsigned long cidValue = 0UL, std::uint64_t expectedObjectAddress = 0ULL, unsigned long flags = KSWORD_ARK_OBJECT_SUMMARY_FLAG_INCLUDE_ALL) const;
        IpcSummaryAuditResult queryIpcSummary(unsigned long processId = 0UL, std::uint64_t handleValue = 0ULL, unsigned long flags = KSWORD_ARK_IPC_QUERY_FLAG_INCLUDE_ALL, unsigned long maxEntries = 64UL) const;
    };
}
