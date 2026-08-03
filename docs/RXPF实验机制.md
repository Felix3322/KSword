# RXPF 实验机制：RX 页面改写与 `#PF` 执行仿真

## 1. 范围、结论与警告

本实现是仅供可回滚、测试签名 Windows x64 虚拟机使用的研究型 PoC。它不能、也不声称能在启用 PatchGuard、VBS、HVCI、Hyper-V、CET 或其他内核完整性机制的生产环境中稳定工作。修改 IDTR/IDT 可能被 PatchGuard 视为内核篡改；内部内存管理 ABI 的任何误判都可能立即触发 bugcheck。

默认构建只允许两类驱动自有测试页：

1. 由驱动通过公开 MDL API 分配的独立物理页；
2. 驱动映像中独立、页对齐的 `.rxpftst` 测试节。

`ntoskrnl` 和第三方驱动映像目标没有在协议 v1 中实现。`KSW_RXPF_ENABLE_EXTERNAL_IMAGE_TARGETS` 默认为 `0`；即使显式改为 `1`，当前代码也仍返回 `STATUS_NOT_SUPPORTED`，直到另行实现精确模块白名单、逐 build ABI 配置和对应恢复策略。不能借此开关处理任意内核地址。

一个必须说明的实证差异是：在当前唯一验证的内核上，`MmChangeImageProtection` 的操作码 `2` 将原映像映射变为只读/NX，而不是直接将原映射变为 RW。实现调用操作码 `2` 后，再基于同一份已锁定 MDL 建立单独的 RW/NX 系统映射别名；指令模拟器从该别名读取字节，CPU 对原映像地址取指时产生 `#PF`。实现从不使用操作码 `1` 尝试恢复 RX。

## 2. 文件与模块

新增文件：

- `shared/driver/KswordArkRxPfIoctl.h`：协议 v1、IOCTL、状态、统计和事件结构。
- `KswordARKDriver/src/features/rxpf/image_protection_manager.c/.h`：精确 build 解析、MDL、测试页、权限变更和资源释放。
- `KswordARKDriver/src/features/rxpf/page_state_table.c/.h`：固定容量、开放寻址页面表。
- `KswordARKDriver/src/features/rxpf/page_fault_manager.c/.h`：per-CPU shadow IDT、安装/回滚/恢复及 `#PF` 分类分派。
- `KswordARKDriver/src/features/rxpf/page_fault_stub.asm`：vector 14 的 x64 汇编入口和测试页调用桩。
- `KswordARKDriver/src/features/rxpf/x64_instruction_emulator.c/.h`：无分配白名单解码和单指令模拟。
- `KswordARKDriver/src/features/rxpf/x64_instruction_emulator_tests.c`：加载时解码器单元测试。
- `KswordARKDriver/src/features/rxpf/rxpf_diagnostics.c/.h`：预分配 per-CPU 环形缓冲区与原子统计。
- `KswordARKDriver/src/features/rxpf/rxpf_self_test.c/.h`：逐在线 CPU 并发执行测试。
- `KswordARKDriver/src/features/rxpf/rxpf_runtime.c/.h`：页面生命周期、分阶段门控及卸载顺序。
- `KswordARKDriver/src/features/rxpf/rxpf_ioctl.c`：WDF IOCTL 适配和安全策略检查。
- `tools/rxpf_vm_test/rxpf_vm_test.cpp`：仅供测试签名 VM 使用的用户态测试客户端。

集成修改：

- `KswordARKDriver/include/ark/ark_ioctl.h`
- `KswordARKDriver/src/dispatch/ioctl_registry.c`
- `KswordARKDriver/src/framework/driver_entry.c`
- `KswordARKDriver/KswordARKDriver.vcxproj`
- `KswordARKDriver/KswordARKDriver.vcxproj.filters`

RXPF 协议只在 `shared/driver/` 定义；业务处理器位于 feature 模块，`ioctl_registry.c` 只注册 handler，符合仓库 Phase -1 边界。

## 3. `MmChangeImageProtection` 的精确 build 验证

### 3.1 唯一支持配置

| 字段 | 已验证值 |
|---|---|
| 运行时 NT build | `26220` |
| `ntoskrnl` 文件版本 | `10.0.26100.8925` |
| Machine | AMD64 (`0x8664`) |
| PE TimeDateStamp | `0xB292FCA9` |
| PE SizeOfImage | `0x01450000` |
| PE CheckSum | `0x00C7D4D4` |
| CodeView/PDB | `ntkrnlmp.pdb` |
| PDB GUID | `{3E5A9A8B-6B78-281F-3BE2-150110325215}` |
| PDB Age | `1` |
| 函数 RVA | `0x00A3B300` |
| 下一个公开符号 RVA | `0x00A3B58C` |

匹配 PDB 只提供该函数的公开符号，没有可供类型系统查询的函数类型记录。因此，“符号名和 RVA”来自匹配 PDB，“参数数量、用途和返回类型”来自对上述精确映像范围的 x64 反汇编与数据流验证，而不是从缺失的 PDB 类型中猜测。

当前 build 描述表只有这一项。任一 build、PE 标识、唯一 RSDS GUID/Age、入口节属性或入口签名不匹配时，函数指针不发布，相关映像页操作返回 `STATUS_NOT_SUPPORTED`。

### 3.2 已验证原型和调用约定

精确映像上的实际调用接口为：

```c
typedef NTSTATUS
(NTAPI* KSW_RXPF_MM_CHANGE_IMAGE_PROTECTION)(
    PMDL Mdl,             // RCX
    PVOID BaseAddress,    // RDX
    ULONG NumberOfBytes,  // R8D；实现拒绝非零高 32 位
    ULONG Operation       // R9D；只接受 1 或 2
    );
```

x64 Windows 调用约定使用 `RCX/RDX/R8/R9` 传递四个参数，`EAX` 返回 `NTSTATUS`。反汇编观察到：

- `R9D - 1` 必须小于等于 `1`，因此只接受操作码 `1` 或 `2`；
- `R8` 会与其低 32 位零扩展值比较，字节数必须能无损表示为 `ULONG`；
- `MdlFlags & 7` 必须精确等于 `2`，即低三位只能是 `MDL_PAGES_LOCKED`，不能同时带 `MDL_MAPPED_TO_SYSTEM_VA` 或 `MDL_SOURCE_IS_NONPAGED_POOL`；
- `ByteOffset` 必须为 `0`；
- `ByteCount` 必须按页对齐；
- `StartVa`、PFN 数组、映像区间和内部映射状态随后会继续参与检查；
- 操作码 `1` 的控制流对应 RX/内部保护值 `3`；操作码 `2` 对应原映像映射只读/NX/内部保护值 `1`。

精确反汇编可见的失败返回包括：

- `0xC000000D` / `STATUS_INVALID_PARAMETER`
- `0xC0000225` / `STATUS_NOT_FOUND`
- `0xC0000043` / `STATUS_SHARING_VIOLATION`
- `0xC0000018` / `STATUS_CONFLICTING_ADDRESSES`
- `0xC0000045` / `STATUS_INVALID_PAGE_PROTECTION`

这些返回码不意味着任意坏指针或伪造 MDL 都会安全返回：函数会解引用 MDL 和映像管理结构，结构错误仍可能在返回前触发 bugcheck。

### 3.3 入口签名和运行时校验

入口前 64 字节：

```text
48 8B C4 48 89 58 08 48 89 68 10 48 89 70 18 44
89 48 20 57 41 54 41 55 41 56 41 57 48 83 EC 30
83 60 C8 00 49 8B D8 41 8D 41 FF 4C 8B E2 48 8B
F9 83 F8 01 0F 87 41 02 00 00 44 8B EB 49 3B DD
```

掩码为 64 个 `FF`，即逐字节精确匹配，不做宽泛扫描。运行时顺序为：

1. `RtlGetVersion` 匹配 build；
2. 从已加载的 NT 内核模块读取 machine、timestamp、SizeOfImage 和 checksum；
3. 要求映像中恰好一个合法 RSDS 记录，并匹配 GUID/Age；
4. `KernelBase + RVA` 必须位于可执行、非 discardable 的 PE 节；
5. 64 字节签名完整匹配；
6. 最后才发布内部函数指针。

没有通用特征码回退，也不调用导出解析器猜测同名地址。

## 4. MDL 与页面状态

### 4.1 分阶段测试页

第一阶段“allocated test page”完全使用公开 WDK API：

1. `MmAllocatePagesForMdlEx` 分配一页；
2. 建立临时 RW/NX 映射写入种子代码；
3. 建立只读映射并用 `MmProtectMdlSystemAddress(..., PAGE_EXECUTE_READ)` 得到初始 RX；
4. 变更时用 `MmProtectMdlSystemAddress(..., PAGE_READWRITE)` 得到 RW/NX；
5. 成功完成三指令、多 CPU 的实际 `#PF` 自测后，才发布 `ALLOCATED_TEST_PASSED` 门控。

第二阶段“self-image test page”只接受 `.rxpftst` 页本身，调用者地址必须为 `0` 或与该页精确相等：

1. 用 `RtlPcToFileHeader` 确认归属当前驱动；
2. `IoAllocateMdl` 后通过 `MmProbeAndLockPages` 产生精确的 `MDL_PAGES_LOCKED` 状态；
3. 不对映像页错误调用 `MmBuildMdlForNonPagedPool`；
4. 复核 low flags、ByteOffset、ByteCount、VirtualAddress 和 PFN；
5. 仅在精确 NT build 门控通过时调用内部操作码 `2`；
6. 原映像地址保持只读/NX，另建 RW/NX 别名用于改写和解码。

两条路径都只处理一页，页基址规范化并要求页对齐；写入长度最多 64 字节，使用 64 位加法检查页内范围和溢出。默认没有任意地址跨页处理。

### 4.2 页面记录

每条记录包含：状态、是否启用模拟、target kind、flags、generation、引用计数、最后状态/失败原因、原始/当前/别名保护、RecordId、PageBase、WritableAlias、PFN、所属映像基址、MDL、原映射、可选整页备份、整页当前内容镜像、所有权标志、最近写入和 fault/emulated/unsupported 计数。

异常路径可见的表、CPU 行和全局状态位于驱动常驻、不可分页的可写数据中；变长数组、事件环、shadow IDT、备份和内容镜像均在初始化/控制路径中通过 NonPagedPoolNx 兼容分配器预分配。安装 vector 14 前不会再为异常路径动态初始化或分配对象。

内部函数无法可靠执行 RW/NX 到 RX 的反向恢复，因此状态转换是单向的。注销 allocated 页会解除映射并释放页；注销 self-image 页会解除 RW/NX 别名、解锁并释放 MDL，但 `.rxpftst` 原映像页保持只读/NX，直至驱动映像卸载。

## 5. 页面 Hash Table 和并发模型

页面表为 64 槽、二次容量掩码的开放寻址表，key 是页对齐 `PageBase`，记录另存 PFN 并在每次受管 fault 时用 `MmGetPhysicalAddress` 复核。

- 普通控制路径用 `EX_PUSH_LOCK` 独占串行化新增、写入、状态修改和删除。
- `#PF` 查找遍历最多 64 个槽，不分配、不等待、不持普通 mutex，也不调用日志格式化或文件 I/O。
- 插入时最后发布 `PageBase`；删除时先清 `EmulationEnabled`、标记 `TERMINATING`，最终将 key 发布为 tombstone。
- fault 处理器在读取管理器/表之前先增加全局 `ActiveHandlers`，命中记录后再增加记录 `ReferenceCount`。
- 删除先取消发布，然后等待全局 read-side grace period 为零，才释放 alias、MDL、备份和记录内容。
- 卸载若无法恢复全部 IDTR 或无法等到处理器退出，不会释放异常仍可到达的代码和数据；它宁可阻塞卸载。

这避免了记录已释放而其他 CPU 仍在 `#PF` 路径中读取的 use-after-free。

## 6. per-CPU shadow IDT

安装过程：

1. 在 PASSIVE_LEVEL 获取当前在线处理器数；
2. 对每个全局处理器索引固定线程 affinity，在该 CPU 上执行 `SIDT`；
3. 为该 CPU 分配 4096 字节 shadow IDT，并按实际 IDTR limit 复制完整表；
4. 保存原 IDTR、vector 14 描述符和原 handler；
5. 要求原门为 present、IST 0、64 位 interrupt gate (`type=0xE`)、selector 非零、reserved 为零且目标为规范内核地址；trap gate 或非零 IST 直接 `STATUS_NOT_SUPPORTED`；
6. 仅替换复制后描述符的三个 offset 字段，selector、IST、type、DPL 和 present 位保持原值；
7. `KeIpiGenericCall` 在所有在线 CPU 上验证原 IDTR 未变化，执行 `LIDT`，再用 `SIDT` 回读验证；
8. 任一 CPU 失败，立即对全部已安装 CPU 执行恢复 IPI，并确认各行已恢复及没有活动 handler；
9. 关闭最后一个页面或卸载时，在所有在线 CPU 上恢复各自保存的原 IDTR并回读验证。

注册了处理器变化通知。安装、捕获或已安装期间的 `KeProcessorAddStartNotify` 被明确以 `STATUS_DEVICE_BUSY` 拒绝；捕获窗口末尾还会复核在线数量。动态 CPU 移除没有实现为支持场景：若它导致某个已安装行无法验证恢复，卸载会安全阻塞而不释放存储。

只接受 interrupt gate 是生命周期设计的一部分：进入 stub 后 IF 保持清零，恢复 IPI 不会在处理器加入全局 `ActiveHandlers` 之前抢占该处理器。

## 7. x64 `#PF` 栈与转交

同 CPL 的内核 `#PF` 在自定义入口最初具有：

| 相对入口 RSP | 内容 |
|---:|---|
| `+0x00` | Page Fault error code |
| `+0x08` | RIP |
| `+0x10` | CS |
| `+0x18` | RFLAGS |

stub 依次保存全部通用寄存器，C 可见帧相对保存后的 `RSP` 为：

| 偏移 | 字段 |
|---:|---|
| `0x00..0x70` | R15..RAX |
| `0x78` | ErrorCode |
| `0x80` | RIP |
| `0x88` | CS |
| `0x90` | RFLAGS |
| `0x98` | HardwareRsp（仅 CPL 变化时由 CPU 压入；同 CPL 时该地址就是逻辑入口 RSP） |
| `0xA0` | HardwareSs（同上） |

`C_ASSERT` 固定该结构大小为 168 字节。汇编另在 `r12-0x130` 建立独立 168 字节 resume frame，避免 `PUSH/CALL` 对逻辑程序栈的写入覆盖正在修改的异常帧；`XMM0..XMM5` 保存在 `r12-0x80..r12-0x21`，二者不重叠。

调用 C 分派器前，stub 清 DF、将栈对齐到 16 字节并预留 shadow space。只对来自 CPL3 的异常在进入 C 前执行 `SWAPGS`，转交前恢复原 GS；不会无条件 `SWAPGS`。

未处理路径恢复所有寄存器和原 DF，令 RSP 精确指向未改写的硬件 error code，再 `JMP` 原 vector 14 handler。这里没有额外 `IRETQ`，也没有弹掉 error code。

处理成功路径在模拟后的逻辑 `RSP-24` 建立 RIP/CS/RFLAGS 三项同 CPL IRET frame，恢复模拟后的 GPR，执行一次 `IRETQ`。因此 `PUSH/CALL/POP/RET` 的栈效果与异常返回帧互不覆盖。当前只允许最多向下移动 8 字节的单条栈操作；直接以 SP/ESP/RSP/SPL 为普通 MOV/LEA/ALU 目的寄存器，以及 `POP SP/RSP`，均返回 Unsupported。

## 8. Page Fault 分类

只有同时满足下列条件才进入模拟：

- `CS.RPL == 0`；
- `CR2 == faulting RIP`；
- `CR2` 页在已发布且启用的页面表中；
- error code：`P=1`、`W/R=0`、`U/S=0`、`RSVD=0`、`I/D=1`；
- error code 的 bit 5 及更高位全为零；
- 当前 IRQL 不高于 APC_LEVEL；
- 记录状态为 RW/NX、PFN 仍匹配且 RW/NX alias 有效；
- per-CPU handler depth 恰好为 1。

典型值是 `0x11`。用户态 fault、not-present fault、写 fault、保留位 fault、非取指 fault、递归 fault、未管理页和未知扩展位均立即转交 Windows 原 handler。代码不会为了避免蓝屏而吞掉异常。

## 9. 指令白名单与失败路径

当前解码/模拟白名单：

- `NOP`
- `MOV`：`B0..BF`、`88/89/8A/8B` 的寄存器形式、`C6/C7 /0` 的寄存器形式
- `LEA`：ModRM/SIB/displacement/RIP-relative 地址计算，不解引用结果
- `PUSH`：寄存器、`68`、`6A`
- `POP`：寄存器，SP/RSP 除外
- `ADD`、`SUB`、`XOR`、`AND`、`OR`、`CMP`、`TEST`：寄存器形式及受支持的 immediate group
- `JMP rel8/rel32`
- 全部短/近 `Jcc`
- `CALL rel32`
- `RET`、`RET imm16`

实现支持单个合法 REX、`66h` 操作数前缀、8/16/32/64 位标量、传统高 8 位寄存器、32 位写零扩展、ModRM、SIB、displacement、immediate、RIP-relative LEA、算术标志和规范控制流目标检查。`PUSH/POP/CALL/RET` 只访问 `IoGetStackLimits` 验证过的当前内核栈。

普通内存操作数、LOCK、REP、字符串、segment/address-size prefix、SIMD、AVX、x87、系统/特权指令、跨页或截断指令均不支持。失败时模拟器不增加 RIP、不按 NOP 处理、不猜结果；分派器恢复原帧、在预分配环中记录原因，然后把原始 `#PF` 无损交给 Windows。对于 managed NX 页，这通常保留 Windows 原有失败/bugcheck 行为。

## 10. 诊断与 IOCTL

每个最大逻辑处理器预分配 128 条事件槽。生产者只做原子递增、`RDTSC`、定长字段写入和 sequence 发布；没有分配、阻塞锁、文件系统、字符串格式化或逐 fault `DbgPrint`。控制路径通过 drain IOCTL 合并并导出最多 64 行。

协议版本为 1，功能号为 `0x900..0x909`：

| IOCTL | 功能 |
|---|---|
| `QUERY_SUPPORT` | build/PE/RSDS/签名/ABI/IDT/自测门控 |
| `REGISTER_PAGE` | 注册 allocated 或 self-image 测试页 |
| `CHANGE_PAGE` | 单向切换至持久 RW/NX 状态 |
| `QUERY_PAGE` | 查询页面、PFN、保护、引用和计数 |
| `WRITE_PAGE` | 通过别名写入最多 64 字节 |
| `SET_EMULATION` | 为页面启停模拟，并安装/恢复 shadow IDT |
| `QUERY_STATS` | 汇总 fault/managed/emulated/chained/recursive/unsupported |
| `DRAIN_EVENTS` | 导出失败和成功事件 |
| `UNREGISTER_PAGE` | 终止、等待 grace period 并释放可恢复资源 |
| `RUN_SELF_TEST` | 在每个在线 CPU 上执行三条受管指令 |

全部 IOCTL 使用 `METHOD_BUFFERED | FILE_WRITE_ACCESS`，并再次检查请求写权限。控制设备 ACL 仅允许 SYSTEM 全权和 Administrators 读写执行；World/Restricted 只有读权限，无法发出这些写访问 IOCTL。每个请求还要求精确 version/size、UI confirmation flag 和 `0x46505852` token；改变机器状态的请求进入仓库统一 `KERNEL_PATCH` safety policy。

## 11. 停止和卸载顺序

卸载实现顺序为：

1. 清 `Accepting`，页面表永久停止插入；
2. 将所有发布记录取消模拟并标记 `TERMINATING`；
3. 循环恢复所有 CPU 的原 IDTR；恢复不成功绝不继续释放；
4. 循环等待全局活动 handler 为零；
5. 释放 alias、解锁/释放 MDL 和 allocated 页；
6. 清 tombstone/记录和备份；
7. 注销处理器变化通知，释放 shadow IDT、CPU 行和事件环；
8. 清除内部函数指针与 build 状态。

若 IDT 仍可能到达驱动代码，卸载会阻塞而不是制造 use-after-free。

## 12. 构建

在仓库根目录的 x64 Native Tools/PowerShell 中：

```powershell
$msbuild = 'C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\MSBuild\Current\Bin\MSBuild.exe'

& $msbuild 'KswordARKDriver\KswordARKDriver.vcxproj' `
  /t:Rebuild `
  /p:Configuration=Release `
  /p:Platform=x64 `
  /p:OutDir=dist\rxpf-driver-rebuild\ `
  /p:IntDir=dist\rxpf-driver-rebuild\obj\ `
  /p:ApiValidator_Arch=x64 `
  /p:ApiExtractor_Arch=x64 `
  /p:EnableInf2cat=false `
  /p:KswordArkSkipAutoVariantSign=true `
  /p:KswordArkSkipAutoTestSign=true `
  /m:1 /v:minimal
```

本次隔离重编译已完成全部 C/MASM 编译、链接和 Universal ApiValidator，输出 `KswordARKDriver/dist/rxpf-driver-rebuild/KswordARK.sys`。命令显式跳过 Inf2Cat 和签名，所以这证明的是编译/链接/API 合规，不是已签名或可部署。

测试客户端：

```powershell
cmd.exe /d /s /c 'call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\Common7\Tools\VsDevCmd.bat" -arch=x64 -host_arch=x64 >nul && cl.exe /nologo /std:c++20 /EHsc /W4 /WX /permissive- /DUNICODE /D_UNICODE "tools\rxpf_vm_test\rxpf_vm_test.cpp" /Fe:"dist\rxpf-vm-test\rxpf_vm_test.exe" /Fo:"dist\rxpf-vm-test\rxpf_vm_test.obj"'
```

该客户端也已在 `/W4 /WX` 下编译通过。

## 13. 测试签名 VM 步骤

只在已有快照、允许丢弃的 VM 中操作。先确认 Secure Boot、VBS、HVCI/Memory Integrity、Hyper-V/CET 等状态；它们可能阻止加载、改变 IDT/页表行为或触发完整性检查。启用测试签名通常需要重启：

```powershell
bcdedit /set testsigning on
shutdown /r /t 0
```

将经过测试签名的 `KswordARK.sys` 放入 VM 的实验目录。若该 VM 已有仓库正式安装流程，优先复用该流程；临时 demand-start 实验可由管理员执行：

```powershell
sc.exe create KswordARK type= kernel start= demand binPath= C:\lab\KswordARK.sys
sc.exe start KswordARK
```

先运行不调用内部函数的 allocated-page 阶段：

```powershell
C:\lab\rxpf_vm_test.exe
```

只有 `QUERY_SUPPORT` 同时返回 `BUILD_MATCH | ABI_VERIFIED | SELF_IMAGE_TEST_PAGE`，且 allocated 阶段已成功，才运行精确映像页阶段：

```powershell
C:\lab\rxpf_vm_test.exe --self-image
```

客户端依次测试注册、RX 到 RW/NX、页内写入、IDT 安装/恢复、用户 `PAGE_NOACCESS` fault 到 Windows SEH 的转交、逐 CPU 三指令执行、统计/事件读取和注销。self-test 代码为 `MOV RAX,12345678h; ADD RAX,1; RET`，每个 worker 必须观察到 3 次 fault，返回 `0x12345679`。

完成后先确认最后一个页面已注销、统计中 `enabledPages=0`、`idtInstalled=0`，再停止驱动：

```powershell
sc.exe stop KswordARK
sc.exe delete KswordARK
```

当前开发主机没有执行驱动动态加载或上述 live self-test；这些步骤必须在目标精确 build 的测试 VM 中完成。

## 14. 十三项测试覆盖

| # | 要求 | 实现/验证入口 | 当前状态 |
|---:|---|---|---|
| 1 | 自有页建立 MDL | allocated 注册路径 | 已实现；编译通过，待 VM 动态运行 |
| 2 | 内部调用成功或明确失败 | support gate + self-image change | 已实现 fail-closed；待精确 build VM |
| 3 | RX 变为可写/NX | allocated 原映射 RW/NX；self-image 原映射 R/NX + RW/NX alias | 已实现；响应与 `!pte` 验证 |
| 4 | 写简单指令 | `WRITE_PAGE` + VM 客户端 | 已实现 |
| 5 | 取指产生 `#PF` | `RUN_SELF_TEST` | 已实现，待 VM |
| 6 | CR2/RIP/error 正确 | 事件环 + WinDbg 断点 | 已实现采集，待 VM |
| 7 | 更新寄存器/RIP | 返回值和 3-fault 计数 | 已实现，待 VM |
| 8 | 连续多指令 | MOV/ADD/RET，每 CPU 三次 fault | 已实现，待 VM |
| 9 | 普通/空指针/用户 fault 转交 | 分类器；客户端自动测试用户 `PAGE_NOACCESS`；内核普通/NULL 用 WinDbg 人工观察 | 用户自动用例已实现；破坏性内核用例不在主机自动执行 |
| 10 | Unsupported 不跳过 | 加载时 LOCK/重复前缀/RSP 目的/POP RSP 单测，失败保持 RIP；真实 fault 可在快照 VM 中做预期 bugcheck 用例 | 静态单测已实现；真实失败路径待 VM |
| 11 | 多 CPU Hash Table | 每在线 CPU 一个固定 affinity 系统线程并发执行 | 已实现，待多核 VM |
| 12 | 安装失败完整回滚 | 每 CPU LastStatus 检查、回滚 IPI、IDTR 回读与 handler grace period | 路径已实现；故障注入需 WinDbg/专用 VM |
| 13 | 卸载后所有 IDT 恢复 | unload 强制恢复并回读；`!idt 0e` 前后比较 | 已实现；需 VM+WinDbg 完成验收 |

“待 VM”不等于已通过运行测试。本次完成的当前机器证据是完整 Release x64 C/MASM 编译、链接、Universal ApiValidator 和 `/W4 /WX` 客户端编译。

## 15. WinDbg 验证

### 15.1 build 与内部函数

```text
vertarget
lmvm nt
x nt!MmChangeImageProtection
u nt!MmChangeImageProtection L80
```

预期：build 为 26220，`lmvm nt` 的 timestamp/size/checksum/RSDS 与第 3 节一致，符号地址减 `nt` 基址为 `0xA3B300`，前 64 字节与签名一致。任何字段不同都应看到 `QUERY_SUPPORT` 报告非 supported，self-image 操作返回 `STATUS_NOT_SUPPORTED`。

### 15.2 驱动符号、测试节和页面

```text
.reload /f KswordARK.sys
x KswordARK!*KswRxpf*
x KswordARK!g_KswRxpfSelfImageTestPage
dt KswordARK!_KSW_RXPF_PAGE_RECORD
!pte <PageBase>
!pte <WritableAlias>
```

预期：allocated 变更后 PageBase/WritableAlias 为同一 RW/NX 映射；self-image 变更后原 PageBase 为只读/NX，WritableAlias 为同 PFN 的 RW/NX 映射。两者都不应恢复为 RX。

### 15.3 per-CPU IDT 前、中、后对比

在安装前、客户端停在已启用阶段、恢复后分别对每个 CPU 执行：

```text
~0s
!idt 0e
~1s
!idt 0e
```

按 VM CPU 数继续。安装期间 vector 14 offset 应指向 `KswordARK!KswRxpfPageFaultStub`，其他 gate 属性不变；恢复和驱动卸载后，每个 CPU 都应回到各自最初记录的 Windows handler。

### 15.4 fault 分派

```text
bp KswordARK!KswRxpfPageFaultDispatch
g
r cr2
dq @rcx+78 L4
```

函数入口 `RCX` 指向保存帧；`@rcx+0x78` 起依次是 ErrorCode、RIP、CS、RFLAGS。典型受管 NX fault 的 ErrorCode 为 `0x11`，`CR2 == RIP`，CS 为内核代码段。单步返回后，事件行的 `newRip` 应前进到下一条或按控制流改变。

普通用户 `PAGE_NOACCESS` 用例命中断点后应直接返回 chain action；用户态看到 `EXCEPTION_ACCESS_VIOLATION`，而不是被模拟器吞掉。

### 15.5 回滚故障注入

仅在快照 VM 中，在 `KswRxpfInstallIpi` 返回后、总体验证前，用 WinDbg 将某个 CPU 行的 `LastStatus` 改成失败值，继续执行。预期进入 rollback：所有 `Installed` 行归零，各 CPU `!idt 0e` 恢复原 handler，shadow 存储只有在回读和 grace period 成功后才释放。不要在无法回滚的实体机执行此测试。

## 16. 已知风险与未完成项

- `MmChangeImageProtection` 是未公开、版本相关的内部接口；当前只有一个精确 build 配置。
- 匹配 PDB没有函数类型，原型是精确反汇编验证结果，不是微软公开 ABI 合同。
- 没有实现 ntoskrnl/第三方驱动任意页目标，也没有宽泛特征码扫描。
- 没有可靠的 RW/NX 到 RX 恢复；self-image 测试页在驱动卸载前保持 NX。
- 指令模拟器不是完整 x86-64 CPU；普通内存操作数、SIMD、AVX、浮点、系统指令等均不支持。
- 每条指令一次 `#PF`，性能极差，只适合短小实验序列。
- per-CPU IDT 只支持当前观察到的 IST0 interrupt gate；trap gate、非零 IST 和动态 CPU 移除不是支持场景。
- PatchGuard 可能检测 IDT 替换；VBS/HVCI/Hyper-V/CET 可能改变或阻止行为。
- 真实 Unsupported fault 通常会继续进入 Windows 的原失败路径，可能导致预期 bugcheck；实现不会篡改 RIP 来伪造成功。
- 当前只完成了构建级验证；所有 IDT、`#PF`、内部函数和卸载验收仍必须在可回滚目标 VM 上完成。
