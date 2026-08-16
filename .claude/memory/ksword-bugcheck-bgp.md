# 蓝屏 BGP 准备与 BPP 哨兵

## 已确认行为

- Windows 10 19042 的 BGP 私有 `GetBpp` 在驱动加载期尚未调用 `InbvAcquireDisplayOwnership` 时可能返回 `1`，同时分辨率返回 `0×0`。这是未取得显示所有权的延迟探测状态，不能直接判定为不支持。
- 加载期仍需在 `PASSIVE_LEVEL` 完成全部资源准备。当前实现同时生成并解析 24 BPP、32 BPP 的 Logo 与黑色/蓝色 ASCII 字形矩形。
- 崩溃回调中的顺序保持为 `InbvAcquireDisplayOwnership → BgpFwAcquireLock → 重新读取分辨率/BPP → BgpClearScreen → BgpGxDrawRectangle → BgpFwReleaseLock`。
- 取得显示所有权后只接受实际 BPP 为 24 或 32。分辨率、BPP、私有特征或节属性不满足时，在清屏前释放锁并退出，保留 Windows 原蓝屏。
- VMware 的 Windows 10 19042 蓝屏显示模式可能固定回落到 `640×480×32`，即使桌面分辨率更高。面板必须保留 `640×480` 紧凑布局；`1024×768` 只能作为完整布局阈值，不能作为 BGP 可用性的最低门槛。
- `640×480`/`800×600` 紧凑页使用左上角 `240×84` Logo 和双栏正文。正文中间需为 Windows 转储进度文字保留空白横带；内部 BGP 阶段、锁状态和回调位图保存在 SecondaryDumpData，不占用户可见页面。

## 诊断依据

- `C:\Windows\Temp\KswordARK-bgp-preparation.log` 用于判断加载期是否成功 Arm。
- 修复前典型状态为 `state=1 (query-only)`、`preparation_stage=2 (read-screen)`、`0xC00000BB`，即回调已注册但绘制不会启动。
- 修复后应看到 `state=3 (armed)`、`preparation_stage=8 (complete)`、`feature_mask=0x000001FF`。加载期完全隐藏模式时，`screen=0x0x1` 与 `last_probe=0x0x1` 属于预期状态。
- 日志中没有 `last_probe=` 时，目标机仍在使用旧驱动。
- 崩溃阶段数据继续通过 GUID `956d0947-326a-4ba7-92f1-4c8b5a5c712d` 写入 `KbCallbackSecondaryDumpData`。
- 阶段序列结束于 `ScreenAfter` 后的 `Rejected|2`，且快照显示真实屏幕 `640×480×32`、要求 `1024×768`、`ClearStatus=STATUS_PENDING` 时，说明回调与 BGP 获取链路均已执行，未清屏仅由尺寸门槛触发。

## 图像资源

- #174 起 Logo 统一采用 qrc 中的 `KswordHome-En.png`（KSwordDEV 版本），不要改回带 KSwordDEV Team 字样的 `MainLogo.png`；BGP 使用离线缩放为 `240x84` 的 `Generated/MainLogoBitmap.h`，SVGA 由主程序上传同一资源。
- 运行时不读取外部 BMP 文件。BMP 头、像素缓冲和 BGP 矩形均在驱动加载期动态建立。
- 当前目标机的 BGP 32 BPP 矩形路径不按 alpha 混合字形背景；`BGRA=00 00 00 00` 会显示成黑色字符块。字形背景必须与当前实色画布完全一致并保持不透明；#174 深色布局使用 `RGB(5,15,33)`。
- `8x12` 字形紧贴小矩形边缘时，BGP 的边缘采样会把顶部和字符间隔像素污染成噪声点。字形矩形应使用外围 1 像素不透明同底色边框，实际解析尺寸为 `10x14`，绘制时以 `X-1,Y-1` 保持原始字形坐标。

## #174 分区式诊断布局

- `bugcheck_layout.c/.h` 是 BGP 与 VMware SVGA 共用的信息架构：深海军蓝底、蓝色强调、浅色正文、弱化标签和一像素分区边框；渲染器只提供 `DrawText/DrawFrame` 回调。
- #174 信息完整版优先匹配 `1280x720` 或更大画布；`1024x768` 继续使用原完整布局，其余受支持画布走 `640x480` 双栏紧凑版。紧凑版 `Y=228..284`、`1024x768` 版底部状态带保持空白，给 Windows 自己的转储进度文字使用。
- 崩溃页只显示已捕获的 BugCheck 参数、候选模块、CPU/IRQL、回调与转储阶段；没有可靠来源的栈、反汇编、进程名和百分比不得按参考图伪造。
- BGP 的字形、Logo 与每种固定尺寸的横/竖边框矩形都在 `PASSIVE_LEVEL` 解析并保留 backing buffer；崩溃回调只清屏、绘制预生成矩形并格式化到栈上固定缓冲，不分配内存。
- `1280x720` 信息完整版使用 11 个预生成分区框和蓝/浅色/弱化/琥珀四色字形；琥珀色明确表示 `DUMP ONLY` 或 `NOT CAPTURED`。线程/进程、栈展开、指令字节、Windows Blackbox、其他 CPU 状态、事件时间和百分比只展示可用性及分析命令，不在高 IRQL 回调中强行采集。
