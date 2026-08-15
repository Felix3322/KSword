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

- Logo 源自 qrc 中的 `MainLogo.png`，离线转换为 `Generated/MainLogoBitmap.h` 的内嵌 BGRA 数据。
- 运行时不读取外部 BMP 文件。BMP 头、像素缓冲和 BGP 矩形均在驱动加载期动态建立。
- 当前目标机的 BGP 32 BPP 矩形路径不按 alpha 混合字形背景；`BGRA=00 00 00 00` 会显示成黑色字符块。24/32 BPP 字形背景都应使用不透明白色，32 BPP 即 `BGRA=FF FF FF FF`。
- `8x12` 字形紧贴小矩形边缘时，BGP 的边缘采样会把顶部和字符间隔像素污染成噪声点。字形矩形应使用外围 1 像素不透明白边，实际解析尺寸为 `10x14`，绘制时以 `X-1,Y-1` 保持原始字形坐标。
