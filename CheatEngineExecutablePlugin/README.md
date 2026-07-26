# Cheat Engine KSword 可执行插件

该目录生成一个 `runtime: executable`、`plugin_type: hybrid` 的 KSword 插件。
它同时提供进程详情页入口和顶部“插件”页中的原生 Tab。用户选择进程插件或打开
Cheat Engine Tab 后，启动器会：

1. 通过 `ArkDriverClient` 检查 KSword R0 设备；
2. 设备不可用时要求用户回到 KSword 启用 R0 并加载驱动；
3. 重试仍失败时明确显示“R0 模式未启用，请小心使用”的风险通知；
4. 启动插件内置 Cheat Engine 7.6；
5. 由 CE `autorun` 调用官方 `loadPlugin()` 自动加载对应架构的桥接 DLL；
6. 等待桥接初始化回执；进程入口会打开 KSword 传入的目标 PID；
7. Tab 入口创建归属于插件进程的 `WS_CHILD` 容器，经宿主校验后识别 Lazarus 的
   `TCustomForm` 主窗体，移除其顶层窗口边框并铺满该容器；宿主退出或 Tab 关闭时
   同步关闭插件会话。

桥接覆盖 CE 的进程打开、虚拟内存查询、内存读取和内存写入函数槽。Tab 模式不
预选进程，用户在嵌入的 CE 界面中选择目标进程后，同样经过这些桥接函数槽。CE 调试器、
线程控制、远程分配等 KSword 驱动协议尚未提供的能力不在此次重定向范围内。

构建并从本机已安装 CE 生成插件目录：

```powershell
& tools\package_cheat_engine_plugin.ps1
```

输出目录为 `plugin\cheat-engine\`，其中包含启动器、x64/Win32 两个桥接 DLL
和完整的用户态 CE 载荷。CE 自带 DBK/DBVM 内核载荷不会进入插件包。
