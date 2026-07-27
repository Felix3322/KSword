# Cheat Engine KSword 可执行插件

该目录生成一个 `runtime: executable` 的 KSword 进程类插件。插件只做两件事：

1. 启动独立的 Cheat Engine 7.6 窗口，并通过 CE `autorun` 读取 KSword 主题色；
2. 加载 KSword 桥接 DLL，将进程打开、虚拟内存查询、内存读取和内存写入转到
   KSword 驱动。

插件不再提供 Tab 模式，不嵌入、吸附、裁剪或改写 CE 窗口，也不替换菜单、按钮和
事件。CE 原生标题栏、菜单栏、窗口层级及交互行为保持不变。

启动流程：

1. 通过 `ArkDriverClient` 检查 KSword R0 设备；
2. 设备不可用时要求用户回到 KSword 启用 R0 并加载驱动；
3. 重试仍失败时明确显示“R0 模式未启用，请小心使用”的风险通知；
4. 启动插件内置 Cheat Engine；
5. `00_ksword_theme.lua` 只注入 KSword 主题颜色和字体；
6. `10_ksword_bridge.lua` 加载对应架构的桥接 DLL并打开 KSword 传入的 PID。

CE 调试器、线程控制、远程分配等 KSword 驱动协议尚未提供的能力不在此次重定向
范围内。

构建并从本机已安装 CE 生成插件目录：

```powershell
& tools\package_cheat_engine_plugin.ps1
```

输出目录为 `plugin\cheat-engine\`，其中包含启动器、x64/Win32 两个桥接 DLL
和完整的用户态 CE 载荷。CE 自带 DBK/DBVM 内核载荷不会进入插件包。
