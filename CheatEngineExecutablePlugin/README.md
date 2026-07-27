# Cheat Engine KSword 可执行插件

该目录生成一个 `runtime: executable` 的 KSword Hybrid 插件。插件只做三件事：

1. 可从进程菜单启动独立的 Cheat Engine 7.6 窗口；
2. 可在插件页创建最小原生子窗口，并把 CE 主窗口一次性平铺到该 TAB；
3. 通过 CE `autorun` 读取 KSword 主题色，并加载 KSword 桥接 DLL，将进程打开、
   虚拟内存查询、内存读取和内存写入转到 KSword 驱动。

TAB 模式只创建协议要求的直接 `WS_CHILD` 容器，对 CE 主窗口执行一次
`SetParent` 和尺寸同步；不复制菜单、不替换按钮、不改写 CE 事件，也不周期性重新
挂接窗口。独立进程模式保持 CE 原生窗口层级。

启动流程：

1. 通过 `ArkDriverClient` 检查 KSword R0 设备；
2. 设备不可用时要求用户回到 KSword 启用 R0 并加载驱动；
3. 重试仍失败时明确显示“R0 模式未启用，请小心使用”的风险通知；
4. 启动插件内置 Cheat Engine；
5. `00_ksword_theme.lua` 只注入 KSword 主题颜色、字体和窗口标题；
6. `10_ksword_bridge.lua` 加载对应架构的桥接 DLL，在 CE 消息循环空闲后打开
   KSword 传入的 PID；
7. 桥接 DLL 只给 CE 保留查询/同步进程句柄，内存查询、读写复用一个持久的
   KSword 驱动设备句柄。

CE 调试器、线程控制、远程分配等 KSword 驱动协议尚未提供的能力不在此次重定向
范围内。

构建并从本机已安装 CE 生成插件目录：

```powershell
& tools\package_cheat_engine_plugin.ps1
```

输出目录为 `plugin\cheat-engine\`，其中包含启动器、x64/Win32 两个桥接 DLL
和完整的用户态 CE 载荷。CE 自带 DBK/DBVM 内核载荷不会进入插件包。
