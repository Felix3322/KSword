# KSword Cheat Engine Driver Bridge

这是一个 Cheat Engine SDK v6 原生 DLL 插件。启用后，Cheat Engine 的以下访问会切换到 KSword 驱动：

- `OpenProcess`：正常打开失败时创建可关闭的代理句柄并记录 PID。
- `VirtualQueryEx`：调用 KSword `IOCTL_KSWORD_ARK_QUERY_VIRTUAL_MEMORY`。
- `ReadProcessMemory`：调用 KSword R0 读内存接口，自动按 1 MiB 分片。
- `WriteProcessMemory`：调用 KSword R0 写内存接口，自动按 256 KiB 分片。

插件不接管调试器、远程线程、远程分配或页面保护修改。写入只携带
`KSWORD_ARK_MEMORY_WRITE_FLAG_UI_CONFIRMED`，不会自动设置 `FORCE`，因此仍受
KSword 驱动写入安全策略约束。

## 构建

```powershell
$msbuild='D:\Software\VS\MSBuild\Current\Bin\MSBuild.exe'
& $msbuild 'CheatEnginePlugin\KswordCheatEnginePlugin.vcxproj' `
    /t:Build /p:Configuration=Release /p:Platform=x64 /m:1 /v:minimal
```

32 位 Cheat Engine 需要把 `Platform` 改为 `Win32` 单独构建。DLL 输出位置：

- `Ksword5.1\x64\Release\KswordCheatEnginePlugin.dll`
- `CheatEnginePlugin\Win32\Release\KswordCheatEnginePlugin.dll`

## 安装与使用

1. 先加载与当前仓库协议匹配的 `KswordARK.sys`。
2. 将与 Cheat Engine 位宽一致的 DLL 放入 Cheat Engine 的 `plugins` 目录。
3. 在 Cheat Engine 的插件设置中启用 `KSword Driver Bridge 1.0`。
4. 正常选择目标进程并扫描、查看或修改内存。

如果插件启用时无法打开 `\\.\KswordARKLog`，它会拒绝安装 hook，避免表面启用但
实际回退到普通 Win32 内存访问。

## ABI 来源

函数表顺序和 SDK 版本依据 Cheat Engine 官方仓库中的
[`Cheat Engine/plugin/cepluginsdk.h`](https://github.com/cheat-engine/cheat-engine/blob/master/Cheat%20Engine/plugin/cepluginsdk.h)。
本项目只声明实际使用的 ABI 前缀，没有复制 Lua SDK 或示例插件实现。
