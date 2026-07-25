[CmdletBinding()]
param(
    [string]$CheatEngineDirectory = '',
    [ValidateSet('Debug', 'Release')]
    [string]$Configuration = 'Release'
)

$ErrorActionPreference = 'Stop'
$repositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$sourceRoot = Join-Path $repositoryRoot 'CheatEngineExecutablePlugin'
$pluginRoot = Join-Path $repositoryRoot 'plugin\cheat-engine'

# 未显式指定时，从系统安装信息解析 CE 目录，避免写个人机器路径。
if ([string]::IsNullOrWhiteSpace($CheatEngineDirectory)) {
    $uninstallRoots = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*'
    )
    $installation = Get-ItemProperty $uninstallRoots -ErrorAction SilentlyContinue |
        Where-Object { $_.DisplayName -eq 'Cheat Engine 7.6' } |
        Select-Object -First 1
    $CheatEngineDirectory = [string]$installation.InstallLocation
}

# 所有输入产物必须存在，缺一项即停止，避免生成看似完整的坏插件。
$ceDirectory = [IO.Path]::GetFullPath($CheatEngineDirectory)
$launcher = Join-Path $sourceRoot "x64\$Configuration\KswordCheatEngineLauncher.exe"
$bridgeX64 = Join-Path $repositoryRoot "CheatEnginePlugin\x64\$Configuration\KswordCheatEnginePlugin.dll"
$bridgeWin32 = Join-Path $repositoryRoot "CheatEnginePlugin\Win32\$Configuration\KswordCheatEnginePlugin.dll"
$requiredFiles = @(
    (Join-Path $ceDirectory 'cheatengine-x86_64.exe'),
    $launcher,
    $bridgeX64,
    $bridgeWin32
)
foreach ($requiredFile in $requiredFiles) {
    if (-not (Test-Path -LiteralPath $requiredFile -PathType Leaf)) {
        throw "Required file is missing: $requiredFile"
    }
}

# 只清理脚本拥有的精确插件目录，并验证它位于仓库 plugin 根下。
$expectedPluginRoot = [IO.Path]::GetFullPath(
    (Join-Path $repositoryRoot 'plugin\cheat-engine'))
if ([IO.Path]::GetFullPath($pluginRoot) -ne $expectedPluginRoot) {
    throw "Refusing to replace unexpected path: $pluginRoot"
}
if (Test-Path -LiteralPath $pluginRoot) {
    Remove-Item -LiteralPath $pluginRoot -Recurse -Force
}

$payloadRoot = Join-Path $pluginRoot 'payload\Cheat Engine'
$bridgeRoot = Join-Path $pluginRoot 'bridge'
New-Item -ItemType Directory -Path $payloadRoot -Force | Out-Null
New-Item -ItemType Directory -Path (Join-Path $bridgeRoot 'x64') -Force | Out-Null
New-Item -ItemType Directory -Path (Join-Path $bridgeRoot 'Win32') -Force | Out-Null

# 保留 CE 原始用户态目录布局，随后移除其 DBK/DBVM 内核载荷和卸载器。
Copy-Item -Path (Join-Path $ceDirectory '*') -Destination $payloadRoot -Recurse -Force
$excludedPayloads = @(
    'dbk32.cepack',
    'dbk64.cepack',
    'dbk64.sys',
    'Kernelmoduleunloader.exe',
    'vmdisk.img',
    'vmdisk.img.sig',
    'unins000.dat',
    'unins000.exe',
    'unins000.msg'
)
foreach ($relativePath in $excludedPayloads) {
    $candidate = Join-Path $payloadRoot $relativePath
    if (Test-Path -LiteralPath $candidate) {
        Remove-Item -LiteralPath $candidate -Force
    }
}

# 覆盖 KSword 自有入口、清单、通知、自动加载脚本和双架构桥接 DLL。
Copy-Item -LiteralPath $launcher -Destination (
    Join-Path $pluginRoot 'KswordCheatEngineLauncher.exe') -Force
Copy-Item -LiteralPath $bridgeX64 -Destination (
    Join-Path $bridgeRoot 'x64\KswordCheatEnginePlugin.dll') -Force
Copy-Item -LiteralPath $bridgeWin32 -Destination (
    Join-Path $bridgeRoot 'Win32\KswordCheatEnginePlugin.dll') -Force
Copy-Item -LiteralPath (Join-Path $sourceRoot 'plugin.json') -Destination $pluginRoot -Force
Copy-Item -LiteralPath (Join-Path $sourceRoot 'README.md') -Destination $pluginRoot -Force
Copy-Item -LiteralPath (Join-Path $sourceRoot 'NOTICE.md') -Destination $pluginRoot -Force
Copy-Item -LiteralPath (
    Join-Path $sourceRoot 'integration\00_ksword_bridge.lua') -Destination (
    Join-Path $payloadRoot 'autorun\00_ksword_bridge.lua') -Force

# 输出机器可读摘要，便于构建日志核对插件文件是否真实包含。
$allFiles = Get-ChildItem -LiteralPath $pluginRoot -Recurse -File
[pscustomobject]@{
    PluginRoot = $pluginRoot
    FileCount = $allFiles.Count
    TotalBytes = [int64](($allFiles | Measure-Object Length -Sum).Sum)
    LauncherSha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath (
        Join-Path $pluginRoot 'KswordCheatEngineLauncher.exe')).Hash
    BridgeX64Sha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath (
        Join-Path $bridgeRoot 'x64\KswordCheatEnginePlugin.dll')).Hash
    BridgeWin32Sha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath (
        Join-Path $bridgeRoot 'Win32\KswordCheatEnginePlugin.dll')).Hash
} | ConvertTo-Json
