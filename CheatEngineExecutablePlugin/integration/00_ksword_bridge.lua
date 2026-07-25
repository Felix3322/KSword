-- KSword Cheat Engine 自动初始化脚本。
-- 本文件由打包脚本放入 CE autorun；它只加载 KSword 桥接并打开宿主提供的 PID。

local statusPath = os.getenv("KSWORD_CE_BRIDGE_STATUS_FILE")

-- writeStatus：向独立启动器回报桥接初始化结果。
local function writeStatus(value)
    if statusPath == nil or statusPath == "" then
        return
    end
    local statusFile = io.open(statusPath, "w")
    if statusFile ~= nil then
        statusFile:write(value)
        statusFile:close()
    end
end

-- 优先使用启动器给出的绝对路径；回退路径便于直接启动插件内置 CE。
local bridgePath = os.getenv("KSWORD_CE_BRIDGE_DLL")
if bridgePath == nil or bridgePath == "" then
    local architecture = cheatEngineIs64Bit() and "x64" or "Win32"
    bridgePath = getCheatEngineDir() .. "..\\..\\bridge\\" ..
        architecture .. "\\KswordCheatEnginePlugin.dll"
end

-- loadPlugin 会同时调用 CEPlugin_InitializePlugin；返回 nil 表示加载或初始化失败。
local loadOk, pluginId = pcall(loadPlugin, bridgePath)
if not loadOk or pluginId == nil then
    writeStatus("failed")
    return
end

-- 在桥接函数槽已安装后再打开目标，确保首个进程句柄也经过 KSword。
local targetPid = tonumber(os.getenv("KSWORD_CE_TARGET_PID") or "")
if targetPid ~= nil and targetPid > 0 then
    pcall(openProcess, targetPid)
end
writeStatus("ready")
