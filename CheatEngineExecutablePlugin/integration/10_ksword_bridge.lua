-- KSword Cheat Engine 自动初始化脚本。
-- UI 主题脚本先注册延迟初始化；本脚本只加载桥接并打开宿主提供的 PID。

local statusPath = os.getenv("KSWORD_CE_BRIDGE_STATUS_FILE")

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

-- 在桥接函数槽安装后再打开目标，确保首个进程句柄也经过 KSword。
local targetPid = tonumber(os.getenv("KSWORD_CE_TARGET_PID") or "")
if targetPid ~= nil and targetPid > 0 then
    local openOk = pcall(openProcess, targetPid)
    if not openOk then
        writeStatus("failed")
        return
    end
end

-- 主题定时器会在全部 autorun 脚本完成后执行，并把 bridge-ready 汇总成 ready。
writeStatus("bridge-ready")
