-- KSword Cheat Engine 自动初始化脚本。
-- UI 主题脚本先注册延迟初始化；本脚本只加载桥接并打开宿主提供的 PID。

local statusPath = os.getenv("KSWORD_CE_BRIDGE_STATUS_FILE")
local themeStatusPath = nil
if statusPath ~= nil and statusPath ~= "" then
    themeStatusPath = statusPath .. ".theme"
end

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

local function readStatus(path)
    if path == nil or path == "" then
        return ""
    end
    local statusFile = io.open(path, "r")
    if statusFile == nil then
        return ""
    end
    local value = statusFile:read("*l") or ""
    statusFile:close()
    return value
end

local function finishBridgeInitialization()
    if type(_G.KSwordApplyR0Caption) == "function" then
        pcall(_G.KSwordApplyR0Caption)
    end
    if readStatus(themeStatusPath) == "ready" then
        writeStatus("ready")
    else
        writeStatus("bridge-ready")
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

-- 等 CE 主消息循环空闲后再打开目标，避免在 autorun 加载栈中同步触发
-- 模块/内存区枚举。桥接已在定时器创建前安装，因此首个进程句柄仍经过 KSword。
local targetPid = tonumber(os.getenv("KSWORD_CE_TARGET_PID") or "")
if targetPid ~= nil and targetPid > 0 then
    local openTimer = createTimer(nil, false)
    openTimer.Interval = 750
    openTimer.OnTimer = function(timer)
        timer.Enabled = false
        timer.destroy()
        _G.KSwordBridgeOpenTimer = nil
        local openOk = pcall(openProcess, targetPid)
        if not openOk or getOpenedProcessID() ~= targetPid then
            writeStatus("failed")
            return
        end
        finishBridgeInitialization()
    end
    _G.KSwordBridgeOpenTimer = openTimer
    openTimer.Enabled = true
else
    finishBridgeInitialization()
end
