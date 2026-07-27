-- KSword Cheat Engine 主题注入。
-- 本脚本只修改颜色和字体，不创建控件、不替换菜单、不改写任何 CE 事件。

local statusPath = os.getenv("KSWORD_CE_BRIDGE_STATUS_FILE")
local themeStatusPath = nil
if statusPath ~= nil and statusPath ~= "" then
    themeStatusPath = statusPath .. ".theme"
end

local function readBridgeStatus()
    if statusPath == nil or statusPath == "" then
        return ""
    end
    local statusFile = io.open(statusPath, "r")
    if statusFile == nil then
        return ""
    end
    local value = statusFile:read("*l") or ""
    statusFile:close()
    return value
end

local function writeFile(path, value)
    if path == nil or path == "" then
        return
    end
    local file = io.open(path, "w")
    if file ~= nil then
        file:write(value)
        file:close()
    end
end

local function writeBridgeStatus(value)
    writeFile(statusPath, value)
end

local function writeThemeStatus(value)
    writeFile(themeStatusPath, value)
end

if _G.KSwordThemeInjectionInstalled == true then
    return
end
_G.KSwordThemeInjectionInstalled = true

local function hexToColor(environmentName, fallback)
    local value = os.getenv(environmentName)
    if value == nil or value == "" then
        value = fallback
    end
    value = value:gsub("#", "")
    local rgb = tonumber(value, 16)
    if rgb == nil then
        rgb = tonumber(fallback:gsub("#", ""), 16)
    end
    local red = math.floor(rgb / 0x10000) % 0x100
    local green = math.floor(rgb / 0x100) % 0x100
    local blue = rgb % 0x100
    return red + green * 0x100 + blue * 0x10000
end

local colors = {
    window = hexToColor("KSWORD_PLUGIN_COLOR_WINDOW", "#08111A"),
    surface = hexToColor("KSWORD_PLUGIN_COLOR_SURFACE", "#101923"),
    surfaceAlt = hexToColor("KSWORD_PLUGIN_COLOR_SURFACE_ALT", "#17232E"),
    text = hexToColor("KSWORD_PLUGIN_COLOR_TEXT_PRIMARY", "#EDF4FA")
}

local function safeGet(object, propertyName, fallback)
    if object == nil then
        return fallback
    end
    local ok, value = pcall(function()
        return object[propertyName]
    end)
    if ok then
        return value
    end
    return fallback
end

local function safeSet(object, propertyName, value)
    if object ~= nil then
        pcall(function()
            object[propertyName] = value
        end)
    end
end

local function containsAny(className, fragments)
    for _, fragment in ipairs(fragments) do
        if className:find(fragment, 1, true) ~= nil then
            return true
        end
    end
    return false
end

local containerClasses = {
    "Form", "Panel", "GroupBox", "TabSheet", "PageControl", "ScrollBox"
}
local inputClasses = {
    "TEdit", "TMemo", "TComboBox", "TListBox", "TListView",
    "TTreeView", "TStringGrid"
}
local textClasses = {
    "Label", "CheckBox", "RadioButton", "Button", "BitBtn", "SpeedButton"
}
local untouchedCustomClasses = {
    "AddressList", "FoundList", "Disassembl", "HexView",
    "MemoryBrowser", "VirtualStringTree"
}

local function applyTheme(control, visited)
    if control == nil or not inheritsFromControl(control) then
        return
    end
    visited = visited or {}
    local identity = tostring(control)
    if visited[identity] then
        return
    end
    visited[identity] = true

    local className = safeGet(control, "ClassName", "")
    if not containsAny(className, untouchedCustomClasses) then
        local font = safeGet(control, "Font", nil)
        if font ~= nil and (
            containsAny(className, containerClasses) or
            containsAny(className, inputClasses) or
            containsAny(className, textClasses)) then
            safeSet(font, "Color", colors.text)
        end

        if className:find("Form", 1, true) ~= nil then
            safeSet(control, "Color", colors.window)
        elseif containsAny(className, inputClasses) then
            safeSet(control, "Color", colors.surfaceAlt)
        elseif containsAny(className, containerClasses) then
            safeSet(control, "Color", colors.surface)
        end
    end

    if inheritsFromWinControl(control) then
        local count = safeGet(control, "ControlCount", 0)
        for index = 0, count - 1 do
            local childOk, child = pcall(function()
                return control.Control[index]
            end)
            if childOk then
                applyTheme(child, visited)
            end
        end
    end
end

local function installTheme()
    local mainForm = getMainForm()
    if mainForm == nil then
        error("Cheat Engine main form is unavailable")
    end

    local originalCaption = safeGet(mainForm, "Caption", "Cheat Engine")
    local originalSuffix = originalCaption:match("%s*(%b())%s*$") or ""
    _G.KSwordApplyR0Caption = function()
        local currentMainForm = getMainForm()
        if currentMainForm ~= nil then
            currentMainForm.Caption = "KSword CE (R0)"
        end
    end
    if readBridgeStatus() == "bridge-ready" or
        readBridgeStatus() == "ready" then
        mainForm.Caption = "KSword CE (R0)"
    else
        mainForm.Caption = "KSword CE" .. originalSuffix
    end
    applyTheme(mainForm)
    _G.KSwordThemeFormNotification = registerFormAddNotification(
        function(form)
            pcall(function()
                form.registerFirstShowCallback(function(createdForm)
                    applyTheme(createdForm)
                end)
            end)
        end)
end

local function finishThemeInitialization()
    local ok, message = xpcall(installTheme, debug.traceback)
    if ok then
        writeThemeStatus("ready")
        if readBridgeStatus() == "bridge-ready" then
            writeBridgeStatus("ready")
        elseif readBridgeStatus() == "failed" then
            writeBridgeStatus("failed")
        end
    else
        writeThemeStatus("failed\n" .. tostring(message))
        writeBridgeStatus("failed")
    end
end

-- 延迟到 CE 自身 autorun 扩展加载完成后，只执行一次颜色注入。
local startupTimer = createTimer(nil, false)
startupTimer.Interval = 500
startupTimer.OnTimer = function(timer)
    timer.Enabled = false
    timer.destroy()
    _G.KSwordThemeStartupTimer = nil
    finishThemeInitialization()
end
_G.KSwordThemeStartupTimer = startupTimer
startupTimer.Enabled = true
