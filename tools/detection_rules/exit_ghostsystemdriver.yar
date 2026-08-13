/*
    EXIT / GhostSystemDriver 静态检测规则。
    规则依赖多组行为字符串，不以单一样本哈希作为判定条件。
*/

rule KSword_EXIT_Libcef_Proxy
{
    meta:
        description = "Detects the EXIT malicious CEF proxy and driver dropper"
        author = "KSword"
        version = "1.0"
        reference_sha256 = "c33fd31c5c7d3a2b41c4042fc95ad864b888279d5494a6e590253ce169d97233"

    strings:
        $cef_1 = "cef_execute_process" ascii
        $cef_2 = "cef_initialize" ascii
        $cef_3 = "cef_shutdown" ascii

        $uac_1 = "Elevation:Administrator!new:" ascii wide
        $uac_2 = "3E5FC7F9-9A51-4367-9063-A120244FBEC7" ascii wide
        $uac_3 = "CoGetObject" ascii
        $uac_4 = "CheckTokenMembership" ascii

        $mask_1 = "explorer.exe" ascii wide
        $mask_2 = "NtQueryInformationProcess" ascii
        $mask_3 = "ReadProcessMemory" ascii

        $driver_1 = "GhostSystemDriver" ascii wide
        $driver_2 = "CreateServiceW" ascii
        $driver_3 = "StartServiceW" ascii
        $evasion = "avp.exe" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        2 of ($cef_*) and
        all of ($uac_*) and
        all of ($mask_*) and
        all of ($driver_*) and
        $evasion
}

rule KSword_GhostSystemDriver_Defense_Impairment
{
    meta:
        description = "Detects the GhostSystemDriver security-product termination driver"
        author = "KSword"
        version = "1.0"
        reference_sha256 = "292ed18766668b363256ba1c5370f1cabb0d8dc1b53027727d943bc98c78256c"

    strings:
        $defender_1 = "TamperProtection" ascii wide
        $defender_2 = "DisableRealtimeMonitoring" ascii wide
        $defender_3 = "WdFilter" ascii wide
        $defender_4 = "WdBoot" ascii wide
        $defender_5 = "WdNisDrv" ascii wide
        $defender_6 = "WinDefend" ascii wide

        $process_1 = "MsMpEng.exe" ascii wide
        $process_2 = "NisSrv.exe" ascii wide
        $process_3 = "360tray.exe" ascii wide
        $process_4 = "360Safe.exe" ascii wide
        $process_5 = "AvastSvc.exe" ascii wide
        $process_6 = "AVGSvc.exe" ascii wide
        $process_7 = "QQPCTray.exe" ascii wide

        $kernel_1 = "ZwSetValueKey" ascii
        $kernel_2 = "ZwTerminateProcess" ascii
        $kernel_3 = "ZwUnloadDriver" ascii
        $registry_360 = "\\Registry\\Machine\\SOFTWARE\\360" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        4 of ($defender_*) and
        3 of ($process_*) and
        all of ($kernel_*) and
        $registry_360
}

rule KSword_EXIT_ISO_Attack_Path
{
    meta:
        description = "Detects an ISO9660 image carrying the EXIT attack path"
        author = "KSword"
        version = "1.0"
        reference_sha256 = "be92506b5dd88992f1c0257ff443037afbb4615507f89a4b412c7c5c16dabdd8"

    strings:
        $iso = "CD001" ascii
        $cef = "cef_execute_process" ascii
        $elevation = "Elevation:Administrator!new:" ascii wide
        $cmstplua = "3E5FC7F9-9A51-4367-9063-A120244FBEC7" ascii wide
        $ghost = "GhostSystemDriver" ascii wide
        $explorer = "explorer.exe" ascii wide

    condition:
        filesize > 0x8800 and
        (uint8(0x8000) == 1 or uint8(0x8000) == 2) and
        $iso at 0x8001 and
        all of ($cef, $elevation, $cmstplua, $ghost, $explorer)
}
