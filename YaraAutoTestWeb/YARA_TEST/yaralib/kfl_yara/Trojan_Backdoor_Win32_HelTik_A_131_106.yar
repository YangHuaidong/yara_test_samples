rule Trojan_Backdoor_Win32_HelTik_A_131_106 
{
    meta:    
        judge = "black"
		threatname = "Trojan[Backdoor]/Win32.HelTik.A"
		threattype = "Backdoor"
		family = "HelTik"
		hacker = "None"
		comment = "https://goo.gl/ZiJyQv"
		date = "2015-05-14"
		author = "Florian Roth--DC"
		description = "APT17_Sample_FXSST_DLL Detects Samples related to APT17 activity - file FXSST.DLL" 
		refer = "4c21336dad66ebed2f7ee45d41e6cada"
        
    strings:
        $x1 = "Microsoft? Windows? Operating System" fullword wide
        $x2 = "fxsst.dll" fullword ascii
        $y1 = "DllRegisterServer" fullword ascii
        $y2 = ".cSV" fullword ascii
        $s1 = "GetLastActivePopup"
        $s2 = "Sleep"
        $s3 = "GetModuleFileName"
        $s4 = "VirtualProtect"
        $s5 = "HeapAlloc"
        $s6 = "GetProcessHeap"
        $s7 = "GetCommandLine"
   
   condition:
        uint16(0) == 0x5a4d and filesize < 800KB and ( 1 of ($x*) or all of ($y*) ) and all of ($s*)
}
