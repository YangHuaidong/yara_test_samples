rule Trojan_Backdoor_Win32_BlackEnergy_Driver_AMDIDE_1070
{
	meta:
		judge = "black"
		threatname = "Trojan[Backdoor]/Win32.BlackEnergy.Driver.AMDIDE"
		threattype = "ICS,Backdoor"
		family = "BlackEnergy"
		hacker = "None"
		refer = "97b41d4b8d05a1e165ac4cc2a8ac6f39"
		author = "LiuGuangzhu"
		comment = "None"
		date = "2019-03-09"
		description = "None"
    strings:
        $s1 = " AMD IDE driver" fullword wide
        $s2 = "SessionEnv" fullword wide
        $s3 = "\\DosDevices\\{C9059FFF-1C49-4445-83E8-" wide
        $s4 = "\\Device\\{C9059FFF-1C49-4445-83E8-" wide
    condition:
        uint16(0) == 0x5a4d and filesize < 150KB and all of them
}