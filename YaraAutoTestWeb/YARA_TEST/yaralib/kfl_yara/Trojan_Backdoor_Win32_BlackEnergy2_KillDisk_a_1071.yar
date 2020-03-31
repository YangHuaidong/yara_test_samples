rule Trojan_Backdoor_Win32_BlackEnergy2_KillDisk_a_1071
{
	meta:
		judge = "black"
		threatname = "Trojan[Backdoor]/Win32.BlackEnergy2.KillDisk.a"
		threattype = "ICS,Backdoor"
		family = "BlackEnergy2"
		hacker = "None"
		refer = "66676deaa9dfe98f8497392064aefbab"
		author = "LiuGuangzhu"
		comment = "None"
		date = "2019-03-09"
		description = "None"
    strings:
        $s0 = "system32\\cmd.exe" fullword ascii
        $s1 = "system32\\icacls.exe" fullword wide
        $s2 = "/c del /F /S /Q %c:\\*.*" fullword ascii
        $s3 = "shutdown /r /t %d" fullword ascii
        $s4 = "/C /Q /grant " fullword wide
        $s5 = "%08X.tmp" fullword ascii
        $s6 = "/c format %c: /Y /X /FS:NTFS" fullword ascii
        $s7 = "/c format %c: /Y /Q" fullword ascii
        $s8 = "taskhost.exe" fullword wide /* Goodware String - occured 1 times */
        $s9 = "shutdown.exe" fullword wide /* Goodware String - occured 1 times */
    condition:
        uint16(0) == 0x5a4d and filesize < 500KB and 8 of them
}