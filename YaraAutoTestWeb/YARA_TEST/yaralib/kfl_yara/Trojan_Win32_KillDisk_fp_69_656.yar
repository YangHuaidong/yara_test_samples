rule Trojan_Win32_KillDisk_fp_69_656 
{

    meta:
        judge = "black"
		threatname = "Trojan[Downloader]/Win32.KillDisk.fp"
		threattype = "Downloader"
		family = "KillDisk"
		hacker = "None"
		comment = "http://feedproxy.google.com/~r/eset/blog/~3/BXJbnGSvEFc/"
		date = "2015-05-14"
		author = "Florian Roth--DC"
		description = "Detects KillDisk malware from BlackEnergy" 
		refer = "66676deaa9dfe98f8497392064aefbab"
		hash1 = "66676deaa9dfe98f8497392064aefbab"
        hash2 = "cd1aa880f30f9b8bb6cf4d4f9e41ddf4"
        hash3 = "7361b64ddca90a1a1de43185bd509b64"
        hash4 = "72bd40cd60769baffd412b84acc03372"
        super_rule = 1
        score = 80

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