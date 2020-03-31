rule Trojan_Backdoor_Win32_Emdivi_leg2_61_64 
{

    meta:
        judge = "black"
				threatname = "Trojan[Backdoor]/Win32.Emdivi.leg2"
				threattype = "Backdoor"
				family = "Emdivi"
				hacker = "None"
				comment = "https://securelist.com/blog/research/71876/new-activity-of-the-blue-termite-apt/"
				date = "2015-05-14"
				author = "Florian Roth @Cyber0ps--dc"
				description = "Detects Emdivi Malware" 
				refer = "076d27e43ad7f3c7b44c479f29ea98b9"
				super_rule = 1
        score = 80
        hash1 = "076d27e43ad7f3c7b44c479f29ea98b9"
        hash2 = "e427ee78902ad672e72b00a5651e107f"
        hash3 = "a0ab2d5b144d4ae2de9ef8d835afd652"
        
    strings:
        $s1 = "%TEMP%\\IELogs\\" fullword ascii
        $s2 = "MSPUB.EXE" fullword ascii
        $s3 = "%temp%\\" fullword ascii
        $s4 = "\\NOTEPAD.EXE" fullword ascii
        $s5 = "%4d-%02d-%02d %02d:%02d:%02d " fullword ascii
        $s6 = "INTERNET_OPEN_TYPE_PRECONFIG" fullword ascii
        $s7 = "%4d%02d%02d%02d%02d%02d" fullword ascii
   
    condition:
        uint16(0) == 0x5a4d and filesize < 1300KB and 6 of them
}