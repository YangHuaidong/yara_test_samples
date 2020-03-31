rule Trojan_Backdoor_Win32_Emdivi_leg_60_65 
{

    meta:
        judge = "black"
		threatname = "Trojan[Backdoor]/Win32.Emdivi.leg"
		threattype = "Backdoor"
		family = "Emdivi"
		hacker = "None"
		comment = "https://securelist.com/blog/research/71876/new-activity-of-the-blue-termite-apt/"
		date = "2015-08-20"
		author = "Florian Roth @Cyber0ps--DC"
		description = "Detects Emdivi Malware" 
		score = 80
        super_rule = 1
		refer = "bf7bc4c288df36bdc4f01e3d97cffc10"
		hash1 = "bf7bc4c288df36bdc4f01e3d97cffc10"
        hash2 = "337efc3851244c93fc0d812fb4ae66f9"
        hash3 = "b8d7fec363ac1d303717ba0732c7eb40"
        hash4 = "62cef94f307b1d2409c7836d75a96b4c"
    
    strings:
        $x1 = "wmic nteventlog where filename=\"SecEvent\" call cleareventlog" fullword wide
        $s0 = "del %Temp%\\*.exe %Temp%\\*.dll %Temp%\\*.bat %Temp%\\*.ps1 %Temp%\\*.cmd /f /q" fullword wide
        $x3 = "userControl-v80.exe" fullword ascii
        $s1 = "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; SV1; .NET CLR 2.0.50727.42)" fullword wide
        $s2 = "http://www.msftncsi.com" fullword wide
        $s3 = "net use | find /i \"c$\"" fullword wide
        $s4 = " /del /y & " fullword wide
        $s5 = "\\auto.cfg" fullword wide
        $s6 = "/ncsi.txt" fullword wide
        $s7 = "Dcmd /c" fullword wide
        $s8 = "/PROXY" fullword wide
    
    condition:
        uint16(0) == 0x5a4d and filesize < 800KB and all of them
}