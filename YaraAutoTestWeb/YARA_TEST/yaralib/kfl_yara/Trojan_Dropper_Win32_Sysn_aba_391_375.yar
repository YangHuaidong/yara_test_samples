rule Trojan_Dropper_Win32_Sysn_aba_391_375
{
    meta:
        judge = "black"
        threatname = "Trojan[Dropper]/Win32.Sysn.aba"
        threattype = "Dropper"
        family = "Sysn"
        hacker = "None"
        author = "Florian Roth-copy"
        refer = "e8cd6fad31bf610d9b0175b2366553a0,afbd94a38675ef6856f4c942d255d4f4"
        comment = "APT"
        date = "2018-07-02"
        description = "Detect Emissary Malware - from samples A08E81B411.DAT, ishelp.dll"
		score = 75
    strings:
        $s1 = "cmd.exe /c %s > %s" fullword ascii
        $s2 = "execute cmd timeout." fullword ascii
        $s3 = "rundll32.exe \"%s\",Setting" fullword ascii
        $s4 = "DownloadFile - exception:%s." fullword ascii
        $s5 = "CDllApp::InitInstance() - Evnet create successful." fullword ascii
        $s6 = "UploadFile - EncryptBuffer Error" fullword ascii
        $s7 = "WinDLL.dll" fullword wide
        $s8 = "DownloadFile - exception:%s,code:0x%08x." fullword ascii
        $s9 = "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1)" fullword ascii
        $s10 = "CDllApp::InitInstance() - Evnet already exists." fullword ascii

    condition:
        uint16(0) == 0x5a4d and filesize < 250KB and 3 of them
}