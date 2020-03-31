rule Trojan_Backdoor_Win32_Regin_aaaaaf_503_185
{
    meta:
        judge = "black"
        threatname = "Trojan[Backdoor]/Win32.Regin.aaaaaf"
        threattype = "Backdoor"
        family = "Regin"
        hacker = "None"
        author = "balala"
        refer = "66afaa303e13faa4913eaad50f7237ea"
		comment = "None"
        date = "2018-08-02"
        description = "Detects svcstat from Regin report - file svcsstat.exe_sample"
    

    strings:
        $s0 = "Service Control Manager" fullword ascii
        $s1 = "_vsnwprintf" fullword ascii
        $s2 = "Root Agency" fullword ascii
        $s3 = "Root Agency0" fullword ascii
        $s4 = "StartServiceCtrlDispatcherA" fullword ascii
        $s5 = "\\\\?\\UNC" fullword wide
        $s6 = "%ls%ls" fullword wide

    condition:
        all of them and filesize < 15KB and filesize > 10KB 
}