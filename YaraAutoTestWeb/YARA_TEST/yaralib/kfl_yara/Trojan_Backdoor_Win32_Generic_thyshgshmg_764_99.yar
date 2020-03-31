rule Trojan_Backdoor_Win32_Generic_thyshgshmg_764_99
{
    meta:
        judge = "black"
        threatname = "Trojan[Backdoor]/Win32.Generic.thyshgshmg"
        threattype = "Backdoor"
        family = "Generic"
        hacker = "None"
        author = "balala"
        refer = "66523a430459f284a3610c2070ca1ea7"
        comment = "None"
        date = "2018-10-11"
        description = "None"
	strings:
        $s1 = "%ProgramFiles%\\Internet Explorer\\iexplore.exe" fullword ascii
        $s2 = "msictl.exe" fullword ascii
        $s3 = "127.0.0.1:8080" fullword ascii
        $s4 = "mshtml.dat" fullword ascii
        $s5 = "msisvc" fullword ascii
        $s6 = "NOKIAN95/WEB" fullword ascii
   
    condition:
        uint16(0) == 0x5a4d and filesize < 160KB and 4 of them 
}