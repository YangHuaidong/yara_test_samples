rule Trojan_Backdoor_Win32_Zusy_hshchjjzhl_767_249
{
    meta:
        judge = "black"
        threatname = "Trojan[Backdoor]/Win32.Zusy.hshchjjzhl"
        threattype = "Backdoor"
        family = "Zusy"
        hacker = "None"
        author = "balala"
        refer = "b35f2de87343a674f5c1d809a5666349,a2378fd84cebe4b58c372d1c9b923542,fb450ecb2639c0a550cec0497e95460e"
        comment = "None"
        date = "2018-10-11"
        description = "None"
	strings:
        $s0 = "-GetModuleFileNameExW" fullword ascii
        $s1 = "\\MSN Talk Start.lnk" fullword wide
        $s2 = ":SeDebugPrivilege" fullword wide
        $s3 = "WinMM Version 1.0" fullword wide
        $s4 = "dwError1 = %d" fullword ascii
        $s5 = "*Can't Get" fullword wide
   
    condition:
        uint16(0) == 0x5a4d and filesize < 1000KB and all of them
}