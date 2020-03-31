rule Trojan_Backdoor_Win32_Generic_wswlfzhsl_678_100
{
    meta:
        judge = "black"
        threatname = "Trojan[Backdoor]/Win32.Generic.wswlfzhsl"
        threattype = "Backdoor"
        family = "Generic"
        hacker = "None"
        author = "balala"
        refer = "5fc9d5c25777f6f802bc41323e103cae"
        comment = "None"
        date = "2018-09-05"
        description = "None"
	strings:
        $s0 = "cmd.exe /q /c \"%s\"" fullword ascii 
        $s1 = "\\\\.\\pipe\\%s%s%d" fullword ascii 
        $s2 = "This is a service executable! Couldn't start directly." fullword ascii 
        $s3 = "\\\\.\\pipe\\TermHlp_communicaton" fullword ascii 
        $s4 = "TermHlp_stdout" fullword ascii 
        $s5 = "TermHlp_stdin" fullword ascii

    condition:
        uint16(0) == 0x5a4d and filesize < 75KB and 4 of ($s*)

}