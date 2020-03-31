rule Trojan_Backdoor_Win32_WisdomEyes_sljmhzml_688_239
{
    meta:
        judge = "black"
        threatname = "Trojan[Backdoor]/Win32.WisdomEyes.sljmhzml"
        threattype = "Backdoor"
        family = "WisdomEyes"
        hacker = "None"
        author = "balala"
        refer = "78b56bc3edbee3a425c96738760ee406,5aa0510f6f1b0e48f0303b9a4bfc641e,531d30c8ee27d62e6fbe855299d0e7de"
        comment = "None"
        date = "2018-09-05"
        description = "None"
	strings:
        $s1 = "svchostdllserver.dll" fullword ascii 
        $s2 = "SvcHostDLL: RegisterServiceCtrlHandler %S failed" fullword ascii 
        $s3 = "\\nbtstat.exe" fullword ascii
        $s4 = "DataVersionEx" fullword ascii

    condition:
        uint16(0) == 0x5a4d and filesize < 150KB and all of them

}