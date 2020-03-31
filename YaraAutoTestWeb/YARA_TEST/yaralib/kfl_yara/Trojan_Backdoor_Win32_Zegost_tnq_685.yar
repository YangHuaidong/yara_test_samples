rule Trojan_Backdoor_Win32_Zegost_tnq_685
{
    meta:
        judge = "black"
        threatname = "Trojan[Backdoor]/Win32.Zegost.tnq"
        threattype = "Backdoor"
        family = "Zegost"
        hacker = "None"
        author = "copy"
        refer = "973f60be2d029e6601bf113906f4ed8d"
        comment = "None"
        date = "2017-07-27"
        description = "None"
    strings:
        $s0 = "AemaNyeKecivreSteG" nocase wide ascii
        $s1 = "SeRestorePrivilege" nocase wide ascii
        $s2 = "SeBackupPrivilege" nocase wide ascii
    condition:
        all of them
}