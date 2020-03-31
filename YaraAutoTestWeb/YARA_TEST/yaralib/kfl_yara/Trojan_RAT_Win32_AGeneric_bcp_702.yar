rule Trojan_RAT_Win32_AGeneric_bcp_702
{
    meta:
        judge = "black"
        threatname = "Trojan[RAT]/Win32.AGeneric.bcp"
        threattype = "RAT"
        family = "AGeneric"
        hacker = "None"
        author = "copy"
        refer = "246a5b03a49fe931650808e5cd9f943d"
        comment = "None"
        date = "2017-09-14"
        description = "None"
    strings:
        $s0 = "SRDSL" nocase wide ascii
        $s1 = "~MHz" nocase wide ascii
        $s2 = "%s\\%d.bak" nocase wide ascii
        $s3 = "WinSta0\\Default" nocase wide ascii
    condition:
        all of them
}