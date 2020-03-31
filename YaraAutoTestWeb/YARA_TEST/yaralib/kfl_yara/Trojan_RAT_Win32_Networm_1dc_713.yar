rule Trojan_RAT_Win32_Networm_1dc_713
{
    meta:
        judge = "black"
        threatname = "Trojan[RAT]/Win32.Networm.1dc"
        threattype = "RAT"
        family = "Networm"
        hacker = "None"
        author = "copy"
        refer = "5e513a458972e3b6702115354e432372"
        comment = "None"
        date = "2017-08-10"
        description = "None"
    strings:
        $s0 = "Yuemingl.txt" nocase wide ascii
        $s1 = "hackshen.exe" nocase wide ascii
        $s2 = "svchost.exe" nocase wide ascii
    condition:
        all of them
}