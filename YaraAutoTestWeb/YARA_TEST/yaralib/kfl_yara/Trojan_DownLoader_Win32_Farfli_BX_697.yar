rule Trojan_DownLoader_Win32_Farfli_BX_697
{
    meta:
        judge = "black"
        threatname = "Trojan[DownLoader]/Win32.Farfli.BX"
        threattype = "DownLoader"
        family = "Farfli"
        hacker = "None"
        author = "copy"
        refer = "c6353a653fc0abb42a38074d2909ea6b"
        comment = "None"
        date = "2017-09-21"
        description = "None"
    strings:
        $s0 = "shlwapi.dll" nocase wide ascii
        $s1 = "%-24s %-15s 0x%x(%d)" nocase wide ascii
        $s2 = "XIAOQI" nocase wide ascii
    condition:
        all of them
}