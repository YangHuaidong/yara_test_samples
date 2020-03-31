rule Trojan_RAT_Win32_SGeneric_MWcp_719
{
    meta:
        judge = "black"
        threatname = "Trojan[RAT]/Win32.SGeneric.MWcp"
        threattype = "RAT"
        family = "SGeneric"
        hacker = "None"
        author = "copy"
        refer = "299522fe80c136bdaca59c58b5a2d4e9"
        comment = "None"
        date = "2017-09-14"
        description = "None"
    strings:
        $s0 = ")\\MemLoader\\MainFrm.cpp" nocase wide ascii
        $s1 = "losYA" nocase wide ascii
        $s2 = ")\\MemLoader\\WaveView.cpp" nocase wide ascii
        $s3 = ")\\MemLoader\\WaveDoc.cpp" nocase wide ascii
    condition:
        all of them
}