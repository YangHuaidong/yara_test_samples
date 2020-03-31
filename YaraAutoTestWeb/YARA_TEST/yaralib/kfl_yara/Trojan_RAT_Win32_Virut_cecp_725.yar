rule Trojan_RAT_Win32_Virut_cecp_725
{
    meta:
        judge = "black"
        threatname = "Trojan[RAT]/Win32.Virut.cecp"
        threattype = "RAT"
        family = "Virut"
        hacker = "None"
        author = "copy"
        refer = "06085536e3c529261d71413f07bd2d24"
        comment = "None"
        date = "2017-09-13"
        description = "None"
    strings:
        $s0 = "C:\\program Files\\Crack\\" nocase wide ascii
        $s1 = "Kother599" nocase wide ascii
        $s2 = "LtkC3" nocase wide ascii
    condition:
        all of them
}