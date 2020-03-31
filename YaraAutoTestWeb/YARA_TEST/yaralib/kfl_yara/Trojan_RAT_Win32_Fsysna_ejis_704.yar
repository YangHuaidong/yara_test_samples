rule Trojan_RAT_Win32_Fsysna_ejis_704
{
    meta:
        judge = "black"
        threatname = "Trojan[RAT]/Win32.Fsysna.ejis"
        threattype = "RAT"
        family = "Fsysna"
        hacker = "None"
        author = "copy"
        refer = "bc0d5ec760abb0f5455447455cf1e739"
        comment = "None"
        date = "2017-09-21"
        description = "None"
    strings:
        $s0 = "/A75BRDzDvkFBdD6D/am" nocase wide ascii
        $s1 = "elklogl" nocase wide ascii
        $s2 = "CDG\tU" nocase wide ascii
        $s3 = "AkkPQj" nocase wide ascii
    condition:
        all of them
}