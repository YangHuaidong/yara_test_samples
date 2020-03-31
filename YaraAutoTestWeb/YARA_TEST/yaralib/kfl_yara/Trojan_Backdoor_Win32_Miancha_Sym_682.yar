rule Trojan_Backdoor_Win32_Miancha_Sym_682
{
    meta:
        judge = "black"
        threatname = "Trojan[Backdoor]/Win32.Miancha.Sym"
        threattype = "backdoor"
        family = "Miancha"
        hacker = "None"
        author = "copy"
        refer = "03f0b6bd148155d1ed74dda7634fb4e2"
        comment = "None"
        date = "2017-11-23"
        description = "None"
    strings:
        $s0 = "SSSf.A" nocase wide ascii
        $s1 = ">YrCh" nocase wide ascii
        $s2 = "E2SN" nocase wide ascii
        $s3 = "E:SNd" nocase wide ascii
    condition:
        all of them
}