rule Trojan_RAT_Win32_Nimnul_abc_714
{
    meta:
        judge = "black"
        threatname = "Trojan[RAT]/Win32.Nimnul.abc"
        threattype = "RAT"
        family = "Nimnul"
        hacker = "None"
        author = "copy"
        refer = "032f59126e7f3aab35dde599ddea8113"
        comment = "None"
        date = "2017-11-23"
        description = "None"
    strings:
        $s0 = "d5YRV" nocase wide ascii
        $s1 = "ddq!j" nocase wide ascii
        $s2 = "ss32." nocase wide ascii
        $s3 = "strupr" nocase wide ascii
    condition:
        all of them
}