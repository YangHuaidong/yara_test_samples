rule Trojan_RAT_Win32_Generic_str_709
{
    meta:
        judge = "black"
        threatname = "Trojan[RAT]/Win32.Generic.str"
        threattype = "RAT"
        family = "Generic"
        hacker = "None"
        author = "copy"
        refer = "69ECBFD76981A656651D617A44F78732"
        comment = "None"
        date = "2017-09-07"
        description = "None"
    strings:
        $s0 = "G3Tmv" nocase wide ascii
        $s1 = "QDPhB" nocase wide ascii
        $s2 = "6zeOb" nocase wide ascii
        $s3 = "43yJD" nocase wide ascii
    condition:
        all of them
}