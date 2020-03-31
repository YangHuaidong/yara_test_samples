rule Trojan_RAT_Win32__Scar_orto_727
{
    meta:
        judge = "black"
        threatname = "Trojan[RAT]/Win32.Scar.orto"
        threattype = "RAT"
        family = "Scar"
        hacker = "None"
        author = "copy"
        refer = "09C488CA9028475F83F8908A0A071FFC"
        comment = "None"
        date = "2017-08-23"
        description = "None"
    strings:
        $s0 = "4jNnIiz7AYwRp10" nocase wide ascii
        $s1 = "xepdy0Y2x1" nocase wide ascii
        $s2 = "DHLDAT.dat" nocase wide ascii
        $s3 = "imagehlp.dll" nocase wide ascii
    condition:
        all of them
}