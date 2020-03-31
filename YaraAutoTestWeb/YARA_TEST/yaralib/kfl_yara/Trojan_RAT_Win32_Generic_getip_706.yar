rule Trojan_RAT_Win32_Generic_getip_706
{
    meta:
        judge = "black"
        threatname = "Trojan[RAT]/Win32.Generic.getip"
        threattype = "RAT"
        family = "Generic"
        hacker = "None"
        author = "copy"
        refer = "D4998D95D2AE950F668FBD70EBA3EBC1"
        comment = "None"
        date = "2017-09-07"
        description = "None"
    strings:
        $s0 = "183.60.204.58" nocase wide ascii
        $s1 = "-64OS" nocase wide ascii
    condition:
        all of them
}