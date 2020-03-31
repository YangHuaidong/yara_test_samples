rule Trojan_RAT_Win32_Scar_716
{
    meta:
        judge = "black"
        threatname = "Trojan[RAT]/Win32.Scar"
        threattype = "RAT"
        family = "Scar"
        hacker = "None"
        author = "copy"
        refer = "81e2983169e4bbde5b61e031d3741fe7"
        comment = "None"
        date = "2017-07-27"
        description = "None"
    strings:
        $s0 = "Consys21.dll" nocase wide ascii
        $s1 = "SeShutdownPrivilege" nocase wide ascii
        $s2 = "uHdxN" nocase wide ascii
        $s3 = "lstrcmpiA" nocase wide ascii
    condition:
        all of them
}