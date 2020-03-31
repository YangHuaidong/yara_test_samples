rule Trojan_Dropper_Win32_Derusbi_avj_390_373
{
    meta:
        judge = "black"
        threatname = "Trojan[Dropper]/Win32.Derusbi.avj"
        threattype = "Dropper"
        family = "Derusbi"
        hacker = "None"
        author = "Florian Roth-copy"
        refer = "7bc8a2ef08f51cf6eeb777b261da3367,ef498ea09bf51b002fc7eb3dfd0d19d3"
        comment = "None"
        date = "2018-06-20"
        description = "Anthem Hack Deep Panda - Trojan.Kakfum sqlsrv32.dll"
    strings:
        $s0 = "%SystemRoot%\\System32\\svchost.exe -k sqlserver" fullword ascii
        $s1 = "%s\\sqlsrv32.dll" fullword ascii
        $s2 = "%s\\sqlsrv64.dll" fullword ascii
        $s3 = "%s\\%d.tmp" fullword ascii
        $s4 = "ServiceMaix" fullword ascii
        $s15 = "sqlserver" fullword ascii
    condition:
        all of them
}