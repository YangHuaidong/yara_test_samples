rule Trojan_Backdoor_Win32_Darkhotel_acw_377_53
{
    meta:
        judge = "black"
        threatname = "Trojan[Backdoor]/Win32.Darkhotel.acw"
        threattype = "Backdoor"
        family = "Darkhotel"
        hacker = "None"
        author = "Florian Roth-copy"
        refer = "4d84720998eb6e358a1671f6eb1ef74e"
        comment = "None"
        date = "2018-06-20"
        description = "Detects sample mentioned in the Dubnium Report"
    strings:
        $x1 = ":*:::D:\\:c:~:" fullword ascii
        $s2 = "SPMUVR" fullword ascii
    condition:
        ( uint16(0) == 0x5a4d and filesize < 2000KB and all of them )
}