rule Trojan_Backdoor_Win32_Sofacy_jwshghj_680_212
{
    meta:
        judge = "black"
        threatname = "Trojan[Backdoor]/Win32.Sofacy.jwshghj"
        threattype = "backdoor"
        family = "Sofacy"
        hacker = "None"
        author = "balala"
        refer = "52c643f21b409ccd6b0d74901de76447"
        comment = "None"
        date = "2018-08-30"
        description = "None"
	strings:
        $s1 = "clconfg.dll" fullword ascii
        $s2 = "ASijnoKGszdpodPPiaoaghj8127391" fullword wide

    condition:
        ( uint16(0) == 0x5a4d and filesize < 200KB and ( 1 of ($s*) ) ) or ( all of them )

}