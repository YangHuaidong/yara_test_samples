rule Trojan_Hacktool_Win32_Equation_Aretesmb_518_425
{
    meta:
        judge = "black"
        threatname = "Trojan[Hacktool]/Win32.Equation.Aretesmb"
        threattype = "Hacktool"
        family = "Equation"
        hacker = "None"
        author = "Florian Roth-copy"
        refer = "30380b78e730efc006216f33fa06964d,2a8d437f0b9ffac482750fe052223c3d,b50fff074764b3a29a00b245e4d0c863"
        comment = "APT Equation Grou-https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
        date = "2018-07-30"
        description = "Equation Group hack tool set Architouch_Eternalsynergy_Smbtouch "
	strings:
		$s1 = "NtErrorMoreProcessingRequired" fullword ascii
		$s2 = "Command Format Error: Error=%x" fullword ascii
		$s3 = "NtErrorPasswordRestriction" fullword ascii
		$op0 = { 8a 85 58 ff ff ff 88 43 4d }
	condition:
		( uint16(0) == 0x5a4d and filesize < 600KB and 2 of them )
}