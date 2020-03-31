rule Trojan_Hacktool_Win64_Equation_OraImpl_597_547
{
    meta:
        judge = "black"
        threatname = "Trojan[Hacktool]/Win64.Equation.OraImpl"
        threattype = "Hacktool"
        family = "Equation"
        hacker = "None"
        author = "Florian Roth-copy"
        refer = "68fd8b368863fa7bbc12d6551d25da74"
        comment = "APT Equation Grou-https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
        date = "2018-08-13"
        description = "Equation Group hack tool set Oracle_Implant "
	strings:
		$op0 = { fe ff ff ff 48 89 9c 24 80 21 00 00 48 89 ac 24 }
		$op1 = { e9 34 11 00 00 b8 3e 01 00 00 e9 2a 11 00 00 b8 }
		$op2 = { 48 8b ca e8 bf 84 00 00 4c 8b e0 8d 34 00 44 8d }
	condition:
		( uint16(0) == 0x5a4d and filesize < 500KB and all of them )
}