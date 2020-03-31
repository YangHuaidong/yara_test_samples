rule Trojan_Hacktool_Win64_Equation_DLoadTa_596_546
{
    meta:
        judge = "black"
        threatname = "Trojan[Hacktool]/Win64.Equation.DLoadTa"
        threattype = "Hacktool"
        family = "Equation"
        hacker = "None"
        author = "Florian Roth-copy"
        refer = "84893511250e6f787bbdd8b4c3327706"
        comment = "APT Equation Grou-https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
        date = "2018-08-13"
        description = "Equation Group hack tool set DllLoad_Target "
	strings:
		$s1 = "BzWKJD+" fullword ascii
		$op1 = { 44 24 6c 6c 88 5c 24 6d }
		$op2 = { 44 24 54 63 c6 44 24 55 74 c6 44 24 56 69 }
		$op3 = { 44 24 5c 6c c6 44 24 5d 65 c6 44 24 5e }
	condition:
		( uint16(0) == 0x5a4d and filesize < 200KB and all of them )
}