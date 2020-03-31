rule Trojan_Hacktool_Win32_Equation_DiTa2_579_441
{
    meta:
        judge = "black"
        threatname = "Trojan[Hacktool]/Win32.Equation.DiTa2"
        threattype = "Hacktool"
        family = "Equation"
        hacker = "None"
        author = "Florian Roth-copy"
        refer = "a995eb4820bd46ab4f6177de4ec7fff8"
        comment = "APT Equation Grou-https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
        date = "2018-08-13"
        description = "Equation Group hack tool set DiBa_Target_2000 "
	strings:
		$s1 = "0M1U1Z1p1" fullword ascii
		$op1 = { f4 65 c6 45 f5 6c c6 45 f6 33 c6 45 f7 32 c6 45 }
		$op2 = { 36 c6 45 e6 34 c6 45 e7 50 c6 45 e8 72 c6 45 e9 }
		$op3 = { c6 45 e8 65 c6 45 e9 70 c6 45 ea 74 c6 45 eb 5f }
	condition:
		( uint16(0) == 0x5a4d and filesize < 1000KB and 3 of them )
}