rule Trojan_Hacktool_Win32_Equation_PCLeyd_644_499
{
    meta:
        judge = "black"
        threatname = "Trojan[Hacktool]/Win32.Equation.PCLeyd"
        threattype = "Hacktool"
        family = "Equation"
        hacker = "None"
        author = "Florian Roth-copy"
        refer = "b91c125ee67eccb5843000fd22be0935"
        comment = "APT Equation Grou-https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
        date = "2018-08-27"
        description = "Equation Group hack tool set PC_Legacy_dll "
	strings:
		$op1 = { 45 f4 65 c6 45 f5 6c c6 45 f6 33 c6 45 f7 32 c6 }
		$op2 = { 49 c6 45 e1 73 c6 45 e2 57 c6 45 e3 }
		$op3 = { 34 c6 45 e7 50 c6 45 e8 72 c6 45 e9 6f c6 45 ea }
	condition:
		( uint16(0) == 0x5a4d and filesize < 200KB and all of them )
}	