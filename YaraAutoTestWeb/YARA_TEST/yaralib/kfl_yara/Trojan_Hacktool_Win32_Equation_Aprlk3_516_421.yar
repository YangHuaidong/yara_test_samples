rule Trojan_Hacktool_Win32_Equation_Aprlk3_516_421
{
    meta:
        judge = "black"
        threatname = "Trojan[Hacktool]/Win32.Equation.Aprlk3"
        threattype = "Hacktool"
        family = "Equation"
        hacker = "None"
        author = "Florian Roth-copy"
        refer = "212665c005dfcb483d4645572c680583"
        comment = "APT Equation Grou-https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
        date = "2018-07-30"
        description = "Equation Group hack tool set April Leak "
	strings:
		$x1 = "[-] The target is NOT vulnerable" fullword ascii
		$x2 = "[+] The target IS VULNERABLE" fullword ascii
	condition:
		( uint16(0) == 0x5a4d and filesize < 50KB and 1 of them )
}