rule Trojan_Hacktool_Win32_Equation_Emade1_520_456
{
    meta:
        judge = "black"
        threatname = "Trojan[Hacktool]/Win32.Equation.Emade1"
        threattype = "Hacktool"
        family = "Equation"
        hacker = "None"
        author = "Florian Roth-copy"
        refer = "305a1577298d2ca68918c3840fccc958"
        comment = "APT Equation Grou-https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
        date = "2018-07-30"
        description = "Equation Group hack tool set Englishmansdentist_1_2_0 "
	strings:
		$x1 = "[+] CheckCredentials(): Checking to see if valid username/password" fullword ascii
		$x2 = "Error connecting to target, TbMakeSocket() %s:%d." fullword ascii
	condition:
		( uint16(0) == 0x5a4d and filesize < 200KB and 1 of them )
}