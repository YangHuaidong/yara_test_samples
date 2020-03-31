rule Trojan_Hacktool_Win32_Equation_Aprlk4_517_422
{
    meta:
        judge = "black"
        threatname = "Trojan[Hacktool]/Win32.Equation.Aprlk4"
        threattype = "Hacktool"
        family = "Equation"
        hacker = "None"
        author = "Florian Roth-copy"
        refer = "c21b3638c69f76071de9b33362aab22a"
        comment = "APT Equation Grou-https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
        date = "2018-07-30"
        description = "Equation Group hack tool set April Leak "
	strings:
		$x1 = "[-] Are you being redirectect? Need to retarget?" fullword ascii
		$x2 = "[+] IIS Target OS: %s" fullword ascii
	condition:
		( uint16(0) == 0x5a4d and filesize < 60KB and 1 of them )
}