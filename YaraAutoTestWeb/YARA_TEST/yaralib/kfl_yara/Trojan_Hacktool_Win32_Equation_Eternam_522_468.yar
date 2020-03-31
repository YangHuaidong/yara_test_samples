rule Trojan_Hacktool_Win32_Equation_Eternam_522_468
{
    meta:
        judge = "black"
        threatname = "Trojan[Hacktool]/Win32.Equation.Eternam"
        threattype = "Hacktool"
        family = "Equation"
        hacker = "None"
        author = "Florian Roth-copy"
        refer = "8d3ffa58cb0dc684c9c1d059a154cf43,4420f8917dc320a78d2ef14136032f69"
        comment = "APT Equation Grou-https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
        date = "2018-07-30"
        description = "Equation Group hack tool set Eternalromance "
	strings:
		$x1 = "[-] Error: Exploit choice not supported for target OS!!" fullword ascii
		$x2 = "Error: Target machine out of NPP memory (VERY BAD!!) - Backdoor removed" fullword ascii
		$x3 = "[-] Error: Backdoor not present on target" fullword ascii
		$x4 = "***********    TARGET ARCHITECTURE IS X64    ************" fullword ascii
	condition:
		( uint16(0) == 0x5a4d and filesize < 200KB and 1 of them ) or 2 of them
}