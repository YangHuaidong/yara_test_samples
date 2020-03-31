rule Trojan_Hacktool_Win32_Equation_Emsism_521_457
{
    meta:
        judge = "black"
        threatname = "Trojan[Hacktool]/Win32.Equation.Emsism"
        threattype = "Hacktool"
        family = "Equation"
        hacker = "None"
        author = "Florian Roth-copy"
        refer = "76237984993d5bae7779a1c3fbe2aac2,84986365e9dfbde4fdd80c0e7481354f"
        comment = "APT Equation Grou-https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
        date = "2018-07-30"
        description = "Equation Group hack tool set Emphasismine "
	strings:
		$x1 = "Error: Could not calloc() for shellcode buffer" fullword ascii
		$x2 = "shellcodeSize: 0x%04X + 0x%04X + 0x%04X = 0x%04X" fullword ascii
		$x3 = "Generating shellcode" fullword ascii
		$x4 = "([0-9a-zA-Z]+) OK LOGOUT completed" fullword ascii
		$x5 = "Error: Domino is not the expected version. (%s, %s)" fullword ascii
	condition:
		( uint16(0) == 0x5a4d and filesize < 100KB and 1 of them )
}