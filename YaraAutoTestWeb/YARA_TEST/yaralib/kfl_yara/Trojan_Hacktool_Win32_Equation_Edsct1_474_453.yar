rule Trojan_Hacktool_Win32_Equation_Edsct1_474_453
{
    meta:
        judge = "black"
        threatname = "Trojan[Hacktool]/Win32.Equation.Edsct1"
        threattype = "Hacktool"
        family = "Equation"
        hacker = "None"
        author = "Florian Roth-copy"
        refer = "3d553da33796c8c73ed00b3d9a91e24e"
        comment = "APT Equation Grou-https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
        date = "2018-07-30"
        description = "Equation Group hack tool set EquationGroup_Toolset_Apr17_Educatedscholartouch_1_0_0 "
	strings:
		$x1 = "[!] A vulnerable target will not respond." fullword ascii
		$x2 = "[-] Target NOT Vulernable" fullword ascii
	condition:
		( uint16(0) == 0x5a4d and filesize < 30KB and 1 of them )
}