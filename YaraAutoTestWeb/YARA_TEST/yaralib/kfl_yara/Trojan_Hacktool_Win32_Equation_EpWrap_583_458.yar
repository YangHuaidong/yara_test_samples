rule Trojan_Hacktool_Win32_Equation_EpWrap_583_458
{
    meta:
        judge = "black"
        threatname = "Trojan[Hacktool]/Win32.Equation.EpWrap"
        threattype = "Hacktool"
        family = "Equation"
        hacker = "None"
        author = "Florian Roth-copy"
        refer = "6b79e331ad066fce834ce89bca20cc1f"
        comment = "APT Equation Grou-https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
        date = "2018-08-13"
        description = "Equation Group hack tool set EpWrapper "
	strings:
		$x1 = "* Failed to get remote TCP socket address" fullword wide
		$x2 = "* Failed to get 'LPStart' export" fullword wide
		$s5 = "Usage: %ls <logdir> <dll_search_path> <dll_to_load_path> <socket>" fullword wide
	condition:
		( uint16(0) == 0x5a4d and filesize < 20KB and 1 of them )
}