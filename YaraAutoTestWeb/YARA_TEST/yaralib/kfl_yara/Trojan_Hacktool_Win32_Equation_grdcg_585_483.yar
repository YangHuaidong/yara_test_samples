rule Trojan_Hacktool_Win32_Equation_grdcg_585_483
{
    meta:
        judge = "black"
        threatname = "Trojan[Hacktool]/Win32.Equation.grdcg"
        threattype = "Hacktool"
        family = "Equation"
        hacker = "None"
        author = "Florian Roth-copy"
        refer = "733ca167aab618c6fc431a90bac7bd33"
        comment = "APT Equation Grou-https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
        date = "2018-08-13"
        description = "Equation Group hack tool set greatdoc_dll_config "
	strings:
		$x1 = "C:\\Projects\\GREATERDOCTOR\\trunk\\GREATERDOCTOR" ascii
		$x2 = "src\\build\\Release\\dllConfig\\dllConfig.pdb" ascii
		$x3 = "GREATERDOCTOR [ commandline args configuration ]" fullword ascii
		$x4 = "-useage: <scanner> \"<cmdline args>\"" fullword ascii
	condition:
		( uint16(0) == 0x5a4d and filesize < 200KB and 1 of them )
}