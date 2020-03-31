rule Trojan_Hacktool_Win32_Equation_DmGzTa_580_443
{
    meta:
        judge = "black"
        threatname = "Trojan[Hacktool]/Win32.Equation.DmGzTa"
        threattype = "Hacktool"
        family = "Equation"
        hacker = "None"
        author = "Florian Roth-copy"
        refer = "b109e373a62660396d9214d2f2307b57"
        comment = "APT Equation Grou-https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
        date = "2018-08-13"
        description = "Equation Group hack tool set DmGz_Target "
	strings:
		$s1 = "\\\\.\\%ls" fullword ascii
		$s3 = "6\"6<6C6H6M6Z6f6t6" fullword ascii
	condition:
		( uint16(0) == 0x5a4d and filesize < 80KB and all of them )
}