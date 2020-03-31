rule Trojan_Hacktool_Win32_Equation_ProTat_588_504
{
    meta:
        judge = "black"
        threatname = "Trojan[Hacktool]/Win32.Equation.ProTat"
        threattype = "Hacktool"
        family = "Equation"
        hacker = "None"
        author = "Florian Roth-copy"
        refer = "331cc20baaa5678a98c219d0f5256b49"
        comment = "APT Equation Grou-https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
        date = "2018-08-13"
        description = "Equation Group hack tool set Processes_Target "
	strings:
		$s1 = "Select * from Win32_Process" fullword ascii
		$s3 = "\\\\%ls\\root\\cimv2" fullword wide
		$s5 = "%4ls%2ls%2ls%2ls%2ls%2ls.%11l[0-9]%1l[+-]%6s" fullword wide
	condition:
		( uint16(0) == 0x5a4d and filesize < 200KB and 2 of them )
}