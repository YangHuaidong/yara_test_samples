rule Trojan_Hacktool_Win32_Equation_Architouch_467_424
{
    meta:
        judge = "black"
        threatname = "Trojan[Hacktool]/Win32.Equation.Architouch"
        threattype = "Hacktool"
        family = "Equation"
        hacker = "None"
        author = "Florian Roth-copy"
        refer = "30380b78e730efc006216f33fa06964d"
        comment = "APT Equation Grou-https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
        date = "2018-07-30"
        description = "Equation Group hack tool set EquationGroup_Toolset_Apr17_Architouch_1_0_0 "
	strings:
		$s1 = "[+] Target is %s" fullword ascii
	condition:
		( uint16(0) == 0x5a4d and filesize < 300KB and all of them )
}