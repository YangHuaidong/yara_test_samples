rule Trojan_Hacktool_Win64_Equation_SharT_598_549
{
    meta:
        judge = "black"
        threatname = "Trojan[Hacktool]/Win64.Equation.SharT"
        threattype = "Hacktool"
        family = "Equation"
        hacker = "None"
        author = "Florian Roth-copy"
        refer = "56d9ef6b2264f824f37544148fca0abc"
        comment = "APT Equation Grou-https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
        date = "2018-08-13"
        description = "Equation Group hack tool set Shares_Target "
	strings:
		$s1 = "Select * from Win32_Share" fullword ascii
		$s2 = "slocalhost" fullword wide
		$s3 = "\\\\%ls\\root\\cimv2" fullword wide
		$s4 = "\\\\%ls\\%ls" fullword ascii
	condition:
		( uint16(0) == 0x5a4d and filesize < 200KB and all of them )
}