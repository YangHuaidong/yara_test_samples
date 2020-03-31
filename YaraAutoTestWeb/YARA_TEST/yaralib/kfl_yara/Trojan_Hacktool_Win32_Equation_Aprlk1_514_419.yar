rule Trojan_Hacktool_Win32_Equation_Aprlk1_514_419
{
    meta:
        judge = "black"
        threatname = "Trojan[Hacktool]/Win32.Equation.Aprlk1"
        threattype = "Hacktool"
        family = "Equation"
        hacker = "None"
        author = "Florian Roth-copy"
        refer = "be8dc61dd7890f8eb4bdc9b1c43e76f7"
        comment = "APT Equation Grou-https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
        date = "2018-07-30"
        description = "Equation Group hack tool set April Leak "
	strings:
		$x1 = "[-] Get RemoteMOFTriggerPath error" fullword ascii
	condition:
		( uint16(0) == 0x5a4d and filesize < 50KB and all of them )
}