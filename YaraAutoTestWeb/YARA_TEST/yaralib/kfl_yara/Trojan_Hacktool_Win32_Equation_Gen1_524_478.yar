rule Trojan_Hacktool_Win32_Equation_Gen1_524_478
{
    meta:
        judge = "black"
        threatname = "Trojan[Hacktool]/Win32.Equation.Gen1"
        threattype = "Hacktool"
        family = "Equation"
        hacker = "None"
        author = "Florian Roth-copy"
        refer = "ba59818d0d3d3cac0979303e62e6bd7f,753b80a4615f355a0666daa0b359f5c4"
        comment = "APT Equation Grou-https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
        date = "2018-07-30"
        description = "Equation Group hack tool set Gen1 "
	strings:
		$x1 = "Restart with the new protocol, address, and port as target." fullword ascii
		$x2 = "TargetPort      : %s (%u)" fullword ascii
		$x3 = "Error: strchr() could not find '@' in account name." fullword ascii
		$x4 = "TargetAcctPwd   : %s" fullword ascii
		$x5 = "Creating CURL connection handle..." fullword ascii
	condition:
		( uint16(0) == 0x5a4d and filesize < 80KB and 1 of them )
}