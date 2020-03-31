rule Trojan_Hacktool_Win32_Equation_ReCoLp_613_507
{
    meta:
        judge = "black"
        threatname = "Trojan[Hacktool]/Win32.Equation.ReCoLp"
        threattype = "Hacktool"
        family = "Equation"
        hacker = "None"
        author = "Florian Roth-copy"
        refer = "639b0ad29892892e8750e997b890e296"
        comment = "APT Equation Grou-https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
        date = "2018-08-20"
        description = "Equation Group hack tool set RemoteCommand_Lp "
	strings:
		$s1 = "Failure parsing command from %hs:%u: os=%u plugin=%u" fullword wide
		$s2 = "Unable to get TCP listen port: %08x" fullword wide
	condition:
		( uint16(0) == 0x5a4d and filesize < 200KB and all of them )
}