rule Trojan_Hacktool_Win32_Equation_Aprlk_513_423
{
    meta:
        judge = "black"
        threatname = "Trojan[Hacktool]/Win32.Equation.Aprlk"
        threattype = "Hacktool"
        family = "Equation"
        hacker = "None"
        author = "Florian Roth-copy"
        refer = "a788c1b34f4487e26135572cbedb4c6f"
        comment = "APT Equation Grou-https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
        date = "2018-07-30"
        description = "Equation Group hack tool set April Leak "
	strings:
		$x1 = "[*] Failed to detect OS / Service Pack on %s:%d" fullword ascii
		$x2 = "[*] SMB String: %s (%s)" fullword ascii
	condition:
		( uint16(0) == 0x5a4d and filesize < 80KB and 1 of them )
}