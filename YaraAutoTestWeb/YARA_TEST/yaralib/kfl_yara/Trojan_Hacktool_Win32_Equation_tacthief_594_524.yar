rule Trojan_Hacktool_Win32_Equation_tacthief_594_524
{
    meta:
        judge = "black"
        threatname = "Trojan[Hacktool]/Win32.Equation.tacthief"
        threattype = "Hacktool"
        family = "Equation"
        hacker = "None"
        author = "Florian Roth-copy"
        refer = "4ca57cd9f1e4d43450c4a9c8549e9c35"
        comment = "APT Equation Grou-https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
        date = "2018-08-13"
        description = "Equation Group hack tool set tacothief "
	strings:
		$x1 = "File too large!  Must be less than 655360 bytes." fullword ascii
	condition:
		( uint16(0) == 0x5a4d and filesize < 100KB and all of them )
}