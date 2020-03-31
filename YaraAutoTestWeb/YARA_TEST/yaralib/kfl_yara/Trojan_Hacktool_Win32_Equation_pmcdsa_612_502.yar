rule Trojan_Hacktool_Win32_Equation_pmcdsa_612_502
{
    meta:
        judge = "black"
        threatname = "Trojan[Hacktool]/Win32.Equation.pmcdsa"
        threattype = "Hacktool"
        family = "Equation"
        hacker = "None"
        author = "Florian Roth-copy"
        refer = "423e8e8447f954aa7be290ebce22b5be"
        comment = "APT Equation Grou-https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
        date = "2018-08-20"
        description = "Equation Group hack tool set promiscdetect_safe "
	strings:
		$s1 = "running on this computer!" fullword ascii
		$s2 = "- Promiscuous (capture all packets on the network)" fullword ascii
		$s3 = "Active filter for the adapter:" fullword ascii
	condition:
		( uint16(0) == 0x5a4d and filesize < 80KB and all of them )
}