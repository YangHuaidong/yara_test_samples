rule Trojan_HackTool_Win32_PassSniffer_aa_1031 
{
	meta:
		judge = "black"
		threatname = "Trojan[HackTool]/Win32.PassSniffer.aa"
		threattype = "HackTool"
		family = "PassSniffer"
		hacker = "None"
		refer = "9570127a32c1cfb0c7b3fe8151333678"
		comment = "None"
		description = "Disclosed hacktool set (old stuff) - file PassSniffer.exe"
		author = "Florian Roth"
		date = "23.11.14"
		
	strings:
		$s2 = "Sniff" fullword ascii
		$s3 = "GetLas" fullword ascii
		$s4 = "VersionExA" fullword ascii
		$s10 = " Only RuntUZ" fullword ascii
		$s12 = "emcpysetprintf\\" fullword ascii
		$s13 = "WSFtartup" fullword ascii
	condition:
		all of them
}