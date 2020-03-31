rule Torjan_DDOS_Win32_Darkddoser_20170407172741_889_4 
{
	meta:
		judge = "black"
		threatname = "Trojan[DDOS]/Win32.Darkdoser"
		threattype = "DDOS"
		family = "Darkdoser"
		hacker = "None"
		refer = "53bc9ef63b83a8ff8963ade1807be787,a808ff8898799ed225385b2ac7cb93b0,d059e4d3697f1d725ef2028a5f1a1782,9b88be88bc3a85d2f4a85dfa11ea3968"
		description = "None"
		comment = "None"
		author = "ccr"
		date = "2017-03-20"
	strings:
		$s0 = "STATUS|Flooding: UDP!" nocase
		$s1 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" nocase
		$s2 = "darkddoser" nocase
		$s3 = "ADDNEW" nocase

	condition:
		($s0 and $s1 and $s3)or $s2
}
