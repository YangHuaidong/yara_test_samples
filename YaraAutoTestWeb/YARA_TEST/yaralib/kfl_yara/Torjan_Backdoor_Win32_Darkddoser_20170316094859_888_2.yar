rule Torjan_Backdoor_Win32_Darkddoser_20170316094859_888_2 
{
	meta:
		judge = "black"
		threatname = "Trojan[Backdoor]/Win32.Darkdoser"
		threattype = "BackDoor"
		family = "Darkdoser"
		hacker = "None"
		refer = "53bc9ef63b83a8ff8963ade1807be787,a808ff8898799ed225385b2ac7cb93b0"
		description = "None"
		comment = "None"
		author = "ccr"
		date = "2017-02-28"
	strings:
		$s0 = "STATUS|Flooding: UDP!" nocase wide ascii
		$s1 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" nocase wide ascii
		$s2 = "darkddoser" nocase wide ascii

	condition:
		$s0 and $s1 or $s2
}
