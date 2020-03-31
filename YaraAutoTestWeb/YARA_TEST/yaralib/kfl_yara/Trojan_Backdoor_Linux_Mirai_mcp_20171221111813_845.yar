rule Trojan_Backdoor_Linux_Mirai_mcp_20171221111813_845 
{
	meta:
		judge = "black"
		threatname = "Trojan[Backdoor]/Linux.Mirai.mcp"
		threattype = "BackDoor"
		family = "Mirai"
		hacker = "None"
		refer = "0b6e8db940bb262c9b9852c9fd75c435"
		description = "None"
		comment = "None"
		author = "copy"
		date = "2017-10-18"
	strings:
		$s0 = "au!MaD" nocase wide ascii
		$s1 = "&aQdtaJ" nocase wide ascii
		$s2 = "z.nsIvL" nocase wide ascii

	condition:
		all of them
}
