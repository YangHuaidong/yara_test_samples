rule Trojan_Backdoor_Linux_Tsunami_bjcp_20171221111816_848 
{
	meta:
		judge = "black"
		threatname = "Trojan[Backdoor]/Linux.Tsunami.bjcp"
		threattype = "BackDoor"
		family = "Tsunami"
		hacker = "None"
		refer = "1ae0e257adab11486f0063759a4f96b4"
		description = "None"
		comment = "None"
		author = "copy"
		date = "2017-10-18"
	strings:
		$s0 = "xcTCPkh" nocase wide ascii
		$s1 = "OueVC5" nocase wide ascii
		$s2 = "td#JGE-=" nocase wide ascii
		$s3 = "+IBn_q#" nocase wide ascii

	condition:
		all of them
}
