rule Trojan_Backdoor_Linux_Rekoobe_acp_20171221111814_847 
{
	meta:
		judge = "black"
		threatname = "Trojan[Backdoor]/Linux.Rekoobe.acp"
		threattype = "BackDoor"
		family = "Rekoobe"
		hacker = "None"
		refer = "0f6dda9c32606352db2f35e05bb4b3ed"
		description = "None"
		comment = "None"
		author = "copy"
		date = "2017-10-18"
	strings:
		$s0 = "urHcD$" nocase wide ascii
		$s1 = "unHcD$" nocase wide ascii
		$s2 = "blogtw.winsopt.com" nocase wide ascii
		$s3 = "bpgdhmrn" nocase wide ascii

	condition:
		all of them
}
