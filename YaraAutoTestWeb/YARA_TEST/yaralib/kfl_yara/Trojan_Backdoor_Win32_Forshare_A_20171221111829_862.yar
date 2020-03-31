rule Trojan_Backdoor_Win32_Forshare_A_20171221111829_862 
{
	meta:
		judge = "black"
		threatname = "Trojan[Backdoor]/Win32.Forshare.A"
		threattype = "BackDoor"
		family = "Forshare"
		hacker = "None"
		refer = "b6b68faa706f7740dafd8941c4c5e35a"
		description = "None"
		comment = "None"
		author = "copy"
		date = "2017-09-26"
	strings:
		$s0 = "inWMI" nocase wide ascii
		$s1 = "http://down.mysking.info:8888/ok.txt" nocase wide ascii
		$s2 = "down10.pdb" nocase wide ascii

	condition:
		all of them
}
