rule Trojan_Backdoor_Win32_Zegost_cbot_20171010143033_881 
{
	meta:
		judge = "black"
		threatname = "Trojan[Backdoor]/Win32.Zegost.cbot"
		threattype = "BackDoor"
		family = "Zegost"
		hacker = "None"
		refer = "8a0a5af0eb1b1605fabf54df9a299169"
		description = "None"
		comment = "None"
		author = "copy"
		date = "2017-09-21"
	strings:
		$s0 = "fMJ9V" nocase wide ascii
		$s1 = "pv:f7b" nocase wide ascii

	condition:
		all of them
}
