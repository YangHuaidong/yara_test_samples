rule Trojan_Backdoor_Win32_Zegost_tnqhex_20170811104321_882 
{
	meta:
		judge = "black"
		threatname = "Trojan[Backdoor]/Win32.Zegost.tnqhex"
		threattype = "BackDoor"
		family = "Zegost"
		hacker = "none"
		refer = "973f60be2d029e6601bf113906f4ed8d"
		description = "None"
		comment = "none"
		author = "xc"
		date = "2017-07-27"
	strings:
		$s0 = { 55 8b ec 6a ff 68 40 4e 40 00 }
		$s1 = { 55 8b ec 6a ff 68 50 4e 40 00 }
		$s2 = { 55 8b ec 6a ff 68 30 4e 40 00 }

	condition:
		all of them
}
