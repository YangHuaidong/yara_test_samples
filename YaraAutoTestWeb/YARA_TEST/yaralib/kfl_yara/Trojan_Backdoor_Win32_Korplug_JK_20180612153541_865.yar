rule Trojan_Backdoor_Win32_Korplug_JK_20180612153541_865 
{
	meta:
		judge = "black"
		threatname = "Trojan[Backdoor]/Win32.Korplug.JK"
		threattype = "BackDoor"
		family = "Korplug"
		hacker = "None"
		refer = "b3139b26a2dabb9b6e728884d8fa8b33,https://www.us-cert.gov/ncas/alerts/TA17-117A,0f6b00b0c5a26a5aa8942ae356329945"
		description = "None"
		comment = "None"
		author = "copy"
		date = "2018-05-29"
	strings:
		$s0 = {2e 6c 6e 6b [0-14] 61 76 70 75 69 2e 65 78 65}
		$s1 = {b9 1a [0-6] f7 f9 46 80 c2 41 88 54 35 8b 83 fe 64}

	condition:
		any of them
}
