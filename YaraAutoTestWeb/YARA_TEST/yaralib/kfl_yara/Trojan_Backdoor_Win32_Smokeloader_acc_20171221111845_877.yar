rule Trojan_Backdoor_Win32_Smokeloader_acc_20171221111845_877 
{
	meta:
		judge = "black"
		threatname = "Trojan[Backdoor]/Win32.Smokeloader.acc"
		threattype = "BackDoor"
		family = "Smokeloader"
		hacker = "None"
		refer = "2fb6b8b2c342f5312684f65575dcf28f"
		description = "None"
		comment = "None"
		author = "copy"
		date = "2017-10-19"
	strings:
		$s0 = "Thresh.bin" nocase wide ascii
		$s1 = "DOS mode." nocase wide ascii
		$s2 = "_adjust_fdiv" nocase wide ascii
		$s3 = "_initterm" nocase wide ascii

	condition:
		all of them
}
