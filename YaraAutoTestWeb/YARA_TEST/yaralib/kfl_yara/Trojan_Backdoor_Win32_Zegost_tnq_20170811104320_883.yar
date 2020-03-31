rule Trojan_Backdoor_Win32_Zegost_tnq_20170811104320_883 
{
	meta:
		judge = "black"
		threatname = "Trojan[Backdoor]/Win32.Zegost.tnq"
		threattype = "BackDoor"
		family = "Zegost"
		hacker = "None"
		refer = "973f60be2d029e6601bf113906f4ed8d"
		description = "None"
		comment = "None"
		author = "copy"
		date = "2017-07-27"
	strings:
		$s0 = "AemaNyeKecivreSteG" nocase wide ascii
		$s1 = "SeRestorePrivilege" nocase wide ascii
		$s2 = "SeBackupPrivilege" nocase wide ascii

	condition:
		all of them
}
