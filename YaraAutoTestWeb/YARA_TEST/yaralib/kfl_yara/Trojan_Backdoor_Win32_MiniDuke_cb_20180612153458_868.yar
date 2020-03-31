rule Trojan_Backdoor_Win32_MiniDuke_cb_20180612153458_868 
{
	meta:
		judge = "black"
		threatname = "Trojan[Backdoor]/Win32.MiniDuke.cb"
		threattype = "BackDoor"
		family = "MiniDuke"
		hacker = "None"
		refer = "ae7e3e531494b201fbf6021066ddd188"
		description = "None"
		comment = "APT29"
		author = "Florian Roth-copy"
		date = "2018-06-05"
	strings:
		$x0 = "GoogleCrashReport.dll" fullword ascii
		$s1 = "CrashErrors" fullword ascii
		$s2 = "CrashSend" fullword ascii
		$s3 = "CrashAddData" fullword ascii
		$s4 = "CrashCleanup" fullword ascii
		$s5 = "CrashInit" fullword ascii

	condition:
		all of them
}
