rule Trojan_BackDoor_Win32_Skeeyah_a_20170324123731_945_206 
{
	meta:
		judge = "black"
		threatname = "Trojan[BackDoor]/Win32.Skeeyah.a"
		threattype = "rat"
		family = "Skeeyah"
		hacker = "None"
		refer = "5261310ea08d35f14ad5833e4c238686"
		description = "None"
		comment = "None"
		author = "cjf"
		date = "2017-03-13"
	strings:
		$s0 = "-create -run"
		$s1 = "update.txt"
		$s2 = "schedule" fullword
		$s3 = "schtasks" fullword
		$s4 = "msinfo.exe"
		$s5 = ".bat"

	condition:
		all of them
}
