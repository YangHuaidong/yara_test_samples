rule Trojan_Backdoor_Win32_Skeeyah_b_20170324123733_946_207 
{
	meta:
		judge = "black"
		threatname = "Trojan[Backdoor]/Win32.Skeeyah.b"
		threattype = "rat"
		family = "Skeeyah"
		hacker = "None"
		refer = "cea583d8fde865d65969d6b9306cd533"
		description = "None"
		comment = "None"
		author = "cjf"
		date = "2017-03-13"
	strings:
		$s0 = "jellyboot.vbs" fullword
		$s1 = "jellydll.dll" fullword
		$s2 = "CMD /C DEL"
		$s3 = "Test..."

	condition:
		all of them
}
