rule Trojan_Downloader_Win32_Dynamer_ac_20170619115508_1046_351 
{
	meta:
		judge = "black"
		threatname = "Trojan[Downloader]/Win32.Dynamer.ac"
		threattype = "BackDoor"
		family = "Dynamer"
		hacker = "None"
		refer = "2582298d51179ff852b8e0171d64d4df"
		description = "None"
		comment = "None"
		author = "cjf"
		date = "2017-06-07"
	strings:
		$s0 = "C:\\Program Files\\AppPatch\\adminw3.dll"
		$s1 = "%SystemRoot%\\system32\\services.exe"
		$s2 = "DOMAIN error"
		$s3 = "%SystemRoot%\\system32\\lsass.exe"

	condition:
		all of them
}
