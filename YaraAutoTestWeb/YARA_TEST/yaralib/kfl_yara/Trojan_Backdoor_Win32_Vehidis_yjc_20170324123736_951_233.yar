rule Trojan_Backdoor_Win32_Vehidis_yjc_20170324123736_951_233 
{
	meta:
		judge = "black"
		threatname = "Trojan[Backdoor]/Win32.Vehidis.yjc"
		threattype = "BackDoor"
		family = "Vehidis"
		hacker = "None"
		refer = "63261e68830e02fdbc8cd7b63d06c5c9"
		description = "None"
		comment = "None"
		author = "sxy"
		date = "2017-03-16"
	strings:
		$s0 = { d1 f8 bc a6 b3 a1 } //yjc
		$s1 = "URLDownloadToFile"
		$s2 = "urlmon.dll"
		$s3 = "%s\\%c%c%s"
		$s4 = "%O4d%O2d%O2d"

	condition:
		all of them
}
