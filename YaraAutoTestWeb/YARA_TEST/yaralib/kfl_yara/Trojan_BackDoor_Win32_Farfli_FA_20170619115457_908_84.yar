rule Trojan_BackDoor_Win32_Farfli_FA_20170619115457_908_84 
{
	meta:
		judge = "black"
		threatname = "Trojan[BackDoor]/Win32.Farfli.FA"
		threattype = "BackDoor"
		family = "Farfli"
		hacker = "None"
		refer = "316615fd3c8cbc17a7b79e6887b910fe"
		description = "None"
		comment = "None"
		author = "cjf"
		date = "2017-06-07"
	strings:
		$s0 = "NetSyst96.dll"
		$s1 = "%SystemRoot%\\system32\\services.exe"
		$s2 = "System\\CurrentControlSet\\Services"
		$s3 = "ZhuDongFangYu"

	condition:
		all of them
}
