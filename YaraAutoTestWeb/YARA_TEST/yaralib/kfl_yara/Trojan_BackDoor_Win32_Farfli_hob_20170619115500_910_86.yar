rule Trojan_BackDoor_Win32_Farfli_hob_20170619115500_910_86 
{
	meta:
		judge = "black"
		threatname = "Trojan[BackDoor]/Win32.Farfli.hob"
		threattype = "BackDoor"
		family = "Farfli"
		hacker = "None"
		refer = "07197E9E8B7B28F18673DB6B120657A6"
		description = "None"
		comment = "None"
		author = "cjf"
		date = "2017-06-07"
	strings:
		$s0 = "360sd.exe"
		$s1 = "LastGood.Tmp"
		$s2 = "wscript.exe"
		$s3 = "System\\CurrentControlSet\\Services"
		$s4 = "C:\\Program Files\\Microsoft Aahffa"
		$s5 = "services.exe"

	condition:
		all of them
}
