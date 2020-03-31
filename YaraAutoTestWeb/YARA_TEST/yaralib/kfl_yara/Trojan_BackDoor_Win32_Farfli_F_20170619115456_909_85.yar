rule Trojan_BackDoor_Win32_Farfli_F_20170619115456_909_85 
{
	meta:
		judge = "black"
		threatname = "Trojan[BackDoor]/Win32.Farfli.F"
		threattype = "BackDoor"
		family = "Farfli"
		hacker = "None"
		refer = "0e38464ebfb27c90c80c7eb810a7e2e8"
		description = "None"
		comment = "None"
		author = "cjf"
		date = "2017-06-07"
	strings:
		$s0 = "st96.dll"
		$s1 = "http://"
		$s2 = "DOMAIN error"
		$s3 = "SING error"
		$s4 = "ddeexec"

	condition:
		all of them
}
