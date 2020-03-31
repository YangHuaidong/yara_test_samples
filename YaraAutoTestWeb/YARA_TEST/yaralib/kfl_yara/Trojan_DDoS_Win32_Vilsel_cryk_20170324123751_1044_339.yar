rule Trojan_DDoS_Win32_Vilsel_cryk_20170324123751_1044_339 
{
	meta:
		judge = "black"
		threatname = "Trojan[DDoS]/Win32.Vilsel.cryk"
		threattype = "DDOS"
		family = "Vilsel"
		hacker = "None"
		refer = "55bf1a9164b15aa8072644e7f0de62e5"
		description = "None"
		comment = "None"
		author = "cjf"
		date = "2017-03-14"
	strings:
		$s0 = "SYSTEM\\CurrentControlSet\\Services\\"
		$s1 = "DbugeFprintf" fullword
		$s2 = "c:\\shg2.txt"
		$s3 = "Protect.exe"

	condition:
		all of them
}
