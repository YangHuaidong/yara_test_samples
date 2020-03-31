rule Trojan_BackDoor_Win32_Farfli_H_20170619115458_911_87 
{
	meta:
		judge = "black"
		threatname = "Trojan[BackDoor]/Win32.Farfli.H"
		threattype = "BackDoor"
		family = "Farfli"
		hacker = "None"
		refer = "0edf087cd0877d810e9f12dc42eef27a"
		description = "None"
		comment = "None"
		author = "cjf"
		date = "2017-06-07"
	strings:
		$s0 = "C:\\Program Files\\AppPatch\\NetSyst96.dll"
		$s1 = "%SystemRoot%\\system32\\services.exe"
		$s2 = "System\\CurrentControlSet\\Services"

	condition:
		all of them
}
