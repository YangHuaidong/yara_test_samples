rule Trojan_BackDoor_Win32_Zegost_Q_20170619115501_960_246 
{
	meta:
		judge = "black"
		threatname = "Trojan[BackDoor]/Win32.Zegost.Q"
		threattype = "BackDoor"
		family = "Zegost"
		hacker = "None"
		refer = "0afa86234c4d4f54e4c96d08005ed1e8"
		description = "None"
		comment = "None"
		author = "cjf"
		date = "2017-06-07"
	strings:
		$s0 = "System\\CurrentControlSet\\Services"
		$s1 = "lsass.exe"
		$s2 = "CNetSyst96"
		$s3 = "%SystemRoot%\\system32\\services.exe"
		$s4 = "\\Registry\\Machine\\System\\CurrentControlSet\\Control\\SecurePipeServers\\"

	condition:
		all of them
}
