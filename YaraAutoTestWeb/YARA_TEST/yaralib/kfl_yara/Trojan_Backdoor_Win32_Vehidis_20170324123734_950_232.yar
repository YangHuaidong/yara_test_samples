rule Trojan_Backdoor_Win32_Vehidis_20170324123734_950_232 
{
	meta:
		judge = "black"
		threatname = "Trojan[Backdoor]/Win32.Vehidis"
		threattype = "BackDoor"
		family = "Vehidis"
		hacker = "None"
		refer = "d4e014ff798a4d89deb0b67443ca3d64,31d29fd5a3f7d1bee783b90040712183,c8507143e1d0b181704e81de0022aab6,4d364d7c693f802b911c2f42212a4e1b"
		description = "None"
		comment = "None"
		author = "sxy"
		date = "2017-03-02"
	strings:
		$s0 = "liujunjieshishabi.vbs"
		$s1 = "%c%c%c%c%c%c.exe"
		$s2 = "%-24s %-15s %s"
		$s3 = "RichXy"
		$s4 = "%s\\%c%c%s"
		$s5 = "SeShutdownPrivilege"

	condition:
		4 of them
}
