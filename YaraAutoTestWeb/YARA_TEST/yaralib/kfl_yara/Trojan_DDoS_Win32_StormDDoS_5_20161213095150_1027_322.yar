rule Trojan_DDoS_Win32_StormDDoS_5_20161213095150_1027_322 
{
	meta:
		judge = "black"
		threatname = "Trojan[DDoS]/Win32.StormDDoS.5"
		threattype = "DDOS"
		family = "StormDDoS"
		hacker = "None"
		refer = "72363EBC436462A268F2C54A37080362"
		description = "gyDDos"
		comment = "None"
		author = "Mark"
		date = "2016-06-23"
	strings:
		$s0 = "%c%c%c%c%ccn.exe"
		$s1 = "hra%u.dll"
		$s2 = "HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0"
		$s3 = "g1fd.exe"
		$s4 = "/c del"

	condition:
		4 of them
}
