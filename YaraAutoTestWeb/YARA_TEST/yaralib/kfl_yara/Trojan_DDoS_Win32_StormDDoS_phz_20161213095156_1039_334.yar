rule Trojan_DDoS_Win32_StormDDoS_phz_20161213095156_1039_334 
{
	meta:
		judge = "black"
		threatname = "Trojan[DDoS]/Win32.StormDDoS.phz"
		threattype = "DDOS"
		family = "StormDDoS"
		hacker = "none"
		refer = "F28713C64C8BDEC258AAFBADA92F4045,AAFFB155B9E8DD6D54E34015CBD5FA30"
		description = "none"
		comment = "none"
		author = "Mark"
		date = "2016-11-23"
	strings:
		$s0 = "%c%c%c%c%c.exe"
		$s1 = "360tray.exe"
		$s2 = "HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0"
		$s3 = "ast.exe"
		$s4 = "/c del"
		$s5 = "STORMDDOS"

	condition:
		5 of them
}
