rule Trojan_Win32_Kbot_vkb_20161213095307_1114_654 
{
	meta:
		judge = "black"
		threatname = "Trojan/Win32.Kbot.vkb"
		threattype = "RAT|DDOS"
		family = "Kbot"
		hacker = "bf1@sitematrix.com"
		refer = "6C349EA18B1606F7E25266EDD7DFFFD4,D4483F3368EC0444A55FDFC2B09C2649"
		description = "None"
		comment = "None"
		author = "Mark"
		date = "2016-06-14"
	strings:
		$s0 = "svchost.exe"
		$s1 = "mssrv32.exe"
		$s2 = "SYSTEM\\CurrentControlSet\\Services\\msupdate"
		$s3 = "id=%s&build_id=%s"
		$s4 = "{F3532CE1-0832-11B1-920A-25000A276A73}"
		$s5 = "aHR0cDovL25vbmFtZS5zdHJlZXQtaW5mby5jb20vc3RhdC5waHD"

	condition:
		5 of them
}
