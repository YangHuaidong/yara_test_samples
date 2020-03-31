rule Trojan_DDOS_Win32_BlackNix_Mark_20161213095143_1000_292 
{
	meta:
		judge = "black"
		threatname = "Trojan[DDOS]/Win32.BlackNix.Mark"
		threattype = "DDOS"
		family = "BlackNix"
		hacker = "Mark Adler"
		refer = "910273DB67A93B6077A0050FA04C5328"
		description = "None"
		comment = "None"
		author = " Kevin Breen <kevin@techanarchy.net>"
		date = "2016-06-23"
	strings:
		$a1 = "SETTINGS" wide
		$a2 = "Mark Adler"
		$a3 = "Random-Number-Here"
		$a4 = "RemoteShell"
		$a5 = "SystemInfo"

	condition:
		all of them
}
