rule Trojan_Backdoor_Win32_Sdbot_x_20170918171442_873 
{
	meta:
		judge = "black"
		threatname = "Trojan[Backdoor]/Win32.Sdbot.x"
		threattype = "BackDoor"
		family = "Sdbot"
		hacker = "None"
		refer = "1aa8049840f7ea8911b78b937c5ee78e"
		description = "None"
		comment = "None"
		author = "xc"
		date = "2017-09-14"
	strings:
		$s0 = "GET %s HTTP/1.1"
		$s1 = "Fuck your"
		$s2 = "drfulqtxct.exe"
		$s3 = "zmcali.exe"
		$s4 = "dnsapi.dll"
		$s5 = "202.168.148.56"

	condition:
		3 of them
}
