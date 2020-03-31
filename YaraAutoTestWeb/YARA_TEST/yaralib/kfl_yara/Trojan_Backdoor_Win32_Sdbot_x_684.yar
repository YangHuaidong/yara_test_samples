rule Trojan_Backdoor_Win32_Sdbot_x_684
{
    meta:
	    judge = "black"
		threatname = "Trojan[Backdoor]/Win32.Sdbot.x"
		threattype = "Backdoor"
		family = "Sdbot"
		hacker = "None"
		refer = "1aa8049840f7ea8911b78b937c5ee78e"
		author = "xc"
		comment = "None"
		date = "2017-09-14"
		description = "None"
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