rule Trojan_DownLoader_Win32_Mikey_getip_20170918171500_960 
{
	meta:
		judge = "black"
		threatname = "Trojan[DownLoader]/Win32.Mikey.getip"
		threattype = "Downloader"
		family = "Mikey"
		hacker = "None"
		refer = "D4998D95D2AE950F668FBD70EBA3EBC1"
		description = "None"
		comment = "None"
		author = "copy"
		date = "2017-09-07"
	strings:
		$s0 = "183.60.204.58" nocase wide ascii
		$s1 = "-64OS" nocase wide ascii

	condition:
		all of them
}
