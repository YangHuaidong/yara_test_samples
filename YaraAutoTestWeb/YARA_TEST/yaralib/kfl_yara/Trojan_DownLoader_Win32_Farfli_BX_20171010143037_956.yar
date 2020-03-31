rule Trojan_DownLoader_Win32_Farfli_BX_20171010143037_956 
{
	meta:
		judge = "black"
		threatname = "Trojan[DownLoader]/Win32.Farfli.BX"
		threattype = "Downloader"
		family = "Farfli"
		hacker = "None"
		refer = "c6353a653fc0abb42a38074d2909ea6b"
		description = "None"
		comment = "None"
		author = "copy"
		date = "2017-09-21"
	strings:
		$s0 = "shlwapi.dll" nocase wide ascii
		$s1 = "%-24s %-15s 0x%x(%d)" nocase wide ascii
		$s2 = "XIAOQI" nocase wide ascii

	condition:
		all of them
}
