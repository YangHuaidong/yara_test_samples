rule Trojan_DownLoader_Win32_Farfli_bcp_20170918171457_955 
{
	meta:
		judge = "black"
		threatname = "Trojan[DownLoader]/Win32.Farfli.bcp"
		threattype = "Downloader"
		family = "Farfli"
		hacker = "None"
		refer = "246a5b03a49fe931650808e5cd9f943d"
		description = "None"
		comment = "None"
		author = "copy"
		date = "2017-09-14"
	strings:
		$s0 = "SRDSL" nocase wide ascii
		$s1 = "~MHz" nocase wide ascii
		$s2 = "%s\\%d.bak" nocase wide ascii
		$s3 = "WinSta0\\Default" nocase wide ascii

	condition:
		all of them
}
