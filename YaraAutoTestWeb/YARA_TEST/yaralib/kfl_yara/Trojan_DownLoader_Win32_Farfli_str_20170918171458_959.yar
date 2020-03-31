rule Trojan_DownLoader_Win32_Farfli_str_20170918171458_959 
{
	meta:
		judge = "black"
		threatname = "Trojan[DownLoader]/Win32.Farfli.str"
		threattype = "Downloader"
		family = "Farfli"
		hacker = "None"
		refer = "69ECBFD76981A656651D617A44F78732"
		description = "None"
		comment = "None"
		author = "copy"
		date = "2017-09-07"
	strings:
		$s0 = "G3Tmv" nocase wide ascii
		$s1 = "QDPhB" nocase wide ascii
		$s2 = "6zeOb" nocase wide ascii
		$s3 = "43yJD" nocase wide ascii

	condition:
		all of them
}
