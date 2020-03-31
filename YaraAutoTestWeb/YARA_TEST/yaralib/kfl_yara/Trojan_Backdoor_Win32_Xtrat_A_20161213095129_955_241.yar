rule Trojan_Backdoor_Win32_Xtrat_A_20161213095129_955_241 
{
	meta:
		judge = "black"
		threatname = "Trojan[Backdoor]/Win32.Xtrat.A"
		threattype = "rat"
		family = "Xtrat"
		hacker = "None"
		refer = "3199172cb1665536dcdf7a74c7f57174"
		description = "Xtrem RAT v3.5"
		comment = "None"
		author = "Jean-Philippe Teissier / @Jipe_"
		date = "2016-11-22"
	strings:
		$a = "XTREME" wide
		$b = "XTREMEBINDER" wide
		$c = "STARTSERVERBUFFER" wide
		$d = "SOFTWARE\\XtremeRAT" wide
		$e = "XTREMEUPDATE" wide
		$f = "XtremeKeylogger" wide
		$g = "myversion|3.5" wide
		$h = "xtreme rat" wide nocase

	condition:
		2 of them
}
