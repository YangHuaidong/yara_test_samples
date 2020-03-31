rule Trojan_RAT_Win32_DarkComet_Jean_20161213095222_1083_606 
{
	meta:
		judge = "black"
		threatname = "Trojan[RAT]/Win32.DarkComet.Jean"
		threattype = "rat"
		family = "DarkComet"
		hacker = "None"
		refer = "6dd1647c6493ad02a25895d25a1d4a70"
		description = "DarkComet RAT"
		comment = "None"
		author = "djw, Jean-Philippe Teissier / @Jipe_"
		date = "2016-11-22"
	strings:
		$a = "#BEGIN DARKCOMET DATA --"
		$b = "#EOF DARKCOMET DATA --"
		$c = "DC_MUTEX-"
		$k1 = "#KCMDDC5#-890"
		$k2 = "#KCMDDC51#-890"

	condition:
		any of them
}
