rule Trojan_RAT_Win32_DarkComet_1_20161213095216_1077_601 
{
	meta:
		judge = "black"
		threatname = "Trojan[RAT]/Win32.DarkComet.1"
		threattype = "rat"
		family = "DarkComet"
		hacker = "None"
		refer = "430a4c9547582546ea238be55af72236,4fcd5e3d6b619ad574b414951c95a694,8B2014764027634969837C4EFE47FC88"
		description = "DarkComet RAT"
		comment = "None"
		author = "Vi"
		date = "2016-11-22"
	strings:
		$s0 = "#BOT#OpenUrl"
		$s1 = "#BOT#VisitUrl"
		$s2 = "[NUM_LOCK]"
		$s3 = "[ESC]"
		$s4 = "[DEL]"
		$s5 = "\\Internet Explorer\\iexplore.exe"

	condition:
		4 of them
}
