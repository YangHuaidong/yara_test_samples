rule Trojan_RAT_Win32_DarkComet_2_20161213095217_1078_602 
{
	meta:
		judge = "black"
		threatname = "Trojan[RAT]/Win32.DarkComet.2"
		threattype = "rat"
		family = "DarkComet"
		hacker = "None"
		refer = "430a4c9547582546ea238be55af72236,4fcd5e3d6b619ad574b414951c95a694,8B2014764027634969837C4EFE47FC88"
		description = "DarkComet RAT"
		comment = "None"
		author = "Kevin Breen <kevin@techanarchy.net>"
		date = "2016-11-22"
	strings:
		$a1 = "#BOT#URLUpdate"
		$a2 = "Command successfully executed!"
		$a3 = "MUTEXNAME" wide
		$a4 = "NETDATA" wide
		$b1 = "FastMM Borland Edition"
		$b2 = "%s, ClassID: %s"
		$b3 = "I wasn't able to open the hosts file"
		$b4 = "#BOT#VisitUrl"
		$b5 = "#KCMDDC"

	condition:
		all of ($a*) or all of ($b*)
}
