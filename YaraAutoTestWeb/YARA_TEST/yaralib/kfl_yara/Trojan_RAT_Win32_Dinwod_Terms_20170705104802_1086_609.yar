rule Trojan_RAT_Win32_Dinwod_Terms_20170705104802_1086_609 
{
	meta:
		judge = "black"
		threatname = "Trojan[RAT]/Win32.Dinwod.Terms"
		threattype = "rat"
		family = "Dinwod"
		hacker = "none"
		refer = "cf80f52ef678cc9b48009cdf0681823c"
		description = "None"
		comment = "none"
		author = "xc"
		date = "2017-06-29"
	strings:
		$s0 = "Terms.exe"
		$s1 = "a7461960"

	condition:
		all of them
}
