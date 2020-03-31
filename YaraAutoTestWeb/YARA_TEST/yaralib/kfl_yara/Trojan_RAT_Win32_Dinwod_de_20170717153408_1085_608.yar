rule Trojan_RAT_Win32_Dinwod_de_20170717153408_1085_608 
{
	meta:
		judge = "black"
		threatname = "Trojan[RAT]/Win32.Dinwod.de"
		threattype = "rat"
		family = "Dinwod"
		hacker = "none"
		refer = "bd1e287ad208ae2e4582aa14505f356f"
		description = "None"
		comment = "none"
		author = "xc"
		date = "2017-07-06"
	strings:
		$s0 = "yonghu='%s' AND mima='%s'"
		$s1 = "Defghij.exe"

	condition:
		all of them
}
