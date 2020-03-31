rule Trojan_RAT_Win32_Zegost_20170717153413_1105_636 
{
	meta:
		judge = "black"
		threatname = "Trojan[RAT]/Win32.Zegost"
		threattype = "rat"
		family = "Zegost"
		hacker = "none"
		refer = "9a996229f9c8f0ff4c371b6974ec47f6"
		description = "None"
		comment = "none"
		author = "xc"
		date = "2017-07-05"
	strings:
		$s0 = "107.150.2.19"
		$s1 = "DJX UP"

	condition:
		all of them
}
