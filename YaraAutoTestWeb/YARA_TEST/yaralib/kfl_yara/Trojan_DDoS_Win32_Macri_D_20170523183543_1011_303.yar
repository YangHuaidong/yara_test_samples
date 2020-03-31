rule Trojan_DDoS_Win32_Macri_D_20170523183543_1011_303 
{
	meta:
		judge = "black"
		threatname = "Trojan[DDoS]/Win32.Macri.D"
		threattype = "DDOS"
		family = "Macri"
		hacker = "none"
		refer = "029c6903b4419e7fea6046eb793c585c"
		description = "None"
		comment = "none"
		author = "xc"
		date = "2017-05-08"
	strings:
		$s0 = "shsjtfalcds"
		$s1 = "blioha raglkb aukufy sailbiub uvukafbh"
		$s2 = "ialbba yiublb aukvbvuvba ibbbvuybaga"

	condition:
		all of them
}
