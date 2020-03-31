rule Trojan_RAT_Win32_Siscos_20170717153418_1103_633 
{
	meta:
		judge = "black"
		threatname = "Trojan[RAT]/Win32.Siscos"
		threattype = "rat"
		family = "Siscos"
		hacker = "none"
		refer = "990f61398a90c75ba040eac9372203f4"
		description = "None"
		comment = "none"
		author = "xc"
		date = "2017-07-05"
	strings:
		$s0 = "Abcdef Hijklmno Qrstuvwx Abcd"
		$s1 = "Abcdefgh Jklmnopqr Tuvwxya Cdefghij Lmn"

	condition:
		all of them
}
