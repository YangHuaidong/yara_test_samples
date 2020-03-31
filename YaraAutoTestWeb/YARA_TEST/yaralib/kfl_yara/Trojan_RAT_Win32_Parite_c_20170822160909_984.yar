rule Trojan_RAT_Win32_Parite_c_20170822160909_984 
{
	meta:
		judge = "black"
		threatname = "Trojan[RAT]/Win32.Parite.c"
		threattype = "rat"
		family = "Parite"
		hacker = "None"
		refer = "b95a4b0d4f7c1a193817c70592d29164"
		description = "None"
		comment = "None"
		author = "copy"
		date = "2017-08-04"
	strings:
		$s0 = "Marlett" nocase wide ascii
		$s1 = "O316EQ" nocase wide ascii
		$s2 = "msctls_statusbar32" nocase wide ascii

	condition:
		all of them
}
