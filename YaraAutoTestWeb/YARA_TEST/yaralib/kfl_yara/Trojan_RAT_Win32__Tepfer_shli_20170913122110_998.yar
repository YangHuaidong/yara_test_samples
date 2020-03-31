rule Trojan_RAT_Win32__Tepfer_shli_20170913122110_998 
{
	meta:
		judge = "black"
		threatname = "Trojan[RAT]/Win32.Tepfer.shli"
		threattype = "rat"
		family = "Tepfer"
		hacker = "None"
		refer = "bef104beac03466e3c73761223941c65"
		description = "None"
		comment = "None"
		author = "copy"
		date = "2017-08-23"
	strings:
		$s0 = "stafftest.ru" nocase wide ascii
		$s1 = "hrtests.ru" nocase wide ascii
		$s2 = "libgcj-13.dll" nocase wide ascii
		$s3 = "Photo.scr" nocase wide ascii

	condition:
		all of them
}
