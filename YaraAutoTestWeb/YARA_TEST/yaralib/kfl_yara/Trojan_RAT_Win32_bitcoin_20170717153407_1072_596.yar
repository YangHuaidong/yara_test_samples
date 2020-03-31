rule Trojan_RAT_Win32_bitcoin_20170717153407_1072_596 
{
	meta:
		judge = "black"
		threatname = "Trojan[RAT]/Win32.bitcoin"
		threattype = "rat"
		family = "bitcoin"
		hacker = "none"
		refer = "abec8375cc8a45a7d129abca946a4f4e"
		description = "None"
		comment = "none"
		author = "xc"
		date = "2017-07-05"
	strings:
		$s0 = "119.1.109.84"
		$s1 = "nzzpenc"
		$s3 = "wodewakuang"

	condition:
		all of them
}
