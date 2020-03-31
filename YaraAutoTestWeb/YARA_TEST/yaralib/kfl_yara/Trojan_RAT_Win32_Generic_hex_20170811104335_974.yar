rule Trojan_RAT_Win32_Generic_hex_20170811104335_974 
{
	meta:
		judge = "black"
		threatname = "Trojan[RAT]/Win32.Generic.hex"
		threattype = "rat"
		family = "Generic"
		hacker = "none"
		refer = "91e0bac2651d904610368b47d939d273"
		description = "None"
		comment = "none"
		author = "xc"
		date = "2017-07-27"
	strings:
		$s0 = { c1 e9 1d c1 ea 1e 83 e1 01 83 e2 01 c1 e8 1f }
		$s1 = { 83 e8 18 c1 f8 03 c1 e0 0c }
		$s2 = { 83 ee 18 c1 fe 03 c1 e6 0c }

	condition:
		all of them
}
