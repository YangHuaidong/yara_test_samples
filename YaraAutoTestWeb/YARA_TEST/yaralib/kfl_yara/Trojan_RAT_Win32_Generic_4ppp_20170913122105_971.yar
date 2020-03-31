rule Trojan_RAT_Win32_Generic_4ppp_20170913122105_971 
{
	meta:
		judge = "black"
		threatname = "Trojan[RAT]/Win32.Generic.4ppp"
		threattype = "rat"
		family = "Generic"
		hacker = "None"
		refer = "279853D58F4DBC23965A60541168AE5B"
		description = "None"
		comment = "None"
		author = "copy"
		date = "2017-08-31"
	strings:
		$s0 = "4P4D4" nocase wide ascii
		$s1 = "PPPPPP" nocase wide ascii
		$s2 = "2U3&5" nocase wide ascii
		$s3 = "50646c6A6" nocase wide ascii

	condition:
		all of them
}
