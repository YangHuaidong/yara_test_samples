rule Trojan_RAT_Win32_Fsysna_ejis_20171010143040_970 
{
	meta:
		judge = "black"
		threatname = "Trojan[RAT]/Win32.Fsysna.ejis"
		threattype = "rat"
		family = "Fsysna"
		hacker = "None"
		refer = "bc0d5ec760abb0f5455447455cf1e739"
		description = "None"
		comment = "None"
		author = "copy"
		date = "2017-09-21"
	strings:
		$s0 = "/A75BRDzDvkFBdD6D/am" nocase wide ascii
		$s1 = "elklogl" nocase wide ascii
		$s2 = "CDG\tU" nocase wide ascii
		$s3 = "AkkPQj" nocase wide ascii

	condition:
		all of them
}
