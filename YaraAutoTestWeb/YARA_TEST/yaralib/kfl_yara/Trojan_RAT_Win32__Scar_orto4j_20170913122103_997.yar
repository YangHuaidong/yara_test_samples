rule Trojan_RAT_Win32__Scar_orto4j_20170913122103_997 
{
	meta:
		judge = "black"
		threatname = "Trojan[RAT]/Win32.Scar.orto4j"
		threattype = "rat"
		family = "Scar"
		hacker = "None"
		refer = "09C488CA9028475F83F8908A0A071FFC"
		description = "None"
		comment = "None"
		author = "copy"
		date = "2017-08-23"
	strings:
		$s0 = "4jNnIiz7AYwRp10" nocase wide ascii
		$s1 = "xepdy0Y2x1" nocase wide ascii
		$s2 = "DHLDAT.dat" nocase wide ascii
		$s3 = "imagehlp.dll" nocase wide ascii

	condition:
		all of them
}
