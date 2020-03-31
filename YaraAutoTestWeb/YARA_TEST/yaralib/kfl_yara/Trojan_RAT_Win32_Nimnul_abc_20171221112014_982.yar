rule Trojan_RAT_Win32_Nimnul_abc_20171221112014_982 
{
	meta:
		judge = "black"
		threatname = "Trojan[RAT]/Win32.Nimnul.abc"
		threattype = "rat"
		family = "Nimnul"
		hacker = "None"
		refer = "032f59126e7f3aab35dde599ddea8113"
		description = "None"
		comment = "None"
		author = "copy"
		date = "2017-11-23"
	strings:
		$s0 = "d5YRV" nocase wide ascii
		$s1 = "ddq!j" nocase wide ascii
		$s2 = "ss32." nocase wide ascii
		$s3 = "strupr" nocase wide ascii

	condition:
		all of them
}
