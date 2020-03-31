rule Trojan_RAT_Win32_Generic_tyrij_20170811104336_975 
{
	meta:
		judge = "black"
		threatname = "Trojan[RAT]/Win32.Generic.tyrij"
		threattype = "rat"
		family = "Generic"
		hacker = "None"
		refer = "4936e38a73ce07eccf0bb0f0cad2afe9"
		description = "None"
		comment = "None"
		author = "copy"
		date = "2017-07-27"
	strings:
		$s0 = "9PT0vef" nocase wide ascii
		$s1 = "sa+utJ8" nocase wide ascii
		$s2 = "tyrij" nocase wide ascii

	condition:
		all of them
}
