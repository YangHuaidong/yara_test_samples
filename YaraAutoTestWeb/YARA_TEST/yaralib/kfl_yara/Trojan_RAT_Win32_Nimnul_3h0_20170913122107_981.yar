rule Trojan_RAT_Win32_Nimnul_3h0_20170913122107_981 
{
	meta:
		judge = "black"
		threatname = "Trojan[RAT]/Win32.Nimnul.3h0"
		threattype = "rat"
		family = "Nimnul"
		hacker = "None"
		refer = "7DFF3108E697A7218ED5B0A5B8C7B16B"
		description = "None"
		comment = "None"
		author = "copy"
		date = "2017-08-31"
	strings:
		$s0 = "3F0DPW" nocase wide ascii
		$s1 = "hVYFZDj3" nocase wide ascii
		$s2 = "02KtLv" nocase wide ascii

	condition:
		all of them
}
