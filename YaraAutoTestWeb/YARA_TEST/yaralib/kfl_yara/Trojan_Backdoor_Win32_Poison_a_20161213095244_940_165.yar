rule Trojan_Backdoor_Win32_Poison_a_20161213095244_940_165 
{
	meta:
		judge = "black"
		threatname = "Trojan[Backdoor]/Win32.Poison.a"
		threattype = "rat"
		family = "Poison"
		hacker = "None"
		refer = "0e21b54b9c773c87fe8a478d46d8b810"
		description = "PoisonIvy"
		comment = "None"
		author = "Kevin Breen <kevin@techanarchy.net>"
		date = "2016-06-23"
	strings:
		$s0 = { 04 08 00 53 74 75 62 50 61 74 68 18 04 }
		$s1 = "CONNECT %s:%i HTTP/1.0"
		$s2 = "ws2_32"
		$s3 = "cks=u"
		$s4 = "thj@h"
		$s5 = "advpack"

	condition:
		all of them
}
