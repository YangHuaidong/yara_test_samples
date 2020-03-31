rule Trojan_Backdoor_Win32_Miancha_Sym_20171221111836_867 
{
	meta:
		judge = "black"
		threatname = "Trojan[Backdoor]/Win32.Miancha.Sym"
		threattype = "BackDoor"
		family = "Miancha"
		hacker = "None"
		refer = "03f0b6bd148155d1ed74dda7634fb4e2"
		description = "None"
		comment = "None"
		author = "copy"
		date = "2017-11-23"
	strings:
		$s0 = "SSSf.A" nocase wide ascii
		$s1 = ">YrCh" nocase wide ascii
		$s2 = "E2SN" nocase wide ascii
		$s3 = "E:SNd" nocase wide ascii

	condition:
		all of them
}
