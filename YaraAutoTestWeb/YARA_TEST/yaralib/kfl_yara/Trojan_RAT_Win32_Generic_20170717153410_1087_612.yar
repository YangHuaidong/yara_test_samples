rule Trojan_RAT_Win32_Generic_20170717153410_1087_612 
{
	meta:
		judge = "black"
		threatname = "Trojan[rat]/Win32.Generic"
		threattype = "rat"
		family = "Generic"
		hacker = "none"
		refer = "d10d6d2a29dd27b44e015dd6bf4cb346"
		description = "None"
		comment = "none"
		author = "xc"
		date = "2017-07-05"
	strings:
		$s1 = "123qweasd"
		$s2 = "\\\\%s\\F$\\hackshen.exe"

	condition:
		all of them
}
