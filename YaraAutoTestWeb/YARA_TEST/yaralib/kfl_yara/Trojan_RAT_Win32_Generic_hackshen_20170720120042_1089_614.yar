rule Trojan_RAT_Win32_Generic_hackshen_20170720120042_1089_614 
{
	meta:
		judge = "black"
		threatname = "Trojan[RAT]/Win32.Generic.hackshen"
		threattype = "rat"
		family = "Generic"
		hacker = "none"
		refer = "d10d6d2a29dd27b44e015dd6bf4cb346"
		description = "None"
		comment = "none"
		author = "xc"
		date = "2017-07-14"
	strings:
		$s0 = "\\\\%s\\admin$\\hackshen.exe"
		$s1 = "\\\\%s\\C$\\hackshen.exe"

	condition:
		all of them
}
