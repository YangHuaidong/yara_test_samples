rule Trojan_RAT_Win32_Boxed_X_20170511162012_1075_599 
{
	meta:
		judge = "black"
		threatname = "Trojan[RAT]/Win32.Boxed.X"
		threattype = "Control"
		family = "Boxed"
		hacker = "None"
		refer = "16de1d33859aa0994e40f8d50415d410"
		description = "None"
		comment = "None"
		author = "ccr"
		date = "2017-05-04"
	strings:
		$s1 = "lsass.exe" nocase
		$s2 = "Services" nocase
		$s3 = "%s\\system\\" nocase
		$s4 = "Mu(xA2" nocase

	condition:
		all of them
}
