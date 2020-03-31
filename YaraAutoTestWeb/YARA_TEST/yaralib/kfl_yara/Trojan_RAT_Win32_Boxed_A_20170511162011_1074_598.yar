rule Trojan_RAT_Win32_Boxed_A_20170511162011_1074_598 
{
	meta:
		judge = "black"
		threatname = "Trojan[RAT]/Win32.Boxed.A"
		threattype = "Control"
		family = "Boxed"
		hacker = "None"
		refer = "1af50a24180cbfd90bf5d34139a3acd0"
		description = "None"
		comment = "None"
		author = "ccr"
		date = "2017-05-04"
	strings:
		$s1 = "lassa.exe" nocase
		$s2 = "%s\\system\\" nocase
		$s3 = "NICK %s" nocase
		$s4 = "host:" nocase

	condition:
		all of them
}
