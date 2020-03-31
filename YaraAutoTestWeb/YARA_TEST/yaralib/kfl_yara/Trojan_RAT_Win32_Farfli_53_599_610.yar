rule Trojan_RAT_Win32_Farfli_53_599_610
{
	meta:
		judge = "black"
		threatname = "Trojan[RAT]/Win32.Farfli"
		threattype = "RAT"
		family = "Farfli"
		hacker = "None"
		refer = "3d7c74d2093c687192822bf6cba51e36"
		author = "lizhenling"
		comment = "None"
		date = "2018-08-17"
		description = "None"

	strings:		
		$s0 = "%s (%s:%d)"
		$s1 = "HtmlHelpA"
		$s2 = "UnregisterClassA"
		$s3 = "lUnWdP"
		$s4 = "sNDsF0IJ"
		$s5 = "lkdjlUn9"
		$s6 = "sNlsF4"
		$s7 = "OhUn5fUndLoW9"
		
	condition:
		all of them
}