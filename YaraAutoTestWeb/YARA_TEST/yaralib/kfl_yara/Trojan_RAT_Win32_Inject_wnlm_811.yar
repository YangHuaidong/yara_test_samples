rule Trojan_RAT_Win32_Inject_wnlm_811
{
	meta:
		judge = "black"
		threatname = "Trojan[RAT]/Win32.Inject.wnlm"
		threattype = "RAT"
		family = "Inject"
		hacker = "None"
		refer = "4e47dd0f5aae07d2d56a46a8139e851f"
		author = "HuangYY"
		comment = "None"
		date = "2017-11-10"
		description = "None"

	strings:		
		$s0 = {50 00 6C 00 65 00 61 00 73 00 65 00 20 00 77 00 61 00 69 00 74 00 20 00 77 00 68 00 69 00 6C 00 65 00 20 00 53 00 65 00 74 00 75 00 70 00 20 00 69 00 73 00 20 00 6C 00 6F 00 61 00 64 00 69 00 6E 00 67}
		$s1 = {EF BE AD DE 4E 75 6C 6C 73 6F 66 74 49 6E 73 74 78 19}
		$s2 = "is not set in language table of language"
		$s3 = "http://nsis.sf.net/NSIS_Error"
		$s4 = "Error writing temporary file. Make sure your temp folder is valid"
		$s5 = "%u.%u%s%s"
	condition:
		all of them
}