rule Trojan_RAT_Win32_Inject_wnlm_20171221112012_976 
{
	meta:
		judge = "black"
		threatname = "Trojan[RAT]/Win32.Inject.wnlm"
		threattype = "rat"
		family = "Inject"
		hacker = "None"
		refer = "4e47dd0f5aae07d2d56a46a8139e851f"
		description = "None"
		comment = "None"
		author = "HuangYY"
		date = "2017-11-10"
	strings:
		$s0 = { 50 00 6c 00 65 00 61 00 73 00 65 00 20 00 77 00 61 00 69 00 74 00 20 00 77 00 68 00 69 00 6c 00 65 00 20 00 53 00 65 00 74 00 75 00 70 00 20 00 69 00 73 00 20 00 6c 00 6f 00 61 00 64 00 69 00 6e 00 67 }
		$s1 = { ef be ad de 4e 75 6c 6c 73 6f 66 74 49 6e 73 74 78 19 }
		$s2 = "is not set in language table of language"
		$s3 = "http://nsis.sf.net/NSIS_Error"
		$s4 = "Error writing temporary file. Make sure your temp folder is valid"
		$s5 = "%u.%u%s%s"

	condition:
		all of them
}
