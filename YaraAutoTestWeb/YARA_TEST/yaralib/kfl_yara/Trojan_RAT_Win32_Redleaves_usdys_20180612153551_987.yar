rule Trojan_RAT_Win32_Redleaves_usdys_20180612153551_987 
{
	meta:
		judge = "black"
		threatname = "Trojan[RAT]/Win32.Redleaves.usdys"
		threattype = "rat"
		family = "Redleaves"
		hacker = "None"
		refer = "https://www.us-cert.gov/ncas/alerts/TA17-117A,fb0c714cd2ebdcc6f33817abe7813c36"
		description = "Detect obfuscated .dat file containing shellcode and core REDLEAVES RAT"
		comment = "None"
		author = "USG-copy"
		date = "2018-05-30"
	strings:
		$s0 = { 73 64 65 5e 60 74 75 74 6c 6f 60 6d 5e 6d 64 60 77 64 72 5e 65 6d 6d 6c 60 68 6f 2f 65 6d 6d }

	condition:
		all of them
}
