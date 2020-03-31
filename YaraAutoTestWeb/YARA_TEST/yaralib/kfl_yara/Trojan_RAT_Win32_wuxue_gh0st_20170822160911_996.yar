rule Trojan_RAT_Win32_wuxue_gh0st_20170822160911_996 
{
	meta:
		judge = "black"
		threatname = "Trojan[RAT]/Win32.wuxue.gh0st"
		threattype = "rat"
		family = "wuxue"
		hacker = "None"
		refer = "c03016e216f408a8e9f7b18f1c7842fe"
		description = "None"
		comment = "None"
		author = "copy"
		date = "2017-08-05"
	strings:
		$s0 = "hhctrl.ocx" nocase wide ascii
		$s1 = "Apartment" nocase wide ascii
		$s2 = "wSh]h6" nocase wide ascii

	condition:
		all of them
}
