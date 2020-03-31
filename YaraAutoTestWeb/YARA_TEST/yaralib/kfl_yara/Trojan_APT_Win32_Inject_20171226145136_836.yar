rule Trojan_APT_Win32_Inject_20171226145136_836 
{
	meta:
		judge = "black"
		threatname = "Trojan[APT]/Win32.Inject"
		threattype = "APT"
		family = "Inject"
		hacker = "None"
		refer = "fb21f3cea1aa051ba2a45e75d46b98b8"
		description = "None"
		comment = "None"
		author = "xc"
		date = "2017-12-13"
	strings:
		$s0 = "wnuptA" nocase wide ascii
		$s1 = "LaunchWinApp.exe" nocase wide ascii
		$s2 = "fRARZRGRTRRRPR" nocase wide ascii
		$s3 = "AaCcdDeFfGhiKLlMmnNoOpPrRsSTtUuVvwWxyZz32" nocase wide ascii
		$s4 = "iRwRGRZRBRFRPRGR" nocase wide ascii

	condition:
		4 of them
}
