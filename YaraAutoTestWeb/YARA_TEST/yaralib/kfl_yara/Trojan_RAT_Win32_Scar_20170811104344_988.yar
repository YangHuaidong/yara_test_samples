rule Trojan_RAT_Win32_Scar_20170811104344_988 
{
	meta:
		judge = "black"
		threatname = "Trojan[RAT]/Win32.Scar"
		threattype = "rat"
		family = "Scar"
		hacker = "None"
		refer = "81e2983169e4bbde5b61e031d3741fe7"
		description = "None"
		comment = "None"
		author = "copy"
		date = "2017-07-27"
	strings:
		$s0 = "Consys21.dll" nocase wide ascii
		$s1 = "SeShutdownPrivilege" nocase wide ascii
		$s2 = "uHdxN" nocase wide ascii
		$s3 = "lstrcmpiA" nocase wide ascii

	condition:
		all of them
}
