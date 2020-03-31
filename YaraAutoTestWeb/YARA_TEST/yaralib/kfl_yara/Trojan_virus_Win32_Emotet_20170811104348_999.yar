rule Trojan_virus_Win32_Emotet_20170811104348_999 
{
	meta:
		judge = "black"
		threatname = "Trojan[virus]/Win32.Emotet"
		threattype = "virus"
		family = "Emotet"
		hacker = "None"
		refer = "e6706149cb29a70497c23976c756547f"
		description = "None"
		comment = "None"
		author = "HuangYY"
		date = "2017-07-24"
	strings:
		$s0 = "sfxrar.pdb"
		$s1 = "WINRAR.SFX"
		$s2 = "service.exe"
		$s3 = "bypass.exe"
		$s4 = "JanFebMarAprMay"

	condition:
		all of them
}
