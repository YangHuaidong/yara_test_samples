rule Trojan_virus_Win32_Emotet_Service_20170811104350_1000 
{
	meta:
		judge = "black"
		threatname = "Trojan[virus]/Win32.Emotet.service"
		threattype = "virus"
		family = "Emotet"
		hacker = "None"
		refer = "937dd1a1ae435538d97d6a052a2d9e39"
		description = "None"
		comment = "None"
		author = "HuangYY"
		date = "2017-07-24"
	strings:
		$s0 = "setup.exe"
		$s1 = "dfjghsdofg"
		$s2 = "SystemFunction036"
		$s3 = "SunMonTueWedThuFriSat"
		$s4 = "JanFebMarAprMay"

	condition:
		all of them
}
