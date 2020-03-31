rule Worm_Ransomware_Win32_WannaCry_c_1130
{
	meta:
		judge = "black"
		threatname = "Worm[Ransomware]/Win32.WannaCry.c"
		threattype = "ICS,Ransomware"
		family = "WannaCry"
		hacker = "None"
		refer = "db349b97c37d22f5ea1d1841e3c89eb4"
		author = "LiuGuangzhu"
		comment = "None"
		date = "2019-05-10"
		description = "Detection for worm-strain bundle of Wcry, DOublePulsar"
	strings:		
        $cwnry = { 63 2e 77 6e 72 79 }
        $twnry = { 74 2e 77 6e 72 79 }
	condition:
		$cwnry at 262324 and $twnry at 267672 and $cwnry at 284970
}