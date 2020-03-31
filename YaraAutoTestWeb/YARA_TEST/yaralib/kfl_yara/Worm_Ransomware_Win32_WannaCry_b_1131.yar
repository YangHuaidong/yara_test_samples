rule Worm_Ransomware_Win32_WannaCry_b_1131
{
	meta:
		judge = "black"
		threatname = "Worm[Ransomware]/Win32.WannaCry.b"
		threattype = "ICS,Ransomware"
		family = "WannaCry"
		hacker = "None"
		refer = "4da1f312a214c07143abeeafb695d904"
		author = "LiuGuangzhu"
		comment = "None"
		date = "2019-05-10"
		description = "Specific sample match for WannaCryptor"
	strings:		
        $rwnry = { 72 2e 77 72 79 }
        $swnry = { 73 2e 77 72 79 }
	condition:
		$rwnry at 88195 and $swnry at 88656 and $rwnry at 4495639
}