rule Trojan_Ransomware_Win32_Wanna_x_20170918171501_964 
{
	meta:
		judge = "black"
		threatname = "Trojan[Ransomware]/Win32.Wanna.x"
		threattype = "Ransomware"
		family = "Wanna"
		hacker = "None"
		refer = "f156781034daea29e43e997a2a09ff4c"
		description = "None"
		comment = "None"
		author = "xc"
		date = "2017-09-08"
	strings:
		$s0 = "mssecsvc.exe"
		$s1 = "PlayGame"
		$s2 = "WANACRY!"
		$s3 = "c.wnry"
		$s4 = "tasksche.exe"
		$s5 = "WNcry"
		$s6 = "b.wnryP8"
		$s7 = "msg/m_bulgarian.wnry"
		$s8 = "WanaCrypt0r"
		$s9 = "WNcry@2ol7"
		$s10 = "t.wnry"

	condition:
		7 of them
}
