rule Worm_Ransomware_Win32_WannaCry_j_1108
{
	meta:
		judge = "black"
		threatname = "Worm[Ransomware]/Win32.WannaCry.j"
		threattype = "ICS,Ransomware"
		family = "WannaCry"
		hacker = "None"
		refer = "84c82835a5d21bbcf75a61706d8ab549"
		author = "LiuGuangzhu"
		comment = "None"
		date = "2019-05-10"
		description = "Detects WannaCryptor spreaded during 2017-May-12th campaign and variants"
	strings:		
        $mutex01 = "Global\\MsWinZonesCacheCounterMutexA" ascii
        $lang01 = "m_bulgarian.wnr" ascii
        $lang02 = "m_vietnamese.wnry" ascii
        $startarg01 = "StartTask" ascii
        $startarg02 = "TaskStart" ascii
        $startarg03 = "StartSchedule" ascii
        $wcry01 = "WanaCrypt0r" ascii wide
        $wcry02 = "WANACRY" ascii
        $wcry03 = "WANNACRY" ascii
        $wcry04 = "WNCRYT" ascii wide
        $forig01 = ".wnry\x00" ascii
        $fvar01 = ".wry\x00" ascii
	condition:
		($mutex01 or any of ($lang*)) and ( $forig01 or all of ($fvar*) ) and any of ($wcry*) and any of ($startarg*)
}