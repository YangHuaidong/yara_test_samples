rule Worm_Ransomware_Win32_WannaCry_Dropper_1111
{
	meta:
		judge = "black"
		threatname = "Worm[Ransomware]/Win32.WannaCry.Dropper"
		threattype = "ICS,Ransomware"
		family = "WannaCry"
		hacker = "None"
		refer = "84c82835a5d21bbcf75a61706d8ab549"
		author = "LiuGuangzhu"
		comment = "None"
		date = "2019-05-10"
		description = "WannaCry Ransomware Dropper"
	strings:		
	    $s1 = "cmd.exe /c \"%s\"" fullword ascii
 	    $s2 = "tasksche.exe" fullword ascii
 	    $s3 = "icacls . /grant Everyone:F /T /C /Q" fullword ascii
 	    $s4 = "Global\\MsWinZonesCacheCounterMutexA" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 4MB and all of them
}