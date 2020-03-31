rule Worm_Ransomware_Win32_WannaCry_vbs_1125
{
	meta:
		judge = "black"
		threatname = "Worm[Ransomware]/Win32.WannaCry.vbs"
		threattype = "ICS,Ransomware"
		family = "WannaCry"
		hacker = "None"
		refer = "800446ec5d8b6041f6b08693d8aa1d53"
		author = "LiuGuangzhu"
		comment = "None"
		date = "2019-05-10"
		description = "Detects WannaCry Ransomware VBS"
	strings:		
        $x1 = ".TargetPath = \"C:\\@" ascii
        $x2 = ".CreateShortcut(\"C:\\@" ascii
        $s3 = " = WScript.CreateObject(\"WScript.Shell\")" ascii
	condition:
		( uint16(0) == 0x4553 and filesize < 1KB and all of them )
}