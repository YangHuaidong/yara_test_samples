rule Worm_Ransomware_Win32_WannaCry_bat_1124
{
	meta:
		judge = "black"
		threatname = "Worm[Ransomware]/Win32.WannaCry.bat"
		threattype = "ICS,Ransomware"
		family = "WannaCry"
		hacker = "None"
		refer = "fefe6b30d0819f1a1775e14730a10e0e"
		author = "LiuGuangzhu"
		comment = "None"
		date = "2019-05-10"
		description = "Detects WannaCry Ransomware BATCH File"
	strings:		
        $s1 = "@.exe\">> m.vbs" ascii
        $s2 = "cscript.exe //nologo m.vbs" fullword ascii
        $s3 = "echo SET ow = WScript.CreateObject(\"WScript.Shell\")> " ascii
        $s4 = "echo om.Save>> m.vbs" fullword ascii
	condition:
		( uint16(0) == 0x6540 and filesize < 1KB and 1 of them )
}