rule Worm_Ransomware_Win32_WannaCry_g_1126
{
	meta:
		judge = "black"
		threatname = "Worm[Ransomware]/Win32.WannaCry.g"
		threattype = "ICS,Ransomware"
		family = "WannaCry"
		hacker = "None"
		refer = "efa8cda6aa188ef8564c94a58b75639f,8ff9c908dea430ce349cc922cee3b7dc,e333604e0d214d03328a854df130377f"
		author = "LiuGuangzhu"
		comment = "None"
		date = "2019-05-10"
		description = "Detects WannaCry Ransomware"
	strings:		
        $s1 = "__TREEID__PLACEHOLDER__" fullword ascii
        $s2 = "__USERID__PLACEHOLDER__" fullword ascii
        $s3 = "Windows for Workgroups 3.1a" fullword ascii
        $s4 = "PC NETWORK PROGRAM 1.0" fullword ascii
        $s5 = "LANMAN1.0" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 5000KB and all of them
}