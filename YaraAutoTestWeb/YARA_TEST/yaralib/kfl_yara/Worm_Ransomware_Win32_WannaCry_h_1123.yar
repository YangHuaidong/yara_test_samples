rule Worm_Ransomware_Win32_WannaCry_h_1123
{
	meta:
		judge = "black"
		threatname = "Worm[Ransomware]/Win32.WannaCry.h"
		threattype = "ICS,Ransomware"
		family = "WannaCry"
		hacker = "None"
		refer = "7e6b6da7c61fcb66f3f30166871def5b"
		author = "LiuGuangzhu"
		comment = "None"
		date = "2019-05-10"
		description = "Detects WannaCry Ransomware Note"
	strings:		
        $s1 = "A:  Don't worry about decryption." fullword ascii
        $s2 = "Q:  What's wrong with my files?" fullword ascii
	condition:
		( uint16(0) == 0x3a51 and filesize < 2KB and all of them )
}