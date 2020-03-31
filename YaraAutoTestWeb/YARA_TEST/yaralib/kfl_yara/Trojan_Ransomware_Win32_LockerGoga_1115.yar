rule Trojan_Ransomware_Win32_LockerGoga_1115
{
	meta:
		judge = "black"
		threatname = "Trojan[Ransomware]/Win32.LockerGoga"
		threattype = "ICS,Ransomware"
		family = "LockerGoga"
		hacker = "None"
		refer = "e11502659f6b5c5bd9f78f534bc38fea"
		author = "LiuGuangzhu"
		comment = "None"
		date = "2019-05-10"
		description ="Detects LockerGoga ransomware binaries"
	strings:
        $x1 = "\\.(doc|dot|wbk|docx|dotx|docb|xlm|xlsx|xltx|xlsb|xlw|ppt|pot|pps|pptx|potx|ppsx|sldx|pdf)" wide
        $x2 = "|[A-Za-z]:\\cl.log" wide
        $x4 = "\\crypto-locker\\" ascii
        $xc1 = { 00 43 00 6F 00 6D 00 70 00 61 00 6E 00 79 00 4E
               00 61 00 6D 00 65 00 00 00 00 00 4D 00 6C 00 63
               00 72 00 6F 00 73 00 6F 00 66 00 74 }
        $xc2 = { 00 2E 00 6C 00 6F 00 63 00 6B 00 65 00 64 00 00
               00 20 46 41 49 4C 45 44 20 00 00 00 00 20 00 00
               00 20 75 6E 6B 6E 6F 77 6E 20 65 78 63 65 70 74
               69 6F 6E }
        $rn1 = "This may lead to the impossibility of recovery of the certain files." wide
	condition:
		( uint16(0) == 0x5a4d and filesize < 4000KB and 1 of ($x*) ) or $rn1
}