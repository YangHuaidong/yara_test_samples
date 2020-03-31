rule Trojan_Ransomware_Win32_NotPetya_1087
{
	meta:
		judge = "black"
		threatname = "Trojan[Ransomware]/Win32.NotPetya"
		threattype = "ICS,Ransomware"
		family = "NotPetya"
		hacker = "None"
		refer = "71b6a493388e7d0b40c83ce903bc6b04"
		author = "LiuGuangzhu"
		comment = "None"
		date = "2019-03-21"
		description ="https://github.com/Neo23x0/signature-base/blob/master/yara/crime_nopetya_jun17.yar"
	strings:
		$x1 = "Ooops, your important files are encrypted." fullword wide ascii
		$x2 = "process call create \"C:\\Windows\\System32\\rundll32.exe \\\"C:\\Windows\\%s\\\" #1 " fullword wide
		$x3 = "-d C:\\Windows\\System32\\rundll32.exe \"C:\\Windows\\%s\",#1 " fullword wide
		$x4 = "Send your Bitcoin wallet ID and personal installation key to e-mail " fullword wide
		$x5 = "fsutil usn deletejournal /D %c:" fullword wide
		$x6 = "wevtutil cl Setup & wevtutil cl System" ascii
		/* ,#1 ..... rundll32.exe */
		$x7 = { 2C 00 23 00 31 00 20 00 00 00 00 00 00 00 00 00 72 00 75 00 6E
				00 64 00 6C 00 6C 00 33 00 32 00 2E 00 65 00 78 00 65 00 }
		$s1 = "%s /node:\"%ws\" /user:\"%ws\" /password:\"%ws\" " fullword wide
		$s4 = "\\\\.\\pipe\\%ws" fullword wide
		$s5 = "schtasks %ws/Create /SC once /TN \"\" /TR \"%ws\" /ST %02d:%02d" fullword wide
		$s6 = "u%s \\\\%s -accepteula -s " fullword wide
		$s7 = "dllhost.dat" fullword wide
	condition:
		uint16(0) == 0x5a4d and filesize < 1000KB and ( 1 of ($x*) or 3 of them )
}