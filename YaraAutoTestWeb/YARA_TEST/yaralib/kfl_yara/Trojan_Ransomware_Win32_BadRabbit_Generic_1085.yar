rule Trojan_Ransomware_Win32_BadRabbit_Generic_1085
{
	meta:
		judge = "black"
		threatname = "Trojan[Ransomware]/Win32.BadRabbit.Generic"
		threattype = "ICS,Ransomware"
		family = "BadRabbit"
		hacker = "None"
		refer = "b14d8faf7f0cbcfad051cefe5f39645f"
		author = "LiuGuangzhu"
		comment = "None"
		date = "2019-03-21"
		description = "https://github.com/Neo23x0/signature-base/blob/master/yara/crime_badrabbit.yar"
	strings:
		$x1 = "schtasks /Create /SC ONCE /TN viserion_%u /RU SYSTEM /TR \"%ws\" /ST" fullword wide
		$x2 = "schtasks /Create /RU SYSTEM /SC ONSTART /TN rhaegal /TR \"%ws /C Start \\\"\\\" \\\"%wsdispci.exe\\\"" fullword wide
		$x3 = "C:\\Windows\\infpub.dat" fullword wide
		$x4 = "C:\\Windows\\cscc.dat" fullword wide
		$s1 = "need to do is submit the payment and get the decryption password." fullword ascii
		$s2 = "\\\\.\\GLOBALROOT\\ArcName\\multi(0)disk(0)rdisk(0)partition(1)" fullword wide
		$s3 = "\\\\.\\pipe\\%ws" fullword wide
		$s4 = "fsutil usn deletejournal /D %c:" fullword wide
		$s5 = "Run DECRYPT app at your desktop after system boot" fullword ascii
		$s6 = "Files decryption completed" fullword wide
		$s7 = "Disable your anti-virus and anti-malware programs" fullword wide
		$s8 = "SYSTEM\\CurrentControlSet\\services\\%ws" fullword wide
		$s9 = "process call create \"C:\\Windows\\System32\\rundll32.exe" fullword wide
		$s10 = "%ws C:\\Windows\\%ws,#1 %ws" fullword wide
	condition:
		uint16(0) == 0x5a4d and filesize < 700KB and ( 1 of ($x*) or 2 of them )
}