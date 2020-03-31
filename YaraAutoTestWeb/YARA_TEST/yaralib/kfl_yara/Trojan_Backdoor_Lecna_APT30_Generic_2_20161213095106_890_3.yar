rule Trojan_Backdoor_Lecna_APT30_Generic_2_20161213095106_890_3 
{
	meta:
		judge = "black"
		threatname = "Trojan[BackDoor]/Win32.Lecna.APT30_Generic_2"
		threattype = "BackDoor"
		family = "Lecna"
		hacker = "None"
		refer = "57325f56792b6119a6d830881c7905c7"
		description = "FireEye APT30 Report Sample - from many files, https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
		comment = "None"
		author = "djw,Florian Roth"
		date = "2015-04-13"
	strings:
		$s0 = "%s\\%s\\KB985109.log" fullword
		$s1 = "%s\\%s\\KB989109.log" fullword
		$s2 = "Opera.exe" fullword wide
		$s3 = "%s:All online success on %u!" fullword
		$s4 = "%s:list online success on %u!" fullword
		$s5 = "%s:All online fail!" fullword
		$s6 = "Copyright Opera Software 1995-" fullword wide
		$s7 = "%s:list online fail!" fullword
		$s8 = "OnlineTmp.txt" fullword
		$s9 = "Opera Internet Browser" fullword wide
		$s12 = "Opera Software" fullword wide
		$s15 = "Check lan have done!!!" fullword
		$s16 = "List End." fullword

	condition:
		filesize < 100KB and uint16(0) == 0x5A4D and all of them
}
