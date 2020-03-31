rule Trojan_Backdoor_Lecna_APT30_Generic_E_v2_20161213095108_891_5 
{
	meta:
		judge = "black"
		threatname = "Trojan[BackDoor]/Win32.Lecna.APT30_Generic_E_v2"
		threattype = "BackDoor"
		family = "Lecna"
		hacker = "None"
		refer = "dfc3a1dfd8078be8892766039766a41b"
		description = "FireEye APT30 Report Sample - file 71f25831681c19ea17b2f2a84a41bbfb, https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
		comment = "None"
		author = "djw,Florian Roth"
		date = "2015-04-13"
	strings:
		$s0 = "Nkfvtyvn}duf_Z}{Ys" fullword ascii
		$s1 = "Nkfvtyvn}*Zrswru1i" fullword ascii
		$s2 = "Nkfvtyvn}duf_Z}{V" fullword ascii
		$s3 = "Nkfvtyvn}*ZrswrumT\\b" fullword ascii

	condition:
		filesize < 100KB and uint16(0) == 0x5A4D and all of them
}
