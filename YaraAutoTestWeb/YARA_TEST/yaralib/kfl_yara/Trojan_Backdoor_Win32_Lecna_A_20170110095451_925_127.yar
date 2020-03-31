rule Trojan_Backdoor_Win32_Lecna_A_20170110095451_925_127 
{
	meta:
		judge = "black"
		threatname = "Trojan[Backdoor]/Win32.Lecna.A"
		threattype = "rat"
		family = "Lecna"
		hacker = "None"
		refer = "37aee58655f5859e60ece6b249107b87,4154548e1f8e9e7eb39d48a4cd75bcd1,a2e0203e665976a13cdffb4416917250,b4ae0004094b37a40978ef06f311a75e,37aee58655f5859e60ece6b249107b87"
		description = "FireEye APT30 Report Sample,https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
		comment = "None"
		author = "Florian Roth"
		date = "2015-04-13"
	strings:
		$s0 = "MYUSER32.dll" fullword ascii
		$s1 = "MYADVAPI32.dll" fullword ascii
		$s2 = "MYWSOCK32.dll" fullword ascii
		$s3 = "MYMSVCRT.dll" fullword ascii

	condition:
		filesize < 100KB and uint16(0) == 0x5A4D and all of them
}
