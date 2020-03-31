rule Trojan_DDoS_Win32_Generic_mt_20170619115504_1007_299 
{
	meta:
		judge = "black"
		threatname = "Trojan[DDoS]/Win32.Generic.mt"
		threattype = "DDOS"
		family = "Generic"
		hacker = "none"
		refer = "8c3b9af0c1c6db5eaa4ebd3150dc01d0"
		description = "None"
		comment = "none"
		author = "xc"
		date = "2017-06-12"
	strings:
		$s0 = "c:\\winnt\\system32\\ias\\ias.mdb"
		$s1 = "c:\\mt.exe"
		$s2 = "c:\\Siiget.vbs"
		$s3 = "textcopy /s 127.0.0.1 /U "
		$s4 = "c:\\T3tmp.log"

	condition:
		all of them
}
