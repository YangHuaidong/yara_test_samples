rule Trojan_RAT_Win32_Mucc_20170811104341_979 
{
	meta:
		judge = "black"
		threatname = "Trojan[RAT]/Win32.Mucc"
		threattype = "rat"
		family = "Mucc"
		hacker = "None"
		refer = "19697676f886485b02b62ac3eeb29a26"
		description = "None"
		comment = "None"
		author = "copy"
		date = "2017-07-26"
	strings:
		$s0 = "NewTest.dat" nocase wide ascii
		$s1 = "tyrij" nocase wide ascii
		$s2 = "9O7mtbWvr70FsLCxsb39AvOf" nocase wide ascii
		$s3 = "3gEAAwIFv9f2" nocase wide ascii
		$s4 = "8wLw870C5wKf" nocase wide ascii

	condition:
		all of them
}
