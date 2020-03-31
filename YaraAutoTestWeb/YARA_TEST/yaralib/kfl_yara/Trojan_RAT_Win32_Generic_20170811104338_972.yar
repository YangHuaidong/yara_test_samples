rule Trojan_RAT_Win32_Generic_20170811104338_972 
{
	meta:
		judge = "black"
		threatname = "Trojan[RAT]/Win32.Generic"
		threattype = "rat"
		family = "Generic"
		hacker = "None"
		refer = "14d996266926bf59ae3d99ff79d3c717"
		description = "None"
		comment = "None"
		author = "copy"
		date = "2017-07-26"
	strings:
		$s0 = "C:\\Yuemingl.txt" nocase wide ascii
		$s1 = "Hotkey" nocase wide ascii
		$s2 = "%.f|%d%%" nocase wide ascii
		$s3 = "D:\\hackshen.exe" nocase wide ascii

	condition:
		all of them
}
