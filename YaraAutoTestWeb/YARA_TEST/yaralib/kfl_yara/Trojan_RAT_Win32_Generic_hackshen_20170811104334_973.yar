rule Trojan_RAT_Win32_Generic_hackshen_20170811104334_973 
{
	meta:
		judge = "black"
		threatname = "Trojan[rat]/Win32.Generic.hackshen"
		threattype = "rat"
		family = "Generic"
		hacker = "none"
		refer = "14d996266926bf59ae3d99ff79d3c717"
		description = "None"
		comment = "none"
		author = "xc"
		date = "2017-07-26"
	strings:
		$s0 = "C:\\Program Files\\svchost.exe"
		$s1 = "\\\\%s\\admin$\\hackshen.exe"
		$s2 = "C:\\Yuemingl.txt"

	condition:
		all of them
}
