rule Trojan_RAT_Win32_Generic_20170720120040_1088_613 
{
	meta:
		judge = "black"
		threatname = "Trojan[RAT]/Win32.Generic"
		threattype = "rat"
		family = "Generic"
		hacker = "none"
		refer = "bbafd17495b1fd0afd0987226d17de5b"
		description = "None"
		comment = "none"
		author = "xc"
		date = "2017-07-14"
	strings:
		$s0 = "C:\\Yuemingl.txt"
		$s1 = "svchost.exe"
		$s2 = "1qazxsw2#EDC"
		$s3 = "\\\\%s\\admin$\\hackshen.exe"

	condition:
		all of them
}
