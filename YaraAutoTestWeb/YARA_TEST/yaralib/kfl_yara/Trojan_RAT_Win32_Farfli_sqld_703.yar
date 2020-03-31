rule Trojan_RAT_Win32_Farfli_sqld_703
{
	meta:
		judge = "black"
		threatname = "Trojan[RAT]/Win32.Farfli.sqld"
		threattype = "RAT"
		family = "Farfli"
		hacker = "None"
		refer = "0d377b74c17e54f5577a466f037ed045"
		author = "xc"
		comment = "None"
		date = "2017-08-17"
		description = "None"
	strings:
		$s0 = "mysqld.dll"
		$s1 = "YYYYYYYYYYYY"
		$s2 = "127.0.0.1"
	condition:
		all of them
}