rule Trojan_Win32_Havex_R_737
{
	meta:
		judge = "black"
		threatname = "Trojan[BackDoor]/Win32.Havex.r"
		threattype = "BackDoor"
		family = "Havex"
		hacker = "None"
		refer = "875b0702ef3cc2d909ecf720bb4079c2"
		author = "HuangYY"
		comment = "None"
		date = "2017-09-06"
		description = "None"

	strings:		
		$s0 = "bzip2/libbzip2"
		$s1 = "jseward@bzip.org"
		$s3 = "google.com:80"
		$s4 = "Proxy-Authorization:Basic"
		$s5 = "Host: google.com"
	condition:
		all of them
}