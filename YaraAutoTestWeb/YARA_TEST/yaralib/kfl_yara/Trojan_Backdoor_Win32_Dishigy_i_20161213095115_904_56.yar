rule Trojan_Backdoor_Win32_Dishigy_i_20161213095115_904_56 
{
	meta:
		judge = "black"
		threatname = "Trojan[Backdoor]/Win32.Dishigy.i"
		threattype = "rat"
		family = "Dishigy"
		hacker = "None"
		refer = "94b73a992e9c3e3067b041b3bbb929ac"
		description = "dirtjumper_drive"
		comment = "None"
		author = "Jason Jones"
		date = "2016-06-23"
	strings:
		$s0 = "-get" fullword
		$s1 = "-ip" fullword
		$s2 = "-ip2" fullword
		$s3 = "-post1" fullword
		$s4 = "-post2" fullword
		$s5 = "-udp" fullword
		$s6 = "login=[1000]&pass=[1000]&password=[50]&log=[50]&passwrd=[50]&user=[50]&username=[50]&vb_login_username=[50]&vb_login_md5password=[50]"
		$s7 = "-timeout" fullword
		$s8 = "-thread" fullword
		$s9 = " Local; ru) Presto/2.10.289 Version/"
		$s10 = "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT"

	condition:
		9 of them
}
