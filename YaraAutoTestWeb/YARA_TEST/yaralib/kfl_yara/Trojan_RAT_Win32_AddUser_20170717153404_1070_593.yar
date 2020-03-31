rule Trojan_RAT_Win32_AddUser_20170717153404_1070_593 
{
	meta:
		judge = "black"
		threatname = "Trojan[RAT]/Win32.AddUser"
		threattype = "rat"
		family = "AddUser"
		hacker = "none"
		refer = "e2045d233bc9182043e4ff8ca45c0766"
		description = "None"
		comment = "none"
		author = "xc"
		date = "2017-07-07"
	strings:
		$s0 = "jiaozhu$"
		$s1 = "/c del"
		$s2 = "admins8450"

	condition:
		all of them
}
