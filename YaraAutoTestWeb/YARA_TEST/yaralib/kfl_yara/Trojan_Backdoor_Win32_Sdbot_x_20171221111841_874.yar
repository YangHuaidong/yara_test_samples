rule Trojan_Backdoor_Win32_Sdbot_x_20171221111841_874 
{
	meta:
		judge = "black"
		threatname = "Trojan[Backdoor]/Win32.Sdbot.x"
		threattype = "BackDoor"
		family = "Sdbot"
		hacker = "None"
		refer = "007b78eebec22a9c6e1759c3421a7800"
		description = "None"
		comment = "None"
		author = "xc"
		date = "2017-09-28"
	strings:
		$s0 = "COMMAND_DDOS_GET"
		$s1 = ".temp.fortest"
		$s2 = "fengnannan1044.f3322.org"
		$s3 = "C:\\WINDOWS\\WindowsUpdata\\vxunwlrzgj.exe"
		$s4 = "No Config.ini"
		$s5 = "sqgwitnawqf.exe"

	condition:
		3 of them
}
