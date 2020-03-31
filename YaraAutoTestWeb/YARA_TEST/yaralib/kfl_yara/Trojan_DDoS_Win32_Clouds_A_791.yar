rule Trojan_DDoS_Win32_Clouds_A_791
{
	meta:
		judge = "black"
		threatname = "Trojan[DDoS]/Win32.Clouds.A"
		threattype = "DDoS"
		family = "Clouds"
		hacker = "None"
		refer = "71a1953e5fe17066ac659365c7d2d974"
		author = "HuangYY"
		comment = "None"
		date = "2017-08-18"
		description = "None"
	strings:		
		$s0 = "Clouds"
		$s1 = "COMMAND_DDOS_GET"
		$s3 = "Config.ini"
		$s4 = "%d*%dMHz"
		$s5 = " /c del"
		$s6 = "WindowsUpdata"
	condition:
		all of them
}