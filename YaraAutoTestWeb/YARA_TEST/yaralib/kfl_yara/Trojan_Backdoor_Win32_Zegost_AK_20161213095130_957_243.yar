rule Trojan_Backdoor_Win32_Zegost_AK_20161213095130_957_243 
{
	meta:
		judge = "black"
		threatname = "Trojan[Backdoor]/Win32.Zegost.AK"
		threattype = "DDOS"
		family = "Zegost"
		hacker = "None"
		refer = "31977AFC32FD48C2AD001B677B88E15F,4EB6A33D1B71D60585FF9BE8F249A2E1"
		description = "Backdoor:Win32/Zegost.AK(Microsoft),gh0st"
		comment = "Filename and DDoS attack mode"
		author = "zhoufenyan"
		date = "2016-07-19"
	strings:
		$s0 = "WinHbft32"
		$s1 = "SynFlood"
		$s2 = "Game2Flood"
		$s3 = "UDPSmallFlood"
		$s4 = "DIYUDPFlood"
		$s5 = "MultiTCPFlood"
		$s6 = "ICMPFlood"
		$s7 = "WebWXCCFlood"
		$s8 = "HTTPGetFlood"
		$s9 = "DIYTCPFlood"
		$s10 = "DNSFlood"

	condition:
		6 of them
}
