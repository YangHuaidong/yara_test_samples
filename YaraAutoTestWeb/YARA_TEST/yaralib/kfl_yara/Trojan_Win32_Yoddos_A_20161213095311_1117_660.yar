rule Trojan_Win32_Yoddos_A_20161213095311_1117_660 
{
	meta:
		judge = "black"
		threatname = "Trojan[Backdoor]/Win32.Yoddos.A"
		threattype = "RAT|DDOS"
		family = "Yoddos"
		hacker = "None"
		refer = "d4f29dd46643c2df22eb51c47d1eb392"
		description = "http://telussecuritylabs.com/threats/show/TSL20100831-01"
		comment = "None"
		author = "sxy"
		date = "2016-11-29"
	strings:
		$s0 = "NxbhMEDx.exe"
		$s1 = "360tray.exe"
		$s2 = "RavMonD.exe"
		$s3 = "kxetray.exe"
		$s4 = "MPSVC.exe"
		$s5 = "%08X-%04X-%04x-%02X%02X-%02X%02X%02X%02X%02X%02X"
		$s6 = "Plug:DDOS"
		$s7 = "www.baidu.com"

	condition:
		5 of them
}
