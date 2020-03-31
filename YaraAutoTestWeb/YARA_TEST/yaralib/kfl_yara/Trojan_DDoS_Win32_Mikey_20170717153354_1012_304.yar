rule Trojan_DDoS_Win32_Mikey_20170717153354_1012_304 
{
	meta:
		judge = "black"
		threatname = "Trojan[DDoS]/Win32.Mikey"
		threattype = "DDOS"
		family = "Mikey"
		hacker = "None"
		refer = "0311cd0be99abf4c71ebce8713cdf851"
		description = "None"
		comment = "None"
		author = "HuangYY"
		date = "2017-06-30"
	strings:
		$s0 = "cmd /c ping 127.0.0.1 -n 1&del"
		$s1 = "%-24s %-15s %s"
		$s2 = "360sd"
		$s3 = "avguard"
		$s4 = "ashDisp"
		$s5 = "avcenter"
		$s6 = "TMBMSRV"
		$s7 = "RavMonD"
		$s8 = "KvMonXP"
		$s9 = "360tray"

	condition:
		8 of them
}
