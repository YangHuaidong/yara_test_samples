rule Trojan_DDoS_Win32_Mikey_A_20171221111940_929 
{
	meta:
		judge = "black"
		threatname = "Trojan[DDoS]/Win32.Mikey.A"
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
		$s3 = "360sd"
		$s4 = "avguard"
		$s5 = "ashDisp"
		$s6 = "avcenter"
		$s7 = "TMBMSRV"
		$s8 = "RavMonD"
		$s9 = "KvMonXP"
		$s10 = "360tray"

	condition:
		8 of them
}
