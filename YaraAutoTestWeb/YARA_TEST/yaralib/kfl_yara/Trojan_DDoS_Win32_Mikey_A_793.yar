rule Trojan_DDoS_Win32_Mikey_A_793
{
	meta:
		judge = "black"
		threatname = "Trojan[DDoS]/Win32.Mikey.A"
		threattype = "DDoS"
		family = "Mikey"
		hacker = "None"
		refer = "0311cd0be99abf4c71ebce8713cdf851"
		author = "HuangYY"
		comment = "None"
		date = "2017-06-30"
		description = "None"

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