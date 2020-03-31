rule Trojan_DDoS_Win32_Ddostf_A_20170822160903_922 
{
	meta:
		judge = "black"
		threatname = "Trojan[DDoS]/Win32.Ddostf.A"
		threattype = "DDOS"
		family = "Ddostf"
		hacker = "None"
		refer = "89ae55408ef61eacfd72e1c972d9c9d9"
		description = "None"
		comment = "None"
		author = "HuangYY"
		date = "2017-08-18"
	strings:
		$s0 = "x=%d, y=%d"
		$s1 = "i=%d, j=%d"
		$s3 = "lpk.dll"
		$s4 = "LpkPSMTextOut"
		$s5 = "LpkUseGDIWidthCache"
		$s6 = "LpkDllInitialize"

	condition:
		all of them
}
