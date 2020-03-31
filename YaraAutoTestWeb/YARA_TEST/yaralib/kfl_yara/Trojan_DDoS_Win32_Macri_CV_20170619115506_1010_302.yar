rule Trojan_DDoS_Win32_Macri_CV_20170619115506_1010_302 
{
	meta:
		judge = "black"
		threatname = "Trojan[DDoS]/Win32.Macri.CV"
		threattype = "DDOS"
		family = "Macri"
		hacker = "none"
		refer = "7dd2582f78608bc6c9560e1ec4917147"
		description = "None"
		comment = "none"
		author = "xc"
		date = "2017-06-07"
	strings:
		$s0 = "CVmwareCDoc"
		$s1 = "CVmwareCView"
		$s2 = "SysListView32"

	condition:
		all of them
}
