rule Trojan_DDoS_Win32_StormDDoS_123_20170523183545_1030_326 
{
	meta:
		judge = "black"
		threatname = "Trojan[DDoS]/Win32.StormDDoS.123"
		threattype = "DDOS"
		family = "StormDDoS"
		hacker = "none"
		refer = "D109D588C3666D9C67CD4476BE2C6BCE"
		description = "None"
		comment = "none"
		author = "xc"
		date = "2017-05-11"
	strings:
		$s0 = "%c%c%c%c%c%c.exe"
		$s1 = "iexplore.exe"
		$s2 = "Vip2010-0818"
		$s3 = "tcfg.exe"
		$s4 = "HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0"
		$s5 = "snetcfg.pdb"
		$s6 = "copy netsf_m.inf c:\\netsf_m.inf"

	condition:
		6 of them
}
