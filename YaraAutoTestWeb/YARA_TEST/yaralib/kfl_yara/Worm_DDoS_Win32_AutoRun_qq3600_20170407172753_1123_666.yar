rule Worm_DDoS_Win32_AutoRun_qq3600_20170407172753_1123_666 
{
	meta:
		judge = "black"
		threatname = "Worm[DDoS]/Win32.AutoRun.qq3600"
		threattype = "DDOS"
		family = "AutoRun"
		hacker = "None"
		refer = "3364ddbfc5b568fd4f44b8e02a31bdc8"
		description = "None"
		comment = "None"
		author = "djw"
		date = "2017-03-29"
	strings:
		$s0 = "DNSFlood" nocase wide ascii
		$s1 = "URLDownloadToFileA"
		$s2 = "Global\\SvcctrlStartEvent_A3752DX"  nocase wide ascii
		$s3 = "_adjust_fdiv"
		$s4 = "qq3600.f3322.org"
		$s5 = "?AVtype_info@@"

	condition:
		5 of them
}
