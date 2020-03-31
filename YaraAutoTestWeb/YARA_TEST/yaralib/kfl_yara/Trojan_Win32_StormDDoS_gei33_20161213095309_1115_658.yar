rule Trojan_Win32_StormDDoS_gei33_20161213095309_1115_658 
{
	meta:
		judge = "black"
		threatname = "Trojan[DDoS]/Win32.StormDDoS.gei33"
		threattype = "DDOS"
		family = "StormDDoS"
		hacker = "None"
		refer = "fe142a9bbc3a85e66c2e289358554505,94313D3252591FDB98E1CB928F01AEF3"
		description = "\\u9b3c\\u5f71ddos\\u5bb6\\u65cf\\u53d8\\u79cd"
		comment = "None"
		author = "dongjianwu"
		date = "2016-07-19"
	strings:
		$s0 = "rat2.100geili.com:8000"
		$s1 = "cmd /c %s vb \"%s\" lpk.dll|find /i \"lpk.dll\""
		$s2 = "rat3.100geili.com:9000"
		$s3 = "gei%u.dll"

	condition:
		1 of them
}
