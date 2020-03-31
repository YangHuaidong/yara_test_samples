rule Trojan_DDoS_Win32_StormDDoS_3389_20170424091944_1032_328 
{
	meta:
		judge = "black"
		threatname = "Trojan[DDoS]/Win32.StormDDoS.3389"
		threattype = "DDOS"
		family = "StormDDoS"
		hacker = "None"
		refer = "eec4f7bccc332f7f87efc85cdc8e1131"
		description = "None"
		comment = "None"
		author = "sxy"
		date = "2017-04-12"
	strings:
		$s0 = "3389"
		$s1 = "RDP-Tcp"
		$s2 = "%c%c%c%c%c%c.exe"
		$s3 = "King.dat"
		$s4 = "ast.exe"
		$s5 = "360tray.exe"
		$s6 = "Referer: http://%s:80/http://%s"
		$s7 = "http://www.baidu.com/search/spider.html"
		$s8 = "Ghijkl Nsdfsdfsdf"

	condition:
		all of them
}
