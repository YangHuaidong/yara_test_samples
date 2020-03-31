rule Trojan_DDoS_Win32_ServStart_20170717153357_1021_316 
{
	meta:
		judge = "black"
		threatname = "Trojan[DDoS]/Win32.ServStart"
		threattype = "DDOS"
		family = "ServStart"
		hacker = "None"
		refer = "0311cd0be99abf4c71ebce8713cdf851"
		description = "None"
		comment = "None"
		author = "HuangYY"
		date = "2017-06-30"
	strings:
		$s0 = "Yuemingl.txt"
		$s1 = "hackshen.exe"
		$s3 = "Password1"
		$s4 = "dmin123"
		$s5 = "qwer1234"
		$s6 = "CPU(%d) %d.GHZ @%d.Mb"

	condition:
		all of them
}
