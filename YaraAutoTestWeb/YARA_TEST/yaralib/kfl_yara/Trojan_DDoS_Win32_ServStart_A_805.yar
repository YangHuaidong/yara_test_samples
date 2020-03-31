rule Trojan_DDoS_Win32_ServStart_A_805
{
	meta:
		judge = "black"
		threatname = "Trojan[DDoS]/Win32.ServStart.A"
		threattype = "DDoS"
		family = "ServStart"
		hacker = "None"
		refer = "0311cd0be99abf4c71ebce8713cdf851"
		author = "HuangYY"
		comment = "None"
		date = "2017-06-30"
		description = "None"

	strings:		
		$s1 = "hackshen.exe"
		$s3 = "Password1"
		$s4 = "dmin123"
		$s5 = "qwer1234"
		$s6 = "CPU(%d) %d.GHZ @%d.Mb"
	condition:
		all of them
}