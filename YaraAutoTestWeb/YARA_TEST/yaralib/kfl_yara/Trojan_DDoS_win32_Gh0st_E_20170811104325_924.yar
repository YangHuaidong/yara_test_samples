rule Trojan_DDoS_win32_Gh0st_E_20170811104325_924 
{
	meta:
		judge = "black"
		threatname = "Trojan[DDoS]/Win32.Gh0st.E"
		threattype = "DDOS"
		family = "Gh0st"
		hacker = "None"
		refer = "0311cd0be99abf4c71ebce8713cdf851"
		description = "None"
		comment = "None"
		author = "HuangYY"
		date = "2017-06-30"
	strings:
		$s0 = "%c%c%c%c%c%c.exe"
		$s1 = "user.qzone.qq.com"
		$s3 = "rasphone.pbk"
		$s4 = "iexplore.exe"
		$s5 = "%d.%d.%d.%d"
		$s6 = "%c%c%c%c%c%c.exe"

	condition:
		all of them
}
