rule Trojan_DDoS_Win32_StormDDoS_1_696
{
	meta:
	    judge = "black"
		threatname = "Trojan[DDoS]/Win32.StormDDoS.1"
		threattype = "DDoS"
		family = "StormDDoS"
		hacker = "None"
		refer = "958181c5d35f24bb6d26e6a4548cd936"
		author = "mqx"
		comment = "None"
		date = "2017-10-25"
		description = "None"
	strings:
	    $s0 = "%c%c%c%c%c.exe"
	    $s1 = "/c del "
	    $s2 = "\\SNETCFG.exe"
	    $s3 = "%d.%d.%d.%d"
	condition:
	    all of them	
}
