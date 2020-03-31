rule Trojan_DDoS_Win32_Nitol_34_819_308
{
	meta:
		judge = "black"
		threatname = "Trojan[DDoS]/Win32.Nitol.Ex"
		threattype = "DDoS"
		family = "Nitol"
		hacker = "None"
		refer = "ac87756743f583adb6b6d44300db2f74"
		author = "lizhenling"
		comment = "None"
		date = "2018-10-31"
		description = "None"

	strings:		
		$s0 = "REG_MULTI_SZ"
		$s1 = "F:\\g1fd.exe"
		$s2 = "HSVHWtgHHtF"
		$s3 = "hra%u.dll"
		$s4 = "F*PjTWj"
		$s5 = "HtOHt)H"
		$s6 = "HHtiHtGH"
		$s7 = "HHtpHHtl"
		$s8 = "tEj@Vh"
		$s9 = "SVWh@w"
		
	condition:
		all of them
}