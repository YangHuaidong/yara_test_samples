rule Trojan_DDoS_Win32_Flusihoc_A_20170316094901_1003_295 
{
	meta:
		judge = "black"
		threatname = "Trojan[DDoS]/Win32.Flusihoc.A"
		threattype = "DDOS"
		family = "Flusihoc"
		hacker = "None"
		refer = "4E6EBD7051AA54325BA0F5669C3EE69D"
		description = "None"
		comment = "None"
		author = "cjf"
		date = "2017-03-08"
	strings:
		$s0 = "spoolsv"
		$s1 = "svchost"
		$s2 = "%s|%s|%s|%s|%send"
		$s3 = "null"
		$s4 = "end"
		$s5 = "Idle"

	condition:
		all of them
}
