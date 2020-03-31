rule Trojan_DDoS_Win32_Flusihoc_C_20170511162008_1005_297 
{
	meta:
		judge = "black"
		threatname = "Trojan[DDoS]/Win32.Flusihoc.C"
		threattype = "DDOS"
		family = "Flusihoc"
		hacker = "none"
		refer = "ef07be2cdf9076007bcc7a4cb3929aa5"
		description = "None"
		comment = "none"
		author = "xc"
		date = "2017-05-02"
	strings:
		$s0 = "spoolsv"
		$s1 = "svchost"
		$s2 = "D:\\Program Files\\svchost\\svchost.exe"
		$s3 = "E:\\Program Files\\svchost\\svchost.exe"

	condition:
		all of them
}
