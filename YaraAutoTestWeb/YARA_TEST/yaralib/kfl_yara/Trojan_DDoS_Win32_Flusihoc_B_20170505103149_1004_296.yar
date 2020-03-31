rule Trojan_DDoS_Win32_Flusihoc_B_20170505103149_1004_296 
{
	meta:
		judge = "black"
		threatname = "Trojan[DDoS]/Win32.Flusihoc.B"
		threattype = "DDOS"
		family = "Flusihoc"
		hacker = "None"
		refer = "1ed97dd137a4d334c506d24de6e1d489"
		description = "None"
		comment = "None"
		author = "xc"
		date = "2017-04-28"
	strings:
		$s0 = "GET %s%s%s%s%s%s%s%s%s%s"
		$s1 = "%siexplore.exe"
		$s2 = "%s|%s|%s|%s|%send"
		$s3 = "SYN_Flood"
		$s4 = "UDP_Flood"
		$s5 = "TCP_Flood"
		$s6 = "ICMP_Flood"
		$s7 = "HTTP_Flood"
		$s8 = "DNS_Flood"
		$s9 = "CON_Flood"
		$s10 = "CC_Flood"
		$s11 = "CC_Flood2"

	condition:
		9 of them
}
