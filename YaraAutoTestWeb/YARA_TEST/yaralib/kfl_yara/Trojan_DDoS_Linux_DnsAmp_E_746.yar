rule Trojan_DDoS_Linux_DnsAmp_E_746
{
	meta:
		judge = "black"
		threatname = "Trojan[DDoS]/Linux.DnsAmp.E"
		threattype = "DDoS"
		family = "DnsAmp"
		hacker = "None"
		refer = "0cad84c0d9e0ff68c34fbaa8ca573d3b"
		author = "LiuGuangZhu"
		comment = "None"
		date = "2017-08-22"
		description = "None"
	strings:
		$s0 = "VERSONEX:%s|%d|%d|%s"
		$s1 = "who|awk '{print $1}'"
		$s2 = "TCP_FLOOD i:%d"
		$s3 = "SYN_FLOOD i: %d"
		$s4 = "UDP_FILOOD i:%d"
		$s5 = "STREAM_FLOOD i: %d"
	condition:
		all of them
}