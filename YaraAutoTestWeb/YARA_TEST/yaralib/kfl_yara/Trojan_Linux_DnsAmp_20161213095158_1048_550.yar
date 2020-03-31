rule Trojan_Linux_DnsAmp_20161213095158_1048_550 
{
	meta:
		judge = "black"
		threatname = "Trojan/Linux.DnsAmp"
		threattype = "DDOS"
		family = "DnsAmp"
		hacker = "None"
		refer = "14f2713117ac55281f40b54ba7cb7f6c,981d83d5435c7f6a2b259c46c8dc66a9"
		description = "None"
		comment = "None"
		author = "HuangYY"
		date = "2016-11-23"
	strings:
		$s0 = "INFO:%d|%d"
		$s1 = "VERS0NEX:%s|%d|%d|%s"
		$s2 = "Keep-Alive"
		$s3 = "/proc/self/maps"
		$s4 = "/proc/stat"
		$s5 = "/proc/net/dev"
		$s6 = "MemTotal: %ld kB"

	condition:
		6 of them
}
