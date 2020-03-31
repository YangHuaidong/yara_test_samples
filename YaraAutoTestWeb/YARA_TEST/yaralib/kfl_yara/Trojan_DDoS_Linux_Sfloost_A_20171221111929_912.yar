rule Trojan_DDoS_Linux_Sfloost_A_20171221111929_912 
{
	meta:
		judge = "black"
		threatname = "Trojan[DDoS]/Linux.Sfloost.A"
		threattype = "DDOS"
		family = "Sfloost"
		hacker = "None"
		refer = "4e972bde97f5461240fffbabaad8fcaf,dfd2fe2618a8bc7ba321b8afc346df66,9e9d533d7d55fa547fac56e373c81138"
		description = "None"
		comment = "None"
		author = "HuangYY"
		date = "2016-11-16"
	strings:
		$s0 = "MemFree: %ld kB"
		$s1 = "/proc/meminfo"
		$s2 = "delxxaazz"
		$s3 = "/sys/devices/system/cpu"
		$s4 = "HOSTALIASES"
		$s5 = "M%hu.%hu.%hu%n"
		$s6 = "/etc/resolv.conf"
		$s7 = "SynFloodSendThread"
		$s8 = "DnsFloodSendThread"

	condition:
		7 of them
}
