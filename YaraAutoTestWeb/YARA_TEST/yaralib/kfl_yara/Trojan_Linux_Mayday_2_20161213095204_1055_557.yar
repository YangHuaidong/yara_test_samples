rule Trojan_Linux_Mayday_2_20161213095204_1055_557 
{
	meta:
		judge = "black"
		threatname = "Trojan/Linux.Mayday"
		threattype = "DDOS"
		family = "Mayday"
		hacker = "none"
		refer = "f75b5d1d7e9de2f049a5b7e95f3ef7f8"
		description = "none"
		comment = "none"
		author = "HuangYY"
		date = "2016-08-17"
	strings:
		$s0 = "/proc/self/e"
		$s1 = "xec/getconf"
		$s2 = "/proc/cpuinfo"
		$s3 = "%Y-%m-%d"
		$s4 = "%d.%d-stat"

	condition:
		all of them
}
