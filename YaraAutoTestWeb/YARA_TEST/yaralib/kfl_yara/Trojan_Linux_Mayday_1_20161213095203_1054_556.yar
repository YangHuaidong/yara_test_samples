rule Trojan_Linux_Mayday_1_20161213095203_1054_556 
{
	meta:
		judge = "black"
		threatname = "Trojan/Linux.Mayday"
		threattype = "DDOS"
		family = "Mayday"
		hacker = "none"
		refer = "8aaf936b63e9ab6bd0ea3c520aa71834,b5046d06909557bb89180a858b1d5a3d"
		description = "none"
		comment = "none"
		author = "HuangYY"
		date = "2016-08-17"
	strings:
		$s0 = "A/proc/self/e"
		$s1 = "libexec/getco"
		$s2 = "/proc/cpuinfo"
		$s3 = "%Y-%m-%d"
		$s4 = "c/bugs.html"
		$s5 = "/dev/full"

	condition:
		all of them
}
