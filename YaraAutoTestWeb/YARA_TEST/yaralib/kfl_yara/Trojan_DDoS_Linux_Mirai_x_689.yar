rule Trojan_DDoS_Linux_Mirai_x_689
{
    meta:
	    judge = "black"
		threatname = "Trojan[DDoS]/Linux.Mirai.x"
		threattype = "DDoS"
		family = "Mirai"
		hacker = "None"
		refer = "AE5883A9964534A9B4C395C53097B00C"
		author = "xc"
		comment = "None"
		date = "2017-09-03"
		description = "None"
	strings:
	    $s0 = "POST /cdn-cgi/"
		$s1 = "/proc/net/tcp"
		$s2 = "/dev/watchdog"
		$s3 = "/dev/misc/watchdog"
		$s4 = "MTRSLULUb"
		$s5 = "bttiayytass"
		$s6 = "xAPPSh"
		$s7 = "/var/Challenge"
		$s8 = "8pir2chbm1o5ke6w4djn0vt7uqgfsl3a"
		$s9 = "7cliftvqm1ugnkbej08owar2phd35s64"
		$s10 = "/sys/devices/system/cpu"
	condition:
	    5 of them		
}