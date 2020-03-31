rule Trojan_Backdoor_Linux_Mirai_n_688
{
	meta:
	    judge = "black"
		threatname = "Trojan[DDoS]/Linux.Mirai.n"
		threattype = "DDoS"
		family = "Mirai"
		hacker = "None"
		refer = "009c1ee3916d188d456239fe5458698e"
		author = "mqx"
		comment = "None"
		date = "2017-11-23"
		description = "None"
	strings:
	    $s0 = "POST /cdn-cgi/"
	    $s1 = "/dev/misc/watchdog"
	    $s2 = "enter"
	    $s3 = "assword"
	    $s4 = "/proc/net/tcp"
	condition:
	    all of them	
}
