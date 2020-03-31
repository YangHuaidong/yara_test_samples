rule Trojan_Backdoor_Linux_Gafgyt_x_670
{
	meta:
	    judge = "black"
		threatname = "Trojan[Backdoor]/Linux.Gafgyt.x"
		threattype = "Backdoor"
		family = "Gafgyt"
		hacker = "None"
		refer = "00b94bc59b89cec7eb980e440f7bb94b"
		author = "mqx"
		comment = "None"
		date = "2017-11-24"
		description = "None"
	strings:
	    $s0 = "POST /cdn-cgi/"
	    $s1 = "/dev/misc/watchdog"
	    $s2 = "assword"
	    $s3 = "/proc/net/tcp"
	    $s4 = "pgrmpv"
	condition:
	    all of them	
}
