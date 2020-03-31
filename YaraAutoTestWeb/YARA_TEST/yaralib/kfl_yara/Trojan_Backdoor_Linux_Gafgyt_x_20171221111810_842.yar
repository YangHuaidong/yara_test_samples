rule Trojan_Backdoor_Linux_Gafgyt_x_20171221111810_842 
{
	meta:
		judge = "black"
		threatname = "Trojan[Backdoor]/Linux.Gafgyt.x"
		threattype = "BackDoor"
		family = "Gafgyt"
		hacker = "None"
		refer = "00b94bc59b89cec7eb980e440f7bb94b"
		description = "None"
		comment = "None"
		author = "mqx"
		date = "2017-11-24"
	strings:
		$s0 = "POST /cdn-cgi/"
		$s1 = "/dev/misc/watchdog"
		$s2 = "assword"
		$s3 = "/proc/net/tcp"
		$s4 = "pgrmpv"

	condition:
		all of them
}
