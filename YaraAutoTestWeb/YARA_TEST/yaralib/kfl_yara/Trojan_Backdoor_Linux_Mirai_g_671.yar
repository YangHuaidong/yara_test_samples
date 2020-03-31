rule Trojan_Backdoor_Linux_Mirai_g_671
{
	meta:
	    judge = "black"
		threatname = "Trojan[Backdoor]/Linux.Mirai.g"
		threattype = "Backdoor"
		family = "Mirai"
		hacker = "None"
		refer = "0dfed50ec104b1768b91693c37fbf5c6"
		author = "mqx"
		comment = "None"
		date = "2017-10-16"
		description = "None"
	strings:
	    $s0 = "ogin:"
		$s1 = "assword:"
		$s2 = "ncorrect"
		$s3 = "/proc/%s/fd/%s"
		$s4 = "/bin/dd if=/bin/dd bs=22 count=1 || /bin/cat /bin/cat"
	condition:
	    all of them	
}