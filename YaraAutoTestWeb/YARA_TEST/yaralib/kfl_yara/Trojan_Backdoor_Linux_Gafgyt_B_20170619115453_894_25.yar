rule Trojan_Backdoor_Linux_Gafgyt_B_20170619115453_894_25 
{
	meta:
		judge = "black"
		threatname = "Trojan[Backdoor]/Linux.Gafgyt.B"
		threattype = "DDOS"
		family = "Gafgyt"
		hacker = "None"
		refer = "1af4851b383b14e31e914685f2bf9dca"
		description = "None"
		comment = "None"
		author = "LGZ"
		date = "2017-06-06"
	strings:
		$s0 = "cd /tmp || cd /var; wget"
		$s1 = "mylock"
		$s2 = "oodbye"
		$s3 = "chmod 777"
		$s4 = "rm -rf *"
		$s5 = "TRYING %s:%s:%s"
		$s6 = "cd /tmp; wget"
		$s7 = "/bin/sh"
		$s8 = "/proc/net/route"

	condition:
		($s0 and $s1 and $s2 and $s3 and $s4) or ($s5 and $s6 and $s7 and $s8)
}
