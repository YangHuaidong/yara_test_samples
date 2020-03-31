rule Trojan_Linux_Gafgyt_C_20170324123752_1051_553 
{
	meta:
		judge = "black"
		threatname = "Trojan/Linux.Gafgyt.C"
		threattype = "DDOS"
		family = "Gafgyt"
		hacker = "None"
		refer = "9feaaf20275a80f9cf46aa36e9aa22e7,81c3ec87c026c7c5b78ee1e7a7ec66fb"
		description = "None"
		comment = "None"
		author = "LGZ"
		date = "2017-03-13"
	strings:
		$s1 = "IP: %s || Port: 23 || Username: %s || Password: %s"
		$s2 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget"
		$s3 = "Mozilla/5.0"
		$s4 = "chmod 777"

	condition:
		3 of them
}
