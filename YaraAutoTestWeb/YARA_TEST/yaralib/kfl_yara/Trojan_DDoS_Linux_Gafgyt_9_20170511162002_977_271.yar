rule Trojan_DDoS_Linux_Gafgyt_9_20170511162002_977_271 
{
	meta:
		judge = "black"
		threatname = "Trojan[DDoS]/Linux.Gafgyt.9"
		threattype = "DDOS"
		family = "Gafgyt"
		hacker = "None"
		refer = "098cada713d7cca2ae588c8d66da187a"
		description = "None"
		comment = "None"
		author = "cjf"
		date = "2017-05-02"
	strings:
		$s0 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /"
		$s1 = "bins.sh"
		$s2 = ":>%$#"
		$s3 = "/bin/sh"
		$s4 = "http"
		$s5 = "wget"

	condition:
		all of them
}
