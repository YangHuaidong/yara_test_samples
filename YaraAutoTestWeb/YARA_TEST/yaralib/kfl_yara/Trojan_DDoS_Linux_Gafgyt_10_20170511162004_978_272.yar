rule Trojan_DDoS_Linux_Gafgyt_10_20170511162004_978_272 
{
	meta:
		judge = "black"
		threatname = "Trojan[DDoS]/Linux.Gafgyt.10"
		threattype = "DDOS"
		family = "Gafgyt"
		hacker = "None"
		refer = "c9c3a0d74dea85074c1911b5ddf0706f"
		description = "None"
		comment = "None"
		author = "cjf"
		date = "2017-05-02"
	strings:
		$s0 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /"
		$s1 = "ALIVE"
		$s2 = ":>%$#"
		$s3 = "/bin/sh"
		$s4 = "http"
		$s5 = "wget"
		$s6 = "Shit Failed"
		$s7 = "Joined"

	condition:
		all of them
}
