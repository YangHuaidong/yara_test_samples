rule Trojan_DDoS_Linux_Gafgyt_B_758
{
	meta:
		judge = "black"
		threatname = "Trojan[DDoS]/Linux.Gafgyt.B"
		threattype = "DDoS"
		family = "Gafgyt"
		hacker = "None"
		refer = "FFD31D877815988845D4577AA084FEB2"
		author = "LiuGuangzhu"
		comment = "None"
		date = "2017-09-07"
		description = "None"
	strings:
		$s0 = "cd /tmp || cd /var/run; rm -rf *"
		$s1 = "gayfgt"
		$s2 = "My IP: %s"
		$s3 = "REPORT %s:%s:%s"
		$s4 = "SCANNER ON | OFF"
	condition:
		all of them
}