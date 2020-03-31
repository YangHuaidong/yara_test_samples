rule Trojan_DDoS_Linux_Gafgyt_2_20170324123742_971_265 
{
	meta:
		judge = "black"
		threatname = "Trojan[DDoS]/Win32.Gafgyt.2"
		threattype = "DDOS"
		family = "Gafgyt"
		hacker = "None"
		refer = "31A9611A922813BB28BCA22452DB1E18"
		description = "None"
		comment = "None"
		author = "cjf"
		date = "2017-03-14"
	strings:
		$s0 = "PONG!"
		$s1 = "%s 2>&1"
		$s2 = ":>%$#"
		$s3 = "root"
		$s4 = "My Public IP: %s"
		$s5 = "My IP: %s"
		$s6 = "buf: %s"

	condition:
		$s0 and $s1 and $s2 and $s3 and ($s4 or $s5 or $s6)
}
