rule Trojan_DDoS_Linux_Melt_b_20170523183535_988_281 
{
	meta:
		judge = "black"
		threatname = "Trojan[DDoS]/Linux.Melt.b"
		threattype = "DDOS"
		family = "Melt"
		hacker = "None"
		refer = "f59259eb49b0cc22c221aedd852f858f"
		description = "None"
		comment = "None"
		author = "cjf"
		date = "2017-05-09"
	strings:
		$s0 = "MondoMan"
		$s1 = "ERROR: Must specify valid IP or hostname."
		$s2 = "tcp_flags"
		$s3 = "ack"

	condition:
		all of them
}
