rule Trojan_DDoS_Linux_Ddostf_A_20170523183528_965_257 
{
	meta:
		judge = "black"
		threatname = "Trojan[DDoS]/Linux.Ddostf.A"
		threattype = "DDOS"
		family = "Ddostf"
		hacker = "None"
		refer = "93ABD3DF73C8C442A47848949677D92D,4D6434D4D8024B2D7ABF7919E88647EA"
		description = "None"
		comment = "None"
		author = "sxy"
		date = "2017-05-10"
	strings:
		$s0 = "test message"
		$s1 = "connnect server"
		$s2 = "%s%Lu%Lu%Lu%Lu%Lu%Lu%Lu"
		$s3 = "%d Kb/bps|%d%%"
		$s4 = "GET %s HTTP/1.1"
		$s5 = "SYN-Flow"
		$s6 = "UDP-Flow"

	condition:
		5 of them
}
