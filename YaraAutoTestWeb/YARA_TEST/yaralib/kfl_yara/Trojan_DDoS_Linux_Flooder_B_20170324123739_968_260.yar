rule Trojan_DDoS_Linux_Flooder_B_20170324123739_968_260 
{
	meta:
		judge = "black"
		threatname = "Trojan[DDoS]/Linux.Flooder.B"
		threattype = "DDOS"
		family = "Flooder"
		hacker = "None"
		refer = "cf072a5dd57c1d23e9f4e728d3e09d26"
		description = "None"
		comment = "None"
		author = "sxy"
		date = "2017-03-15"
	strings:
		$s0 = "fnAttackInformation"
		$s1 = "X-%c%c%c%c%c%c%c: 1"
		$s2 = "GET /%s HTTP/1.1"
		$s3 = "Can't set remote->sin_addr.s_addr"
		$s4 = "GET /~dqyefldi/response.php?auth=tru&id=%d&pro=%d HTTP/1.1"
		$s5 = "Usage: %s <target url> <number threads to use> <proxy list> <time> [manual ip]"

	condition:
		3 of them
}
