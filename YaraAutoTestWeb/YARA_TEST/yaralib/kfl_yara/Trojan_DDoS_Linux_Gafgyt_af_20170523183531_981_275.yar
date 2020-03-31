rule Trojan_DDoS_Linux_Gafgyt_af_20170523183531_981_275 
{
	meta:
		judge = "black"
		threatname = "Trojan[DDoS]/Linux.Gafgyt.af"
		threattype = "DDOS"
		family = "Gafgyt"
		hacker = "None"
		refer = "126572e4078482ceb62318a9e2222217"
		description = "None"
		comment = "None"
		author = "cjf"
		date = "2017-05-09"
	strings:
		$s0 = "jack*"
		$s1 = "hack*"
		$s2 = ":>%$#"
		$s3 = "Starting scanner!!"
		$s4 = "Mozilla/5.0"
		$s5 = "BIN.sh"
		$s6 = "PING"
		$s7 = "HTTP"

	condition:
		all of them
}
