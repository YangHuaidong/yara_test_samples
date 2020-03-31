rule Trojan_DDoS_Linux_Gafgyt_5_20170324123745_974_268 
{
	meta:
		judge = "black"
		threatname = "Trojan[DDoS]/Linux.Gafgyt.5"
		threattype = "DDOS"
		family = "Gafgyt"
		hacker = "None"
		refer = "9321bf1e28d14f16abe30ea66c2d4ae6"
		description = "None"
		comment = "None"
		author = "cjf"
		date = "2017-03-14"
	strings:
		$s0 = "scan.py"
		$s1 = "jack*"
		$s2 = "hack*"
		$s3 = ":>%$#"
		$s4 = "Starting scanner!!"
		$s5 = "fucker"

	condition:
		all of them
}
