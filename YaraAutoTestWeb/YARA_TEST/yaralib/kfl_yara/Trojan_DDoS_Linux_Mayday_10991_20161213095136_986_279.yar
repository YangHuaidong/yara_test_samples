rule Trojan_DDoS_Linux_Mayday_10991_20161213095136_986_279 
{
	meta:
		judge = "black"
		threatname = "Trojan[DDoS]/Linux.Mayday.10991"
		threattype = "DDOS"
		family = "Mayday"
		hacker = "None"
		refer = "387D4B2BBE856D8C76C499F32AEE47BF"
		description = "Mayday DDOS"
		comment = "None"
		author = "zhoufenyan"
		date = "2016-11-23"
	strings:
		$s0 = "7CThread"
		$s1 = "12CThreadTimer"
		$s2 = "18CThreadTaskManager"
		$s3 = "17CThreadHostStatus"
		$s4 = "19CThreadAttackKernal"
		$s5 = "dlcfg"
		$s6 = "fake.cfg"

	condition:
		4 of them
}
