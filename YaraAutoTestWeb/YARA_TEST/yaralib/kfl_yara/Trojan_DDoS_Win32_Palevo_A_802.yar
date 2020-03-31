rule Trojan_DDoS_Win32_Palevo_A_802
{
	meta:
		judge = "black"
		threatname = "Trojan[DDoS]/Win32.Palevo.A"
		threattype = "DDoS"
		family = "Palevo"
		hacker = "None"
		refer = "d1e12c89fdb63d74e0e2ce8e7c7c1ee3"
		author = "HuangYY"
		comment = "None"
		date = "2017-08-21"
		description = "None"
	strings:		
		$s0 = "systemroot"
		$s1 = "Server.pdb"
		$s3 = "%d * %dMHz"
		$s4 = "Fuck your ass!"
		$s5 = "F:\\Projects"
		$s6 = "X-%c: %c"
	condition:
		all of them
}