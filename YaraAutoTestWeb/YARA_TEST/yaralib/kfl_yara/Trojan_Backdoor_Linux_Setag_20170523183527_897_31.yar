rule Trojan_Backdoor_Linux_Setag_20170523183527_897_31 
{
	meta:
		judge = "black"
		threatname = "Trojan[DDoS]/Linux.Setag"
		threattype = "BackDoor"
		family = "Setag"
		hacker = "None"
		refer = "E9A1C7C31FBAB9855DDDEBF7CBB474AE"
		description = "None"
		comment = "None"
		author = "cjf"
		date = "2017-05-09"
	strings:
		$s0 = "CAttackBase"
		$s1 = "CPacketAttack"
		$s2 = "CAttackUdp"
		$s3 = "CAttackSyn"
		$s4 = "CAttackIcmp"
		$s5 = "CAttackCompress"
		$s6 = "CTcpAttack"
		$s7 = "CAttackCc"

	condition:
		all of them
}
