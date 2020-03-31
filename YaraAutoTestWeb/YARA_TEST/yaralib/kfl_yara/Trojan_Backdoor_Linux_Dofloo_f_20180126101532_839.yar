rule Trojan_Backdoor_Linux_Dofloo_f_20180126101532_839 
{
	meta:
		judge = "black"
		threatname = "Trojan[Backdoor]/Linux.Dofloo.f"
		threattype = "BackDoor"
		family = "Dofloo"
		hacker = "None"
		refer = "283f4d7bb142ccf7d2e0aed13dc8f8bd"
		description = "None"
		comment = "None"
		author = "mqx"
		date = "2017-01-18"
	strings:
		$s0 = "ddos.tf/LinuxTF"
		$s1 = "ddos.tf/dat/worm.TF"
		$s2 = "ddos.tf/dat/MipsLinux.TF"
		$s3 = "ddos.tf/dat/ARMv6Linux.TF"

	condition:
		all of them
}
