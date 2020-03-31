rule Trojan_Backdoor_Linux_Dofloo_VERSONEX_20161213095109_892_8 
{
	meta:
		judge = "black"
		threatname = "Trojan[Backdoor]/Linux.Dofloo.VERSONEX"
		threattype = "DDOS"
		family = "Dofloo"
		hacker = "QQ\\uff1a380623650"
		refer = "2450706edbe19e7bef2bccc4da029c37,d8cbba4cdee88c49e11fa73307e24ed0,8aa20d131ba8317c22940ba8f2326504,98b9a58e314a97a29d5c2208dab92840,8ca813032f0e054c52cb6ca264db8ab8,A62BD401421253C27FC38AA8803F1451"
		description = "www.tfddos.com Linux/MrBlack"
		comment = "Linux/MrBlack"
		author = "zhoufenyan"
		date = "2016-07-19"
	strings:
		$s0 = "VERSONEX:Linux"
		$s1 = "connnect server."
		$s2 = "3AES"
		$s3 = "/dev/urandom"
		$s4 = "/dev/random"
		$s5 = "create socket error"
		$s6 = "setsockopt error"

	condition:
		4 of them
}
