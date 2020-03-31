rule Trojan_DDoS_Win32_Mirai_Wget_20170412094559_1015_306 
{
	meta:
		judge = "black"
		threatname = "Trojan[DDoS]/Win32.Mirai.Wget"
		threattype = "DDOS"
		family = "Mirai"
		hacker = "None"
		refer = "8e6f4c1d993d43e7e30c9454f511e6dd,05163f24091f1e659c1f799209c798bd"
		description = "sh code to download and execute the dvrHelper module of mirai"
		comment = "None"
		author = "djw"
		date = "2017-04-06"
	strings:
		$s0 = "./dvrHelper"
		$s1 = "chmod 777 dvrHelper"
		$s2 = "#!/bin/sh"

	condition:
		all of them
}
