rule Trojan_Linux_Mirai_Source_20170324123756_1063_563 
{
	meta:
		judge = "black"
		threatname = "Trojan/Linux.Mirai.Source"
		threattype = "DDOS"
		family = "Mirai"
		hacker = "None"
		refer = "ca501f627e1ef5df266577a81342bf22"
		description = "None"
		comment = "None"
		author = "LGZ"
		date = "2017-03-13"
	strings:
		$s0 = "SUATAUAVAW"
		$s1 = "attack.go"
		$s2 = "mirai"
		$s3 = "clientList.go"
		$s5 = "zversion.go"
		$s6 = "scanListen.go"

	condition:
		3 of them
}
