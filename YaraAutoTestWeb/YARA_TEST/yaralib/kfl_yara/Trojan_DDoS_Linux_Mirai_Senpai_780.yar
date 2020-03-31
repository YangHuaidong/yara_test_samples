rule Trojan_DDoS_Linux_Mirai_Senpai_780
{
	meta:
		judge = "black"
		threatname = "Trojan[DDoS]/Linux.Mirai.Senpai"
		threattype = "DDoS"
		family = "Mirai"
		hacker = "None"
		refer = "462926a322f15f42d82301ce55a9572f"
		author = "LiuGuangzhu"
		comment = "None"
		date = "2018-09-12"
		description = "None"

	strings:
		$s0 = "/ctrlt/DeviceUpgrade_1"
		$s1 = {5B33353B316D666F6C6C6F77206F75722049473A20726F6F742E73656E70616920616E642031626F74676F641B5B306D}
		$s2 = {5B313B33376D3C1B5B313B33356D4465766963657320436F6E6E65637465641B5B313B33376D3E}
		$s3 = {5B 33 35 3B 31 6D 6F 6F 66 1B 5B 30 6D}
		$s4 = {5B 31 3B 33 37 6D 3C 1B 5B 31 3B 33 35 6D 44 65 76 69 63 65 73 20 43 6F 6E 6E 65 63 74 65 64 1B 5B 31 3B 33 37 6D 3E}
		
	condition:
		$s0 and (($s1 and $s2) or ($s3 and $s4))
}