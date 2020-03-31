rule Trojan_Backdoor_Win32_Siscos_xb_20171221111844_876 
{
	meta:
		judge = "black"
		threatname = "Trojan[Backdoor]/Win32.Siscos.xb"
		threattype = "BackDoor"
		family = "Siscos"
		hacker = "None"
		refer = "062787b419487d53ad46f7edda50f00f"
		description = "None"
		comment = "None"
		author = "xc"
		date = "2017-09-28"
	strings:
		$s0 = "2.1.0.37"
		$s1 = "daijeb"
		$s2 = "duckyou"
		$s3 = "www.baidu.com"
		$s4 = "jpg|jpeg|gif"

	condition:
		4 of them
}
