rule Trojan_Backdoor_Linux_Gafgyt_hcIP_20170621093706_895_26 
{
	meta:
		judge = "black"
		threatname = "Trojan[Backdoor]/Linux.Gafgyt.hcIP"
		threattype = "BackDoor"
		family = "Gafgyt"
		hacker = "none"
		refer = "18dc01ebf3367c6c62706ed67e7baf84"
		description = "None"
		comment = "none"
		author = "xc"
		date = "2017-06-19"
	strings:
		$s0 = "mdm9625"
		$s1 = "zyad1234"
		$s2 = "173.0.52.188"

	condition:
		all of them
}
