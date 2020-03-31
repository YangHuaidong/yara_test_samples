rule Trojan_Backdoor_Linux_Gafgyt_npxip_669
{
	meta:
		judge = "black"
		threatname = "Trojan[Backdoor]/Linux.Gafgyt.npxip"
		threattype = "Backdoor"
		family = "Gafgyt"
		hacker = "None"
		refer = "11b8acb3eeb757bd7f3c75fa2a3ea257"
		author = "xc"
		comment = "None"
		date = "2017-08-17"
		description = "None"
	strings:
		$s0 = "/etc/resolv.conf"
		$s1 = "npxXoudifFeEgGaACScs"
		$s2 = "87.121.98.34"
	condition:
		all of them
}