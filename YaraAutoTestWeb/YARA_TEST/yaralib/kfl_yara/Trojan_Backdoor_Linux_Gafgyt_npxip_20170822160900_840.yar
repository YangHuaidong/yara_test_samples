rule Trojan_Backdoor_Linux_Gafgyt_npxip_20170822160900_840 
{
	meta:
		judge = "black"
		threatname = "Trojan[Backdoor]/Linux.Gafgyt.npxip"
		threattype = "BackDoor"
		family = "Gafgyt"
		hacker = "None"
		refer = "11b8acb3eeb757bd7f3c75fa2a3ea257"
		description = "None"
		comment = "None"
		author = "xc"
		date = "2017-08-17"
	strings:
		$s0 = "/etc/resolv.conf"
		$s1 = "npxXoudifFeEgGaACScs"
		$s2 = "87.121.98.34"

	condition:
		all of them
}
