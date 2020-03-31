rule Trojan_Backdoor_Linux_Gafgyt_npx222_667
{
	meta:
		judge = "black"
		threatname = "Trojan[Backdoor]/Linux.Gafgyt.npx222"
		threattype = "Backdoor"
		family = "Gafgyt"
		hacker = "None"
		refer = "076a191da6a29906840b708cffca9810"
		author = "xc"
		comment = "None"
		date = "2017-08-17"
		description = "None"
	strings:
		$s0 = "hlLjztqZ"
		$s1 = "attempts"
		$s2 = "/etc/resolv.conf"
		$s3 = "npxXoudifFeEgGaACScs"
	condition:
		all of them
}