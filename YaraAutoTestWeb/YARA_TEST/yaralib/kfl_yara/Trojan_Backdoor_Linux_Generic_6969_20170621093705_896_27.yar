rule Trojan_Backdoor_Linux_Generic_6969_20170621093705_896_27 
{
	meta:
		judge = "black"
		threatname = "Trojan[Backdoor]/Linux.Tsunami.6969"
		threattype = "BackDoor"
		family = "Tsunami"
		hacker = "none"
		refer = "0eb0bef453fda4e9c3277ce23d4b63ed"
		description = "None"
		comment = "none"
		author = "xc"
		date = "2017-06-19"
	strings:
		$s0 = "/etc/resolv.conf"
		$s1 = "45.76.21.239"
		$s2 = "6969"

	condition:
		all of them
}
