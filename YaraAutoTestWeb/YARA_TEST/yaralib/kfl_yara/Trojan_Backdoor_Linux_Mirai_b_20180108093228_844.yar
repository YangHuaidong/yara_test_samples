rule Trojan_Backdoor_Linux_Mirai_b_20180108093228_844 
{
	meta:
		judge = "black"
		threatname = "Trojan[Backdoor]/Linux.Mirai.b"
		threattype = "BackDoor"
		family = "Mirai"
		hacker = "None"
		refer = "51ce4d6b3259c028b87f1ad912e4334b"
		description = "None"
		comment = "None"
		author = "mqx"
		date = "2017-12-27"
	strings:
		$s0 = "//dev//null"
		$s1 = "_HND_RE"
		$s2 = "lHXOD="
		$s3 = "NI\\IHN="

	condition:
		3 of them
}
