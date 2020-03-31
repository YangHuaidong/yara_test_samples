rule Trojan_Backdoor_Linux_Tsunami_B_20170619115454_898_32 
{
	meta:
		judge = "black"
		threatname = "Trojan[Backdoor]/Linux.Tsunami.B"
		threattype = "DDOS"
		family = "Tsunami"
		hacker = "None"
		refer = "432da226279b1d29bf077cbb689777eb"
		description = "None"
		comment = "None"
		author = "LGZ"
		date = "2017-06-07"
	strings:
		$s0 = "andemo shiranai wa yo,"
		$s1 = "shitteru koto dake"

	condition:
		all of them
}
