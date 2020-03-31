rule Trojan_Backdoor_Linux_Mirai_n_672
{
	meta:
	    judge = "black"
		threatname = "Trojan[Backdoor]/Linux.Mirai.n"
		threattype = "Backdoor"
		family = "Mirai"
		hacker = "None"
		refer = "287829cfc664289f9fe8786772e656b2"
		author = "mqx"
		comment = "None"
		date = "2017-10-16"
		description = "None"
	strings:
	    $s0 = "ogin"
		$s1 = "/dev/watchdog"
		$s2 = "ZZZZZZ"
		$s3 = "/dev/null"
		$s4 = "assword"
	condition:
	    all of them	
}