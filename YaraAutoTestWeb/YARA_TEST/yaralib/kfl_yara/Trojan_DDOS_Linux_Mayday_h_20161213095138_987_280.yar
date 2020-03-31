rule Trojan_DDOS_Linux_Mayday_h_20161213095138_987_280 
{
	meta:
		judge = "black"
		threatname = "Trojan[DDOS]/Linux.Mayday.h"
		threattype = "DDOS"
		family = "Mayday"
		hacker = "None"
		refer = "387D4B2BBE856D8C76C499F32AEE47BF"
		description = "Linux-variant of Chicken ident for both dropper and dropped file"
		comment = "None"
		author = "Jason Jones <jasonjones@arbor.net>"
		date = "2016-11-22"
	strings:
		$cfg = "fake.cfg"
		$file1 = "ThreadAttack.cpp"
		$file2 = "Fake.cpp"
		$str1 = "dns_array"
		$str2 = "DomainRandEx"
		$str3 = "cpu %llu %llu %llu %llu"
		$str4 = "[ %02d.%02d %02d:%02d:%02d.%03ld ] [%lu] [%s] %s" ascii

	condition:
		$cfg and all of ($file*) and 3 of ($str*)
}
