rule Trojan_Linux_Gafgyt_20161213095202_1050_552 
{
	meta:
		judge = "black"
		threatname = "Trojan/Linux.Gafgyt"
		threattype = "DDOS"
		family = "Gafgyt"
		hacker = "None"
		refer = "6b7b6ee71c8338c030997d902a2fa593"
		description = "None"
		comment = "None"
		author = "HuangYY"
		date = "2016-10-09"
	strings:
		$s1 = "/dev/null"
		$s2 = "gLEKLG"
		$s3 = "pgrmpv"
		$s4 = "PGCNVGI"
		$s5 = "CFOKLKQVPCVMP"

	condition:
		all of them
}
