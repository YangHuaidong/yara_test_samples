rule Trojan_DDoS_Win32_Linux_Ay_20171211110714_928 
{
	meta:
		judge = "black"
		threatname = "Trojan[DDoS]/Linux.Gafgyt.Ay"
		threattype = "DDOS"
		family = "Gafgyt"
		hacker = "None"
		refer = "8E16C2D1FF6E385D66A509340DB88173,3754E891D4BF86D784FF7496A25920A9"
		description = "None"
		comment = "None"
		author = "LiuGuangzhu"
		date = "2017-09-07"
	strings:
		$s0 = "cd /tmp; wget"
		$s1 = ".%d.%d"
		$s2 = "REPORT %s:%s:%s"
		$s3 = "gayfgt"
		$s4 = "STD <target> <port> <time>"
		$s5 = "CNC <target> <port> <time>"
		$s6 = "SCANNER ON | OFF"
		$s7 = "BUILD %s:%s"
		$s8 = "My Public IP: %s"

	condition:
		all of them
}
