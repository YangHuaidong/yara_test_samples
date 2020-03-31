rule Trojan_DDoS_Linux_Gafgyt_79_1096
{
	meta:
		judge = "black"
		threatname = "Trojan[DDoS]/Linux.Gafgyt"
		threattype = "DDoS"
		family = "Gafgyt"
		hacker = "None"
		refer = "2e19b4b49b180195ad72e60e29830597"
		author = "lizhenling"
		comment = "None"
		date = "2019-04-18"
		description = "None"

	strings:		
		$s0 = "FAILED TO CONNECT"
		$s1 = "changeme"
		$s2 = "BOGOMIPS"
		$s3 = "/bin/busybox;shell"
		$s4 = "Invalid flag"
		$s5 = "PONG!"
		$s6 = "SCANNER ON | OFF"	
		$s7 = "KILLATTK"		
		
	condition:
		7 of them
}