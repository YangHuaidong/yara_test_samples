rule Trojan_DDoS_Linux_Triddy_A_786
{
	meta:
		judge = "black"
		threatname = "Trojan[DDoS]/Linux.Triddy.A"
		threattype = "DDoS"
		family = "Triddy"
		hacker = "None"
		refer = "e6706149cb29a70497c23976c756547f"
		author = "HuangYY"
		comment = "None"
		date = "2017-07-18"
		description = "None"

	strings:		
		$s0 = "/sys/devices/system/cpu"
		$s1 = "!exit"
		$s2 = "!webfuck"
		$s3 = "!getid"
		$s4 = "TRUMP IS DADDY"
		$s5 = "!urid"
		$s6 = "!rape"
	condition:
		all of them
}