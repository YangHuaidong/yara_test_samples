rule Trojan_DDoS_Linux_Triddy_20170811104324_914 
{
	meta:
		judge = "black"
		threatname = "Trojan[DDoS]/Linux.Triddy"
		threattype = "DDOS"
		family = "Triddy"
		hacker = "None"
		refer = "e6706149cb29a70497c23976c756547f"
		description = "None"
		comment = "None"
		author = "HuangYY"
		date = "2017-07-18"
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
