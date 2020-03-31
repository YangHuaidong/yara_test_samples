rule Trojan_DDOS_Linux_XorDDoS_APT1_WEBC2_Y21K_20161213095142_998_290 
{
	meta:
		judge = "black"
		threatname = "Trojan[DDOS]/Linux.XorDDoS.APT1_WEBC2_Y21K"
		threattype = "DDOS"
		family = "XorDDoS"
		hacker = "None"
		refer = "9B8D5DD3D73172D9A6DA57E60724C4ED"
		description = "CommentCrew-threat-apt1"
		comment = "None"
		author = "AlienVault Labs"
		date = "2016-06-23"
	strings:
		$1 = "Y29ubmVjdA" wide ascii // connect
		$2 = "c2xlZXA" wide ascii // sleep
		$3 = "cXVpdA" wide ascii // quit
		$4 = "Y21k" wide ascii // cmd
		$5 = "dW5zdXBwb3J0" wide ascii // unsupport

	condition:
		4 of them
}
