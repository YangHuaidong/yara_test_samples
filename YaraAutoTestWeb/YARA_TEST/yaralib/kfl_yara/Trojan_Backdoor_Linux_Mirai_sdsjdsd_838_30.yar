rule Trojan_Backdoor_Linux_Mirai_sdsjdsd_838_30
{
	meta:
		judge = "black"
		threatname = "Trojan[Backdoor]/Linux.Mirai.sdsjdsd"
		threattype = "Backdoor"
		family = "Mirai"
		hacker = "None"
		author = "ljy"
		refer = "f1cc4275d29b7eaa92a4cca015af227e"
		comment = "None"
		date = "2018-11-21"
		description = "None"
	strings:
		$get = "GET /r/sr.arm5 HTTP/1.0"
		$nif = "NIF\n"
	condition:
		$get and $nif and filesize < 700KB 
}
