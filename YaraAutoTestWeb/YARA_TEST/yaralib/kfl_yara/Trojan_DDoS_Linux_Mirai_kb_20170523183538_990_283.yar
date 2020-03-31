rule Trojan_DDoS_Linux_Mirai_kb_20170523183538_990_283 
{
	meta:
		judge = "black"
		threatname = "Trojan[DDoS]/Linux.Mirai.kb"
		threattype = "DDOS"
		family = "Mirai"
		hacker = "None"
		refer = "40d84f032d6f35898d86d59aa7ae732c"
		description = "None"
		comment = "None"
		author = "cjf"
		date = "2017-05-08"
	strings:
		$s0 = "mirai"
		$s1 = "notJapanese"
		$s2 = "action"
		$s3 = "5Start"
		$s4 = "http"
		$s5 = "main"

	condition:
		all of them
}
