rule Trojan_DDoS_Linux_Mirai_al_20170523183537_989_282 
{
	meta:
		judge = "black"
		threatname = "Trojan[DDoS]/Linux.Mirai.al"
		threattype = "DDOS"
		family = "Mirai"
		hacker = "None"
		refer = "b0803b91933fe61b1abc91b001699058"
		description = "None"
		comment = "None"
		author = "cjf"
		date = "2017-05-08"
	strings:
		$s0 = "url="
		$s1 = "POST"
		$s2 = "cFOKLKQVPCVMP"
		$s3 = "OGKLQO"
		$s4 = "QGPTKAG"
		$s5 = "QWRGPTKQMP"
		$s6 = "EWGQV"

	condition:
		all of them
}
