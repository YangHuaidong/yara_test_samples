rule Trojan_DDoS_Linux_Mirai_Hello_779
{
	meta:
		judge = "black"
		threatname = "Trojan[DDoS]/Linux.Mirai.Hello"
		threattype = "DDoS"
		family = "Mirai"
		hacker = "None"
		refer = "03769bd29bead0acb1335afe605d06cf"
		author = "LiuGuangzhu"
		comment = "None"
		date = "2018-09-11"
		description = "None"

	strings:
		$s0 = "/GponForm/diag_Form?images/"
		$s1 = "selfrep.huawei"
		$s2 = "/picsdesc.xml"
		$s3 = "selfrep.realtek"
		$s4 = "XWebPageName=diag&diag_action=ping&wan_conlist=0"
		$s5 = {baa5b9becac5899e98869ec5ae8f9c83898fbf9a8d988b8e8fb5dbcaa2bebebac5dbc4dbea}
	condition:
		all of them
}