rule Trojan_Linux_Gafgyt_Ex_20161213095200_1052_554 
{
	meta:
		judge = "black"
		threatname = "Trojan/Linux.Gafgyt.Ex"
		threattype = "DDOS"
		family = "Gafgyt"
		hacker = "None"
		refer = "5ea32e0bc6181a4aab550bbb534cf78d"
		description = "None"
		comment = "None"
		author = "HuangYY"
		date = "2016-10-10"
	strings:
		$s0 = "fdgets"
		$s1 = "sendHOLD"
		$s2 = "sendJUNK"
		$s3 = "sendUDP"
		$s4 = "sendHTTP"
		$s5 = "sendTCP"
		$s6 = "commServer"

	condition:
		all of them
}
