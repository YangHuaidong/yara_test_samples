rule Trojan_DDoS_Linux_Gafgyt_88_1097
{
	meta:
		judge = "black"
		threatname = "Trojan[DDoS]/Linux.Gafgyt"
		threattype = "DDoS"
		family = "Gafgyt"
		hacker = "None"
		refer = "8afcde4ddb2f600c63fae81711906765"
		author = "lizhenling"
		comment = "None"
		date = "2019-04-18"
		description = "None"

	strings:		
		$s0 = "type_codes"
		$s1 = "UpdateNameSrvs"
		$s2 = "read_until_response"
		$s3 = "SendUDP"
		$s4 = "getRandomIP"
		$s5 = "makeRandomStr"
		
	condition:
		all of them
}