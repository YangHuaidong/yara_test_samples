rule Trojan_DDoS_Linux_Gafgyt_Negative_1163
{
	meta:
		judge = "black"
		threatname = "Trojan[DDoS]/Linux.Gafgyt.Negative"
		threattype = "DDoS"
		family = "Gafgyt"
		hacker = "None"
		refer = "43641a051e543dc0e2c498dad2d7b96c,b0db781ef44eeedd8bc16ab4890d6fa5,35f592830f7f58ca41d5a4cc9c036e2f"
		author = "Luoxuan"
		comment = "None"
		date = "2019-05-15"
		description = "None"

	strings:
		$s0 = "thats a negative"
		$s1 = "rf912x123"
		$s2 = "MnR?TLggKh?MK?NQvhxKh"
		$s3 = "auwAdeFHionGmIKJYBvcxgyhPpqQWRLSCtbsE21NOjklV0XZ34D75fzr86MU9"
		$s4 = "npxXoudifFeEgGaACScs"
		
	condition:
		all of them
}