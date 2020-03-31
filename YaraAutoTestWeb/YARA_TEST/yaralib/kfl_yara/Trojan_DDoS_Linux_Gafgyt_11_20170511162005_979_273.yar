rule Trojan_DDoS_Linux_Gafgyt_11_20170511162005_979_273 
{
	meta:
		judge = "black"
		threatname = "Trojan[DDoS]/Linux.Gafgyt.11"
		threattype = "DDOS"
		family = "Gafgyt"
		hacker = "None"
		refer = "428111c22627e1d4ee87705251704422"
		description = "None"
		comment = "None"
		author = "cjf"
		date = "2017-05-02"
	strings:
		$s0 = "sending"
		$s1 = "ppp0"
		$s2 = "HTTP/1.1"
		$s3 = "bad auth_len gid %d str %d auth %d"
		$s4 = "loginuse="
		$s5 = "Bound"
		$s6 = "SOAPACTION:"

	condition:
		all of them
}
