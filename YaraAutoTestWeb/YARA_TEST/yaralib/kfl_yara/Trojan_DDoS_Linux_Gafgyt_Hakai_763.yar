rule Trojan_DDoS_Linux_Gafgyt_Hakai_763
{
	meta:
		judge = "black"
		threatname = "Trojan[DDoS]/Linux.Gafgyt.Hakai"
		threattype = "DDoS"
		family = "Gafgyt"
		hacker = "None"
		refer = "0c518e35451917abf53509be68dcca97"
		author = "LiuGuangzhu"
		comment = "None"
		date = "2018-09-04"
		description = "None"

	strings:
		$s0 = "/HNAP1/"
		$s1 = "/ctrlt/DeviceUpgrade_1"
		$s2 = "/picsdesc.xml"
		$s3 = "/login.cgi?cli=aa%20aa%27"
		$s4 = "/cdn-cgi/l/chk_captcha"
		$s5 = "Connected [ ARCH:%s ] [ HOST:%s ]"
		$s6 = "netlink send"
		$s7 = "netlink recv"
	condition:
		//4 of them
		$s4 and $s5 and (($s0 and $s1 and $s2 and $s3) or ($s6 and $s7))
}