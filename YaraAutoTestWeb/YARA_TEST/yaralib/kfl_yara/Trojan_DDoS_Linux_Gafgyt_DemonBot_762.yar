rule Trojan_DDoS_Linux_Gafgyt_DemonBot_762
{
	meta:
		judge = "black"
		threatname = "Trojan[DDoS]/Linux.Gafgyt.DemonBot"
		threattype = "DDoS"
		family = "Gafgyt"
		hacker = "None"
		refer = "5aa9640658508805cbd15ff9f2e72a3b"
		author = "LiuGuangzhu"
		comment = "None"
		date = "2018-10-19"
		description = "None"
	strings:
		$s0 = "Sending TCP Packets To: %s:%d for %d seconds"
		$s1 = "/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A"
		$s2 = "[Shelling]-->[%s]-->[%s]-->[%s]-->[%s]-->[%s]"
	condition:
		$s1 or all of them
}