rule Trojan_Win32_Togapy_bfddos_20161213095310_1116_659 
{
	meta:
		judge = "black"
		threatname = "Trojan/Win32.Togapy.bfddos"
		threattype = "DDOS"
		family = "Togapy"
		hacker = "None"
		refer = "E08883ACFB0CF708FF981C61A00206E0,AAFB7A6E42E1BD727C652368A5A45239"
		description = "None"
		comment = "None"
		author = "wgh"
		date = "2016-06-14"
	strings:
		$s0 = "%u MB"
		$s1 = "Win %s SP%d"
		$s2 = "%s%d.exe"
		$s3 = "count = %d"
		$s4 = "COMSPEC"
		$s5 = "Find CPU Error"
		$s6 = "WebDownFileFlood"
		$s7 = "/c del"

	condition:
		5 of them
}
