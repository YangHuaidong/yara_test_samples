rule Trojan_DDoS_Win32_Setag_A_20171010143036_948 
{
	meta:
		judge = "black"
		threatname = "Trojan[DDoS]/Win32.Setag.A"
		threattype = "DDOS"
		family = "Setag"
		hacker = "None"
		refer = "b5ec22b8cec1b217826febb4ce2be785"
		description = "None"
		comment = "None"
		author = "HuangYY"
		date = "2017-09-19"
	strings:
		$s0 = "link_list51:continue|"
		$s1 = "task_listl%see"
		$s2 = "Taskkill /F /IM %s"
		$s3 = "libamplify.dll"
		$s4 = "172.16.0.0"
		$s5 = "192.168.0.0"
		$s6 = "Gates.pdb"
		$s7 = "85284A7BFE7CBC82"
		$s8 = "-p %s.exe"

	condition:
		6 of them
}
