rule Trojan_Backdoor_Win32_Hupigon_1_20161213095117_916_108 
{
	meta:
		judge = "black"
		threatname = "Trojan[Backdoor]/Win32.Hupigon.1"
		threattype = "rat"
		family = "Hupigon"
		hacker = "None"
		refer = "48b49bfa62f6f0159f73f7515bf4793b"
		description = "None"
		comment = "None"
		author = "djw"
		date = "2016-09-01"
	strings:
		$s0 = "Hacker.com.cn_MUTEX"
		$s1 = "thread_func()[id=%.8x]"
		$s2 = "vHideProcess"

	condition:
		all of them
}
