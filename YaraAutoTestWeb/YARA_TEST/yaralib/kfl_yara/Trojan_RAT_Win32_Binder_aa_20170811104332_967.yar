rule Trojan_RAT_Win32_Binder_aa_20170811104332_967 
{
	meta:
		judge = "black"
		threatname = "Trojan[RAT]/Win32.Binder.aa"
		threattype = "rat"
		family = "Binder"
		hacker = "None"
		refer = "c0fd77c0db9e51be506f4efdc226e2ad"
		description = "None"
		comment = "None"
		author = "HuangYY"
		date = "2017-07-24"
	strings:
		$s0 = "www.jiaozhu.net"
		$s1 = "sysdebug.exe"
		$s2 = "net.exe"
		$s3 = "user.txt"
		$s4 = "Computer name:  %s"
		$s5 = "Read %d bytes "

	condition:
		all of them
}
