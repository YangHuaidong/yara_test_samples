rule Trojan_Win32_Yoddos_exp_20170412094604_1118_661 
{
	meta:
		judge = "black"
		threatname = "Trojan[Backdoor]/Win32.Yoddos.exp"
		threattype = "RAT|DDOS"
		family = "Yoddos"
		hacker = "None"
		refer = "54b03331dc121785dd90c3ea0c868bc4,9dd50a49b6a46937659265a0928ccc98,93d7952f28e12410d44471546cfa5ea2"
		description = "None"
		comment = "None"
		author = "sxy"
		date = "2017-03-29"
	strings:
		$s0 = "explorer.exe"
		$s1 = "SOFTWARE\\360Safe\\safemon"
		$s2 = "ntvdm.exe"
		$s3 = "C H R N = %d %d %d %d"
		$s4 = "%s=%3.3u,%3.3u,%s\\system32\\%s.sys%s"
		$s5 = "%s,%d,%s"

	condition:
		all of them
}
