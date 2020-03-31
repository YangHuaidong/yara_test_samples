rule Trojan_Backdoor_Win32_Staser_sys_20170407172742_948_215 
{
	meta:
		judge = "black"
		threatname = "Trojan[Backdoor]/Win32.Staser"
		threattype = "DDOS"
		family = "Staser"
		hacker = "None"
		refer = "d21fd3ac438f00d93b9dc98bcba41801"
		description = "None"
		comment = "None"
		author = "sxy"
		date = "2017-02-09"
	strings:
		$s0 = "GET %s%s HTTP/1.1"
		$s1 = "%s%s%s%s%s%s%s%s%s%s%s"
		$s2 = "%d.%d.%d.%d"
		$s3 = "jdfwkey"
		$s4 = "win%ca%cb%cd.exe"

	condition:
		all of them
}
