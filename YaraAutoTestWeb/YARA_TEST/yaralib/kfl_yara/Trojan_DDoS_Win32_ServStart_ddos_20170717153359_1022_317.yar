rule Trojan_DDoS_Win32_ServStart_ddos_20170717153359_1022_317 
{
	meta:
		judge = "black"
		threatname = "Trojan[DDoS]/Win32.ServStart.ddos"
		threattype = "DDOS"
		family = "ServStart"
		hacker = "none"
		refer = "a4ff8d0de578cdadeb70cf0b1207e990"
		description = "None"
		comment = "none"
		author = "xc"
		date = "2017-07-05"
	strings:
		$s0 = "ddos.m0427.com:2017"
		$s1 = "CMD /c ping 127.0.0.1 -n 1&del \"%s\""

	condition:
		all of them
}
