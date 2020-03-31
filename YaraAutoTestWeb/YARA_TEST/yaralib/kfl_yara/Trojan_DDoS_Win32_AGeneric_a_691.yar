rule Trojan_DDOS_Win32_AGeneric_a_691
{
    meta:
	    judge = "black"
		threatname = "Trojan[DDOS]/Win32.AGeneric.a"
		threattype = "DDOS"
		family = "AGeneric"
		hacker = "None"
		refer = "22377e708c323dbfa8dba7ae3eaabe12"
		author = "mqx"
		comment = "None"
		date = "2017-10-18"
		description = "None"
	strings:
		$s0 = "%c%c%c%c%ccn.exe"
		$s1 = "Host: %s:%d"
		$s3 = "www.baidu.com"
		$s4 = "HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0"
	condition:
	    all of them		
}