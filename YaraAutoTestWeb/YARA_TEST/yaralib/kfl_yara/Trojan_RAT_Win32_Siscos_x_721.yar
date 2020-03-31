rule Trojan_RAT_Win32_Siscos_x_721
{
    meta:
	    judge = "black"
		threatname = "Trojan[RAT]/Win32.Siscos.x"
		threattype = "RAT"
		family = "Siscos"
		hacker = "None"
		refer = "006e0674bd7847c2467589179c36f59f"
		author = "xc"
		comment = "None"
		date = "2017-09-13"
		description = "None"
	strings:
	    $s0 = "PcServer.EXE"
		$s1 = "fuckyou"
		$s2 = "FAPBWAPEZBESCPINRIOLZSysremZCelrpajNpocessopZ"
		$s3 = "www.swordaa.com"
		$s4 = "YANAVI"
		$s5 = "swopbaa"
		$s6 = "Moxijja"
		$s7 = "duckyou"
		$s8 = "wililer"
	condition:
	    5 of them		
}