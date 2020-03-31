rule Trojan_RAT_Win32_Symmi_busi_722
{
    meta:
	        judge = "black"
			threatname = "Trojan[RAT]/Win32.Symmi.busi"
			threattype = "RAT"
			family = "Symmi"
			hacker = "none"
			refer = "a68bc875b14270ea9cc2f61ffae1414f"
			comment = "none"
			author = "xc"
			date = "2017-07-27"
			description = "None"
	strings:
			$s0 = "del busi.exe"
			$s1 = "del busi.batMZ"
			$s2 = "manhack.txt"
			$s3 = "222.186.191.180"
    condition:
            all of them
}