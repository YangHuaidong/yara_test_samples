rule Trojan_backdoor_Win32_Adupib_a_422_35 
{
    
    meta:
        judge = "black"
				threatname = "Trojan[backdoor]/Win32.Adupib.a"
				threattype = "backdoor"
				family = "Adupib"
				hacker = "None"
				comment = "None"
				date = "2016-04-12"
				author = "Microsoft-DC"
				description = "Adupib SSL Backdoor" 
				refer = "d3ad0933e1b114b14c2b3a2c59d7f8a9"
				original_sample_sha1 = "d3ad0933e1b114b14c2b3a2c59d7f8a95ea0bcbd"
        unpacked_sample_sha1 = "a80051d5ae124fd9e5cc03e699dd91c2b373978b"

    strings:
        $str1 = "POLL_RATE"
        $str2 = "OP_TIME(end hour)"
        $str3 = "%d:TCP:*:Enabled"
        $str4 = "%s[PwFF_cfg%d]"
        $str5 = "Fake_GetDlgItemTextW: ***value***="

    condition:
        $str1 and $str2 and $str3 and $str4 and $str5
}