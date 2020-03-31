rule Trojan_backdoor_Win32_Plakelog_a_427_157 
{

    meta:
        judge = "black"
				threatname = "Trojan[backdoor]/Win32.Plakelog.a"
				threattype = "backdoor"
				family = "Plakelog"
				hacker = "None"
				comment = "None"
				date = "2016-04-12"
				author = "Microsoft-DC"
				description = "Raw-input based keylogger"
				refer = "3907a9e41df805f912f821a47031164b"
				original_sample_sha1 = "3907a9e41df805f912f821a47031164b6636bd04"
        unpacked_sample_sha1 = "960feeb15a0939ec0b53dcb6815adbf7ac1e7bb2"

    strings:
        $str1 = "<0x02>" wide
        $str2 = "[CTR-BRK]" wide
        $str3 = "[/WIN]" wide
        $str4 = {8A 16 8A 18 32 DA 46 88 18 8B 15 08 E6 42 00 40 41 3B CA 72 EB 5E 5B}

    condition:
        $str1 and $str2 and $str3 and $str4
}