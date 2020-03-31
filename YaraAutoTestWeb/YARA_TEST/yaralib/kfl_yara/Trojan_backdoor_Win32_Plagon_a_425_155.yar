rule Trojan_backdoor_Win32_Plagon_a_425_155
{
   
    meta:
        judge = "black"
				threatname = "Trojan[backdoor]/Win32.Plagon.a"
				threattype = "backdoor"
				family = "Plagon"
				hacker = "None"
				comment = "None"
				date = "2016-04-12"
				author = "Microsoft-DC"
				description = "Dipsind variant" 
				refer = "48b89f61d58b57dba6a0ca857bce97ba"
				original_sample_sha1 = "48b89f61d58b57dba6a0ca857bce97bab636af65"
        unpacked_sample_sha1 = "6dccf88d89ad7b8611b1bc2e9fb8baea41bdb65a"

    strings:
        $str1 = "VPLRXZHTU"
        $str2 = {64 6F 67 32 6A 7E 6C}
        $str3 = "Dqpqftk(Wou\"Isztk)"
        $str4 = "StartThreadAtWinLogon"
        condition:
        $str1 and $str2 and $str3 and $str4
}