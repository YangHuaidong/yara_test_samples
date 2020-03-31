rule Trojan_backdoor_Win32_Plapiio_a_429_159
{

    meta:
        judge = "black"
				threatname = "Trojan[backdoor]/Win32.Plapiio.a"
				threattype = "backdoor"
				family = "Plapiio"
				hacker = "None"
				comment = "None"
				date = "2016-04-12"
				author = "Microsoft-DC"
				description = "JPin backdoor" 
				refer = "3119de80088c52bd8097394092847cd9"
				original_sample_sha1 = "3119de80088c52bd8097394092847cd984606c88"
        unpacked_sample_sha1 = "3acb8fe2a5eb3478b4553907a571b6614eb5455c"

    strings:
        $str1 = "ServiceMain"
        $str2 = "Startup"
        $str3 = {C6 45 ?? 68 C6 45 ?? 4D C6 45 ?? 53 C6 45 ?? 56 C6 45 ?? 6D C6 45 ?? 6D}

    condition:
        $str1 and $str2 and $str3
}
