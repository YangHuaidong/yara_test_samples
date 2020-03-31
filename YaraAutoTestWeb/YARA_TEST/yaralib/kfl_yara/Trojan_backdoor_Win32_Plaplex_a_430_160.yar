rule Trojan_backdoor_Win32_Plaplex_a_430_160 
{

    meta:
        judge = "black"
				threatname = "Trojan[backdoor]/Win32.Plaplex.a"
				threattype = "backdoor"
				family = "Plaplex"
				hacker = "None"
				comment = "None"
				date = "2016-04-12"
				author = "Microsoft-DC"
				description = "Variant of the JPin backdoor" 
				refer = "e0ac2ae221328313a7eee33e9be0924c"
				original_sample_sha1 = "ca3bda30a3cdc15afb78e54fa1bbb9300d268d66"
        unpacked_sample_sha1 = "2fe3c80e98bbb0cf5a0c4da286cd48ec78130a24"

    strings:
        $class_name1 = "AVCObfuscation"
        $class_name2 = "AVCSetiriControl"
    
    condition:
        $class_name1 and $class_name2
}