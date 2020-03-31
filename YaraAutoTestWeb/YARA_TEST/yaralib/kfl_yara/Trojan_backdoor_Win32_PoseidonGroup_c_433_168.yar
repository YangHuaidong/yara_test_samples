rule Trojan_backdoor_Win32_PoseidonGroup_c_433_168 
{

    meta:
        judge = "black"
				threatname = "Trojan[backdoor]/Win32.PoseidonGroup.c"
				threattype = "backdoor"
				family = "PoseidonGroup"
				hacker = "None"
				comment = "https://securelist.com/blog/research/73673/poseidon-group-a-targeted-attack-boutique-specializing-in-global-cyber-espionage/"
				date = "2016-02-09"
				author = "Florian Roth-DC"
				description = "Detects Poseidon Group - Malicious Word Document" 
				refer = "e0ac2ae221328313a7eee33e9be0924c"
				original_sample_sha1 = "ca3bda30a3cdc15afb78e54fa1bbb9300d268d66"
        unpacked_sample_sha1 = "2fe3c80e98bbb0cf5a0c4da286cd48ec78130a24"

    strings:
        $s0 = "{\\*\\generator Msftedit 5.41." ascii
        $s1 = "Attachment 1: Complete Professional Background" ascii
        $s2 = "E-mail:  \\cf1\\ul\\f1"
        $s3 = "Education:\\par" ascii
        $s5 = "@gmail.com" ascii

    condition:
        uint32(0) == 0x74725c7b and filesize < 500KB and 3 of them
}
