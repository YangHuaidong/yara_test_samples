rule Trojan_backdoor_Win32_Plainst_a_426_156
{

    meta:
        judge = "black"
				threatname = "Trojan[backdoor]/Win32.Plainst.a"
				threattype = "backdoor"
				family = "Plainst"
				hacker = "None"
				comment = "None"
				date = "2016-04-12"
				author = "Microsoft-DC"
				description = "Installer component"
				refer = "99c08d31af211a0e17f92dd312ec7ca2"
        original_sample_sha1 = "99c08d31af211a0e17f92dd312ec7ca2b9469ecb"
        unpacked_sample_sha1 = "dcb6cf7cf7c8fdfc89656a042f81136bda354ba6"

    strings:
        $str1 = {66 8B 14 4D 18 50 01 10 8B 45 08 66 33 14 70 46 66 89 54 77 FE 66 83 7C 77 FE 00 75 B7 8B 4D FC 89 41 08 8D 04 36 89 41 0C 89 79 04}
        $str2 = {4b D3 91 49 A1 80 91 42 83 B6 33 28 36 6B 90 97}

    condition:
        $str1 and $str2
}