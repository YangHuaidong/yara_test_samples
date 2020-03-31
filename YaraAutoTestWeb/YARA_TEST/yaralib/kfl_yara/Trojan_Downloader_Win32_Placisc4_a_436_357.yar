rule Trojan_Downloader_Win32_Placisc4_a_436_357 
{

    meta:
        judge = "black"
				threatname = "Trojan[Downloader]/Win32.Placisc4.a"
				threattype = "Downloader"
				family = "Placisc4"
				hacker = "None"
				comment = "None"
				date = "2016-04-12"
				author = "Microsoft-DC"
				description = "Installer for Dipsind variant" 
				refer = "3d17828632e8ff1560f6094703ece543"
				original_sample_sha1 = "3d17828632e8ff1560f6094703ece5433bc69586"
        unpacked_sample_sha1 = "2abb8e1e9cac24be474e4955c63108ff86d1a034"
    
    strings:
        $str1 = {8D 71 01 8B C6 99 BB 0A 00 00 00 F7 FB 0F BE D2 0F BE 04 39 2B C2 88 04 39 84 C0 74 0A}
        $str2 = {6A 04 68 00 20 00 00 68 00 00 40 00 6A 00 FF D5}
        $str3 = {C6 44 24 ?? 64 C6 44 24 ?? 6F C6 44 24 ?? 67 C6 44 24 ?? 32 C6 44 24 ?? 6A}
    
    condition:
        $str1 and $str2 and $str3
}