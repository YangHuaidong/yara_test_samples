rule Trojan_Downloader_Win32_Placisc2_a_434_355
{

    meta:
        judge = "black"
				threatname = "Trojan[Downloader]/Win32.Placisc2.a"
				threattype = "Downloader"
				family = "Placisc2"
				hacker = "None"
				comment = "None"
				date = "2016-04-12"
				author = "Microsoft-DC"
				description = "Dipsind variant" 
				refer = "bf944eb70a382bd77ee5b47548ea9a49"
				original_sample_sha1 = "bf944eb70a382bd77ee5b47548ea9a4969de0527"
        unpacked_sample_sha1 = "d807648ddecc4572c7b04405f496d25700e0be6e"

    strings:
        $str1 = {76 16 8B D0 83 E2 07 8A 4C 14 24 8A 14 18 32 D1 88 14 18 40 3B C7 72 EA }
        $str2 = "VPLRXZHTU"
        $str3 = "%d) Command:%s"
        $str4 = {0D 0A 2D 2D 2D 2D 2D 09 2D 2D 2D 2D 2D 2D 0D 0A}

    condition:
        $str1 and $str2 and $str3 and $str4
}