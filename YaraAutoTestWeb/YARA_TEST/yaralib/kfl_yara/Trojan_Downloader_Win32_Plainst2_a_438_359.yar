rule Trojan_Downloader_Win32_Plainst2_a_438_359 
{

    meta:
        judge = "black"
				threatname = "Trojan[Downloader]/Win32.Plainst2.a"
				threattype = "Downloader"
				family = "Plainst2"
				hacker = "None"
				comment = "None"
				date = "2016-04-12"
				author = "Microsoft-DC"
				description = "Zc tool" 
				refer = "3f2ce812c38ff5ac3d813394291a5867"
				original_sample_sha1 = "3f2ce812c38ff5ac3d813394291a5867e2cddcf2"
        unpacked_sample_sha1 = "88ff852b1b8077ad5a19cc438afb2402462fbd1a"

    strings:
        $str1 = "Connected [%s:%d]..."
        $str2 = "reuse possible: %c"
        $str3 = "] => %d%%\x0a"

    condition:
        $str1 and $str2 and $str3
}