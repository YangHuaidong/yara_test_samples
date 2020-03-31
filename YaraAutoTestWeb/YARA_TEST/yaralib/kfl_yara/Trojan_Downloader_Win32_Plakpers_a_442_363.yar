rule Trojan_Downloader_Win32_Plakpers_a_442_363
{

    meta:
        judge = "black"
				threatname = "Trojan[Downloader]/Win32.Plakpers.a"
				threattype = "Downloader"
				family = "Plakpers"
				hacker = "None"
				comment = "None"
				date = "2016-04-12"
				author = "Microsoft-DC"
				description = "Injector / loader component" 
				refer = "fa083d744d278c6f4865f095cfd2feab"
				original_sample_sha1 = "fa083d744d278c6f4865f095cfd2feabee558056"
        unpacked_sample_sha1 = "3a678b5c9c46b5b87bfcb18306ed50fadfc6372e"

    strings:
        $str1 = "MyFileMappingObject"
        $str2 = "[%.3u] %s %s %s [%s:" wide
        $str3 = "%s\\{%s}\\%s" wide

    condition:
        $str1 and $str2 and $str3
}
