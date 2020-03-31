rule Trojan_Downloader_Win32_Plagicom_a_437_358
{

    meta:
        judge = "black"
				threatname = "Trojan[Downloader]/Win32.Plagicom.a"
				threattype = "Downloader"
				family = "Plagicom"
				hacker = "None"
				comment = "None"
				date = "2016-04-12"
				author = "Microsoft-DC"
				description = "Installer component" 
				refer = "99dcb148b053f4cef6df5fa1ec5d3397"
				original_sample_sha1 = "99dcb148b053f4cef6df5fa1ec5d33971a58bd1e"
        unpacked_sample_sha1 = "c1c950bc6a2ad67488e675da4dfc8916831239a7"

    strings:
        $str1 = {C6 44 24 ?? 68 C6 44 24 ?? 4D C6 44 24 ?? 53 C6 44 24 ?? 56 C6 44 24 ?? 00}
        $str2 = "OUEMM/EMM"
        $str3 = {85 C9 7E 08 FE 0C 10 40 3B C1 7C F8 C3}

    condition:
        $str1 and $str2 and $str3
}