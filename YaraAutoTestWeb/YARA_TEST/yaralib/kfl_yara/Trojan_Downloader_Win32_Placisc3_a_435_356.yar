rule Trojan_Downloader_Win32_Placisc3_a_435_356 
{

    meta:
        judge = "black"
				threatname = "Trojan[Downloader]/Win32.Placisc3.a"
				threattype = "Downloader"
				family = "Placisc3"
				hacker = "None"
				comment = "None"
				date = "2016-04-12"
				author = "Microsoft-DC"
				description = "Dipsind variant" 
				refer = "1b542dd0dacfcd4200879221709f5fa9"
				original_sample_sha1 = "1b542dd0dacfcd4200879221709f5fa9683cdcda"
        unpacked_sample_sha1 = "bbd4992ee3f3a3267732151636359cf94fb4575d"

    strings:
        $str1 = {BA 6E 00 00 00 66 89 95 ?? ?? FF FF B8 73 00 00 00 66 89 85 ?? ?? FF FF B9 64 00 00 00 66 89 8D ?? ?? FF FF BA 65 00 00 00 66 89 95 ?? ?? FF FF B8 6C 00 00 00}
        $str2 = "VPLRXZHTU"
        $str3 = {8B 44 24 ?? 8A 04 01 41 32 C2 3B CF 7C F2 88 03}

    condition:
        $str1 and $str2 and $str3
}