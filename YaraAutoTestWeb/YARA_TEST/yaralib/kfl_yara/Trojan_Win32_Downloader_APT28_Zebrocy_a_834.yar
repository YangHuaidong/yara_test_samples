rule Trojan_Downloader_Win32_APT28_Zebrocy_a_834
{

    meta:
        judge = "black"
		threatname = "Trojan[Downloader]/Win32.APT28.Zebrocy_a"
		threattype = "Downloader"
		family = "APT28"
		hacker = "APT28"
		comment = "None"
		date = "2018-11-28"
		author = "mqx"
		description = "APT28 zebrocy macro office" 
		refer = "98d1c9770d92ba42607ac5e98fc7486f"
    strings:
        $str1 = "PK"
        $obj1 = {50 4B 03 04 14 00 06 00 08 00 00 00 21 00 38 0B BB 8A 7C 12 00 00 00 2E 00 00 13 00 00 00 77 6F 72 64 2F 76 62 61 50 72 6F 6A 65 63 74 2E 62 69 6E}
        $hex1 = {47 C3 77 CB A4 D3 69 4B 27 0D A5 53 D4 DF 79 1F D2 DA D8 1E C5 D3 99 24 53 AE FC DB 7B EE D7 B9}
        $obj2 = {50 4B 03 04 14 00 06 00 08 00 00 00 21 00 A4 F8 BA 6A E1 FD 06 00 00 6E 0D 00 19 00 00 00 77 6F 72 64 2F 61 63 74 69 76 65 58 2F 61 63 74 69 76 65 58 31 2E 62 69 6E}
        $hex2 = {66 DE 7F E6 AD 66 3E D7 B6 8E 74 74 74 F4 3B A0 93 FB DC B3 AB BC 77 F1 CD EB BE 3F EF 1F B6 5D}
        
    condition:
        all of them
}