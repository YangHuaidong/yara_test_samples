rule Trojan_Downloader_Win32_APT28_Cyber_Conflict_vba_724_348
{
    meta:
        judge = "black"
				threatname = "Trojan[Downloader]/Win32.APT28_Cyber_Conflict.vba"
				threattype = "Downloader"
				family = "APT28_Cyber_Conflict"
				hacker = "APT28"
				comment = "None"
				date = "2018-07-12"
				author = "dengcong"
				description = "Cyber_Conflict_vba doc for drop trojan,APT28" 
				refer = "94B288154E3D0225F86BB3C012FA8D63"
    strings:
        $str1 = "AutoOpen"
        $str2 = "DecodeBase64"
        $str3 = "Execute"
        $str4 = "add leading zeroes, lengt of hex = 6"
        $str5 = "split hex number into 3 groups, 2 hex characters each:"
        $str6 = "extract and decode encoded file"
        $hexstr1 = {53 75 62 6A 65 63 74 00 20 00 5A 02 21 00 5C 02 25 00 5E 02 01 00 27 00 58 02 00 00 20 00 58 02 20 00 58 02 1B 00 AC 00 32 00 0C 00 24 00 60 02 02 00 27 00 58 02}
        $hexstr2 = {43 6F 6D 70 61 6E 79 00 20 00 5A 02 21 00 5C 02 25 00 5E 02 01 00 27 00 62 02 00 00 20 00 62 02 20 00 62 02 1B 00 AC 00 32 00 0C 00 24 00 60 02 02 00 27 00 62 02}                               
        $hexstr3 = {43 61 74 65 67 6F 72 79 20 00 5A 02 21 00 5C 02 25 00 5E 02 01 00 27 00 64 02 00 00 20 00 64 02 20 00 64 02 1B 00 AC 00 32 00 0C 00 24 00 60 02 02 00 27 00 64 02}
        $hexstr4 = {48 79 70 65 72 6C 69 6E 6B 20 62 61 73 65 20 00 5A 02 21 00 5C 02 25 00 5E 02 01 00 27 00 66 02 00 00 00 00 20 00 66 02 20 00 66 02 1B 00 AC 00 32 00 0C 00 24 00 60 02 02 00 27 00 66 02} 
        $hexstr5 = {43 6F 6D 6D 65 6E 74 73 20 00 5A 02 21 00 5C 02 25 00 5E 02 01 00 27 00 68 02 00 00 20 00 68 02 20 00 68 02 1B 00 AC 00 32 00 0C 00 24 00 60 02 02 00 27 00 68 02}  
        $str7 = "netwf" 
        $str8 = {43 3A 5C 00 B6 00 03 00 23 23 23 00 0B 00 B6 00 03 00 57 69 6E 00 0B 00 B6 00 03 00 23 23 23 00 0B 00 B6 00 03 00 64 6F 77 00 0B 00 B6 00 03 00 23 23 23 00 0B 00 B6 00 04 00 73 5C 53 79 0B 00 B6 00 03 00 23 23 23 00 0B 00 B6 00 03 00 73 74 65 00 0B 00 B6 00 03 00 23 23 23 00 0B 00 B6 00 04 00 6D 33 32 5C 0B 00 B6 00 03 00 72 75 6E 00 0B 00 B6 00 03 00 23 23 23 00 0B 00 B6 00 03 00 64 6C 6C 00 0B 00 B6 00 02 00 33 32 0B 00 B6 00 01 00 23 00 0B 00 B6 00 05 00 2E 65 78 65 20 00 0B 00 B6 00 01 00 22 00 0B 00 20 00 4C 02 0B 00 B6 00 01 00 22 00 0B 00 B6 00 03 00 23 23 23 00 0B 00 B6 00 07 00 2C 4B 6C 70 53 76 63}
    condition:
        all of them
}