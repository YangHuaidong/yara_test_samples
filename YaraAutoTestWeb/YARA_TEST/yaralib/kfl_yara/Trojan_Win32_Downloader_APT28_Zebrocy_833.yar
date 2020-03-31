rule Trojan_Downloader_Win32_APT28_Zebrocy_833
{

    meta:
        judge = "black"
		threatname = "Trojan[Downloader]/Win32.APT28.Zebrocy"
		threattype = "Downloader"
		family = "APT28"
		hacker = "APT28"
		comment = "None"
		date = "2018-11-27"
		author = "mqx"
		description = "APT28 zebrocy macro office" 
		refer = "e4ef63f74d55930157bc425bf3bd856f"
    strings:
        $str1 = "PK"
        $str2 = "vbaProject.bin"
        $hex = {50 4B 03 04 14 00 06 00 08 00 00 00 21 00 FA EE CC 9B 7F 26 07 00 00 DA 09 00 13 00 00 00}
        $hex2 = {7D 0F 7C 54 C5 B5 FF DC BB 4B D8 FC 21 6C F8 67 A0 FC B9 24 08 E1 4F C2 66 09 21 68 D4 FD 97 05 24 21 91 44 48 35 CA 6E 92 1B 12 D9 64 D7 CD 26 06 14 D9 40 A8 88 FF A8 22 62 D5 4A A9 D5 68 A9 D2 6A 29 56 E5 17 D4 A7 B4 B5 8A 95 3E A9 B5 8A 7F 9E 3F}
        $hex3 = {11 47 28 46 CD 4E F9 73 B6 0B 95 ED 82 E4 5B 61 89 BB 30 6B 14 C8 DE 85 2B D0 2E CC DC 29 EC 6D 99 72 C7 62 04 D2 91 2A 42 2A 9D D7 9E C5 DB B5 43 C8 DB 9B A2 D5 77 50 A4 FB 30 AC D4 BE E3 42}
    condition:
        all of them
}