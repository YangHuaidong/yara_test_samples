rule Trojan_Downloader_Win32_Satan_pecompact_768_367
{
    meta:
        judge = "black"
        threatname = "Trojan[Downloader]/Win32.Satan.pecompact"
        threattype = "Downloader"
        family = "Satan"
        hacker = "None"
        author = "mqx"
        refer = "48c215344cb03e3710b80c6bbc576856"
        comment = "None"
        date = "2018-10-16"
        description = "None"
    strings:
        $pecompact = {B8 [3] 00 50 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 33 C0 89 08 50 45 43}
        $signature = "PECompact2"
        $ciphertext = {D5 51 50 95 B9 11 13 38 BE CB DC A2 BB 57 84 6D 64 1C AB C1 44 5C A4 00 6F AB 8E E8 DF 5C 3A 91}
        $ciphertext2 = {C1 C1 5C E5 16 67 A8 CD 05 D4 E1 E5 5A DB 69 E0 D8 D9 9C 6C A6 EC 1E 8F 4B ED 63 16 21 C8 1F B1}
    condition:
        all of them
}