rule Trojan_Downloader_Win32_Sofacy_xls_725_369
{
    meta:
        judge = "black"
        threatname = "Trojan[Downloader]/Win32.Sofacy.xls"
        threattype = "Downloader"
        family = "Sofacy"
        hacker = "None"
        author = "mqx"
        refer = "56f98e3ed00e48ff9cb89dea5f6e11c1"
        comment = "None"
        date = "2018-08-08"
        description = "APT28-Romanian Ministry of Foreign Affairs macro xls,APT28"
    strings:
        $header = {D0 CF 11 E0 A1 B1 1A E1}
        $module = "LinesOfBusiness"
        $fun1 = "TQuH8wDO"
        $fun2 = "GetVal"
        $fun3 = "GetRand"
        $fun4 = "cutil"
        $data = {41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 45 41 41 41 34 66 75 67 34 41 74 41}
        $data1 = {46 54 56 6C 65 4C 66 51 67 7A 30 6F 74 66 44 49 74 33 42 49 6C 64 2F 49 58 62 64 44 43 4B 42 44 49 7A 32 34 68 46 43 77 2B 32 77 67 2B 32 79 77 2B 76 79 49 70 46 43 77 4B 4C 56 4A 64 42 41 44 4C 42 51 34 68 46 43 34 50 37 43 6E 4C 6A 69 31 }
    condition:
        all of them
}
