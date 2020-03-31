rule Trojan_Downloader_Win32_Sofacy_ct_534_368
{
    meta:
        judge = "black"
        threatname = "Trojan[Downloader]/Win32.Sofacy.ct"
        threattype = "Downloader"
        family = "Sofacy"
        hacker = "None"
        author = "mqx"
        refer = "809ac196280237b0184ee0bb16879041"
        comment = "None"
        date = "2018-08-08"
        description = "None"
    strings:
        $str1 = "start rundll32.exe"
        $str2 = "cdnver.dll"
        $str3 = "#1"
    condition:
        all of them
}