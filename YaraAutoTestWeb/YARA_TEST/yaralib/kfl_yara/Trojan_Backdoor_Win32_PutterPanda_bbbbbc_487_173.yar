rule Trojan_Downloader_Win32_PutterPanda_bbbbbc_487_173
{
    meta:
        judge = "black"
        threatname = "Trojan[Downloader]/Win32.PutterPanda.bbbbbc"
        threattype = "Downloader"
        family = "PutterPanda"
        hacker = "None"
        author = "balala"
        refer = "08c7b5501df060ccfc3aa5c8c41b452f"
		comment = "None"
        date = "2018-07-25"
        description = "Detects a malware related to Putter Panda"
    strings:
        $s0 = "LOADER ERROR" fullword ascii /* PEStudio Blacklist: strings */ /* score: '12.03' */
        $s1 = "The procedure entry point %s could not be located in the dynamic link library %s" fullword ascii /* PEStudio Blacklist: strings */ /* score: '8.045' */
        $s2 = "psapi.dll" fullword ascii /* PEStudio Blacklist: strings */ /* score: '5' */ /* Goodware String - occured 54 times */
        $s3 = "urlmon.dll" fullword ascii /* PEStudio Blacklist: strings */ /* score: '5' */ /* Goodware String - occured 471 times */
        $s4 = "WinHttpGetProxyForUrl" fullword ascii /* PEStudio Blacklist: strings */ /* score: '5' */ /* Goodware String - occured 179 times */

    condition:
        uint16(0) == 0x5a4d and filesize < 300KB and all of them
}