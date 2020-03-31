rule Trojan_Downloader_Win32_PutterPanda_bbbbbg_491_177
{
    meta:
        judge = "black"
        threatname = "Trojan[Downloader]/Win32.PutterPanda.bbbbbg"
        threattype = "Downloader"
        family = "PutterPanda"
        hacker = "None"
        author = "balala"
        refer = "08c7b5501df060ccfc3aa5c8c41b452f"
		comment = "None"
        date = "2018-07-25"
        description = "Detects Malware related to PutterPanda - MSUpdater"
    strings:
        $s0 = "msupdater.exe" fullword ascii /* PEStudio Blacklist: strings */ /* score: '20.02' */
        $s1 = "Explorer.exe \"" fullword ascii /* PEStudio Blacklist: strings */ /* score: '16.05' */
        $s2 = "FAVORITES.DAT" fullword ascii /* score: '11.02' */
        $s4 = "COMSPEC" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.82' */ /* Goodware String - occured 178 times */
   
    condition:
        uint16(0) == 0x5a4d and 3 of them
}