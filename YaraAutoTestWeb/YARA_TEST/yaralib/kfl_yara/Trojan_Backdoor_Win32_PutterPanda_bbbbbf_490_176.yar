rule Trojan_Downloader_Win32_PutterPanda_bbbbbf_490_176
{
    meta:
        judge = "black"
        threatname = "Trojan[Downloader]/Win32.PutterPanda.bbbbbf"
        threattype = "Downloader"
        family = "PutterPanda"
        hacker = "None"
        author = "balala"
        refer = "08c7b5501df060ccfc3aa5c8c41b452f"
		comment = "None"
        date = "2018-07-25"
        description = "MSUpdater String in Executable"
    strings:
        $x1 = "msupdate.exe" fullword wide /* PEStudio Blacklist: strings */ /* score: '20.01' */
        // $x2 = "msupdate" fullword wide /* PEStudio Blacklist: strings */ /* score: '13.01' */
        $x3 = "msupdater.exe" fullword ascii /* PEStudio Blacklist: strings */ /* score: '20.02' */
        $x4 = "msupdater32.exe" fullword ascii
        $x5 = "msupdater32.exe" fullword wide
        $x6 = "msupdate.pif" fullword ascii
        $fp1 = "_msupdate_" wide /* False Positive */
        $fp2 = "_msupdate_" ascii /* False Positive */
        $fp3 = "/kies" wide

    condition:
        uint16(0) == 0x5a4d and filesize < 500KB and ( 1 of ($x*) ) and not ( 1 of ($fp*) ) 
}