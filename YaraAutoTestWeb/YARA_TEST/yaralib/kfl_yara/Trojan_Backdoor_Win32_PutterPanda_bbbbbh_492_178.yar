rule Trojan_Downloader_Win32_PutterPanda_bbbbbh_492_178
{
    meta:
        judge = "black"
        threatname = "Trojan[Downloader]/Win32.PutterPanda.bbbbbh"
        threattype = "Downloader"
        family = "PutterPanda"
        hacker = "None"
        author = "balala"
        refer = "08c7b5501df060ccfc3aa5c8c41b452f"
		comment = "None"
        date = "2018-07-25"
        description = "Detects Malware related to PutterPanda - MSUpdater"
     strings:
        $x0 = "msupdate.exe" fullword wide /* PEStudio Blacklist: strings */ /* score: '20.01' */
        $x1 = "msupdate" fullword wide /* PEStudio Blacklist: strings */ /* score: '13.01' */
        $s1 = "Microsoft Corporation. All rights reserved." fullword wide /* score: '8.04' */
        $s2 = "Automatic Updates" fullword wide /* PEStudio Blacklist: strings */ /* score: '4.98' */ /* Goodware String - occured 22 times */
        $s3 = "VirtualProtectEx" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.93' */ /* Goodware String - occured 68 times */
        $s4 = "Invalid parameter" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.93' */ /* Goodware String - occured 69 times */
        $s5 = "VirtualAllocEx" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.91' */ /* Goodware String - occured 95 times */
        $s6 = "WriteProcessMemory" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.87' */ /* Goodware String - occured 131 times */
    condition:
        ( uint16(0) == 0x5a4d and 1 of ($x*) and 4 of ($s*) ) or ( 1 of ($x*) and all of ($s*) ) 
}