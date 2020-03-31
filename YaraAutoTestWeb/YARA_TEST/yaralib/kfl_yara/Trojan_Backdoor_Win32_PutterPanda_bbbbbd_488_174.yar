rule Trojan_Downloader_Win32_PutterPanda_bbbbbd_488_174
{
    meta:
        judge = "black"
        threatname = "Trojan[Downloader]/Win32.PutterPanda.bbbbbd"
        threattype = "Downloader"
        family = "PutterPanda"
        hacker = "None"
        author = "balala"
        refer = "08c7b5501df060ccfc3aa5c8c41b452f"
		comment = "None"
        date = "2018-07-25"
        description = "Detects a malware related to Putter Panda"
    strings:
        $x0 = "WUAUCLT.EXE" fullword wide /* PEStudio Blacklist: strings */ /* score: '20.01' */
        $x1 = "%s\\tmp%d.exe" fullword ascii /* score: '14.01' */   
        $x2 = "Microsoft Corporation. All rights reserved." fullword wide /* score: '8.04' */
        $s1 = "Microsoft Windows Operating System" fullword wide /* PEStudio Blacklist: strings */ /* score: '5' */ /* Goodware String - occured 4 times */
        $s2 = "InternetQueryOptionA" fullword ascii /* PEStudio Blacklist: strings */ /* score: '5' */ /* Goodware String - occured 166 times */
        $s3 = "LookupPrivilegeValueA" fullword ascii /* PEStudio Blacklist: strings */ /* score: '5' */ /* Goodware String - occured 336 times */
        $s4 = "WNetEnumResourceA" fullword ascii /* PEStudio Blacklist: strings */ /* score: '5' */ /* Goodware String - occured 29 times */
        $s5 = "HttpSendRequestExA" fullword ascii /* PEStudio Blacklist: strings */ /* score: '5' */ /* Goodware String - occured 87 times */
        $s6 = "PSAPI.DLL" fullword ascii /* PEStudio Blacklist: strings */ /* score: '5' */ /* Goodware String - occured 420 times */
        $s7 = "Microsoft(R) Windows(R) Operating System" fullword wide /* PEStudio Blacklist: strings */ /* score: '5' */ /* Goodware String - occured 128 times */
        $s8 = "CreatePipe" fullword ascii /* PEStudio Blacklist: strings */ /* score: '5' */ /* Goodware String - occured 222 times */
        $s9 = "EnumProcessModules" fullword ascii /* PEStudio Blacklist: strings */ /* score: '5' */ /* Goodware String - occured 410 times */

    condition:
        all of ($x*) or (1 of ($x*) and all of ($s*) )
}