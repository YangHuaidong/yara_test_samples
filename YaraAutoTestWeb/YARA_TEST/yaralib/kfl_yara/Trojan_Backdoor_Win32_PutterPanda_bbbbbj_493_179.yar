rule Trojan_Downloader_Win32_PutterPanda_bbbbbj_493_179
{
    meta:
        judge = "black"
        threatname = "Trojan[Downloader]/Win32.PutterPanda.bbbbbj"
        threattype = "Downloader"
        family = "PutterPanda"
        hacker = "None"
        author = "balala"
        refer = "08c7b5501df060ccfc3aa5c8c41b452f"
		comment = "None"
        date = "2018-07-25"
        description = "Detects Malware related to PutterPanda - MSUpdater"
    strings:
        $s0 = "winsta0\\default" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.99' */ /* Goodware String - occured 6 times */
        $s1 = "EXPLORER.EXE" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.98' */ /* Goodware String - occured 22 times */
        $s2 = "WNetEnumResourceA" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.97' */ /* Goodware String - occured 29 times */
        $s3 = "explorer.exe" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.97' */ /* Goodware String - occured 31 times */
        $s4 = "CreateProcessAsUserA" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.91' */ /* Goodware String - occured 86 times */
        $s5 = "HttpSendRequestExA" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.91' */ /* Goodware String - occured 87 times */
        $s6 = "HttpEndRequestA" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.91' */ /* Goodware String - occured 91 times */
        $s7 = "GetModuleBaseNameA" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.88' */ /* Goodware String - occured 121 times */
        $s8 = "GetModuleFileNameExA" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.86' */ /* Goodware String - occured 144 times */
        $s9 = "HttpSendRequestA" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.85' */ /* Goodware String - occured 154 times */
        $s10 = "HttpOpenRequestA" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.84' */ /* Goodware String - occured 159 times */
        $s11 = "InternetConnectA" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.82' */ /* Goodware String - occured 183 times */
        $s12 = "Process32Next" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.80' */ /* Goodware String - occured 204 times */
        $s13 = "Process32First" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.79' */ /* Goodware String - occured 210 times */
        $s14 = "CreatePipe" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.78' */ /* Goodware String - occured 222 times */
        $s15 = "EnumProcesses" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.73' */ /* Goodware String - occured 273 times */
        $s16 = "LookupPrivilegeValueA" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.66' */ /* Goodware String - occured 336 times */
        $s17 = "PeekNamedPipe" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.65' */ /* Goodware String - occured 347 times */
        $s18 = "EnumProcessModules" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.59' */ /* Goodware String - occured 410 times */
        $s19 = "PSAPI.DLL" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.58' */ /* Goodware String - occured 420 times */
        $s20 = "SPSSSQ" fullword ascii /* score: '4.51' */
   
    condition:
        uint16(0) == 0x5a4d and filesize < 220KB and all of them
}