rule Trojan_Downloader_Win32_PutterPanda_bbbbbe_489_175
{
    meta:
        judge = "black"
        threatname = "Trojan[Downloader]/Win32.PutterPanda.bbbbbe"
        threattype = "Downloader"
        family = "PutterPanda"
        hacker = "None"
        author = "balala"
        refer = "08c7b5501df060ccfc3aa5c8c41b452f"
		comment = "None"
        date = "2018-07-25"
        description = "Detects a malware related to Putter Panda"
    strings:
        $s1 = "%s%duserid=%dthreadid=%dgroupid=%d" fullword ascii /* PEStudio Blacklist: strings */ /* score: '22.02' */
        $s2 = "ssdpsvc.dll" fullword ascii /* score: '11.00' */
        $s3 = "Fail %s " fullword ascii /* score: '10.04' */
        $s4 = "%s%dpara1=%dpara2=%dpara3=%d" fullword ascii /* score: '10.01' */
        $s5 = "LsaServiceInit" fullword ascii /* score: '7.03' */
        $s6 = "%-8d Fs %-12s Bs " fullword ascii /* score: '5.04' */
        $s7 = "Microsoft DH SChannel Cryptographic Provider" fullword ascii /* PEStudio Blacklist: strings */ /* score: '5.00' */ /* Goodware String - occured 5 times */

    condition:
        uint16(0) == 0x5a4d and filesize < 1000KB and 5 of them
}