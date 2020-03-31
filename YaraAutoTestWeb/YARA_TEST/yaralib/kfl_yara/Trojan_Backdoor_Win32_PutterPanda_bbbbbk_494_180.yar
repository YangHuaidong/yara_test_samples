rule Trojan_Downloader_Win32_PutterPanda_bbbbbk_494_180
{
    meta:
        judge = "black"
        threatname = "Trojan[Downloader]/Win32.PutterPanda.bbbbbk"
        threattype = "Downloader"
        family = "PutterPanda"
        hacker = "None"
        author = "balala"
        refer = "08c7b5501df060ccfc3aa5c8c41b452f"
		comment = "None"
        date = "2018-07-25"
        description = "Detects Malware related to PutterPanda - MSUpdater"
    strings:
        $x1 = "rz.dat" fullword ascii /* score: '10.00' */
        $s0 = "Mozilla/4.0 (Compatible; MSIE 6.0;)" fullword ascii /* PEStudio Blacklist: agent */ /* score: '20.03' */
        $s1 = "Internet connect error:%d" fullword ascii /* PEStudio Blacklist: strings */ /* score: '14.04' */
        $s2 = "Proxy-Authorization:Basic " fullword ascii /* PEStudio Blacklist: strings */ /* score: '14.02' */
        $s5 = "Invalid url" fullword ascii /* PEStudio Blacklist: strings */ /* score: '9.03' */
        $s6 = "Create file failed" fullword ascii /* score: '8.04' */
        $s7 = "myAgent" fullword ascii /* score: '8.03' */
        $z1 = "%s%s%d%d" fullword ascii /* score: '8.00' */
        $z2 = "HttpQueryInfo failed:%d" fullword ascii /* PEStudio Blacklist: strings */ /* score: '13.02' */
        $z3 = "read file error:%d" fullword ascii /* score: '11.04' */
        $z4 = "down file success" fullword ascii /* score: '7.04' */
        $z5 = "kPStoreCreateInstance" fullword ascii /* score: '5.03' */
        $z6 = "Avaliable data:%u bytes" fullword ascii /* score: '5.03' */
        $z7 = "abe2869f-9b47-4cd9-a358-c22904dba7f7" fullword ascii /* PEStudio Blacklist: guid */ /* score: '5.00' */ /* Goodware String - occured 2 times */

    condition:
        filesize < 300KB and (( uint16(0) == 0x5a4d and $x1 and 3 of ($s*) ) or ( 3 of ($s*) and 4 of ($z*) ))
}