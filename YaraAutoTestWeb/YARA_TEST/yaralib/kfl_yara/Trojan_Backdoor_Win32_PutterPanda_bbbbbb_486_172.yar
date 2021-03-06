rule Trojan_Downloader_Win32_PutterPanda_bbbbbb_486_172
{
    meta:
        judge = "black"
        threatname = "Trojan[Downloader]/Win32.PutterPanda.bbbbbb"
        threattype = "Downloader"
        family = "PutterPanda"
        hacker = "None"
        author = "balala"
        refer = "08c7b5501df060ccfc3aa5c8c41b452f"
		comment = "None"
        date = "2018-07-25"
        description = "APT Malware related to PutterPanda Group"
    strings:
        $s0 = "http://update.konamidata.com/test/zl/sophos/td/result/rz.dat?" fullword ascii /* PEStudio Blacklist: strings */ /* score: '28.01' */
        $s1 = "http://update.konamidata.com/test/zl/sophos/td/index.dat?" fullword ascii /* PEStudio Blacklist: strings */ /* score: '28.01' */
        $s2 = "Mozilla/4.0 (Compatible; MSIE 6.0;)" fullword ascii /* PEStudio Blacklist: agent */ /* score: '20.03' */
        $s3 = "Internet connect error:%d" fullword ascii /* PEStudio Blacklist: strings */ /* score: '14.035' */
        $s4 = "Proxy-Authorization:Basic" fullword ascii /* PEStudio Blacklist: strings */ /* score: '14.02' */
        $s5 = "HttpQueryInfo failed:%d" fullword ascii /* PEStudio Blacklist: strings */ /* score: '13.015' */
        $s6 = "read file error:%d" fullword ascii /* score: '11.04' */
        $s7 = "downdll.dll" fullword ascii /* score: '11.025' */
        $s8 = "rz.dat" fullword ascii /* score: '10.005' */
        $s9 = "Invalid url" fullword ascii /* PEStudio Blacklist: strings */ /* score: '9.03' */
        $s10 = "Create file failed" fullword ascii /* score: '8.045' */
        $s11 = "myAgent" fullword ascii /* score: '8.025' */
        $s12 = "%s%s%d%d" fullword ascii /* score: '8.005' */
        $s13 = "down file success" fullword ascii /* score: '7.035' */
        $s15 = "error!" fullword ascii /* score: '6.04' */
        $s18 = "Avaliable data:%u bytes" fullword ascii /* score: '5.025' */
    
    condition:
        uint16(0) == 0x5a4d and 6 of them
}