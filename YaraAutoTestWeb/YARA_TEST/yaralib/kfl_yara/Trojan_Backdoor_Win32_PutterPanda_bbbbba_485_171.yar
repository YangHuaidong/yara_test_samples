rule Trojan_Backdoor_Win32_PutterPanda_bbbbba_485_171
{
    meta:
        judge = "black"
        threatname = "Trojan[Backdoor]/Win32.PutterPanda.bbbbba"
        threattype = "backdoor"
        family = "PutterPanda"
        hacker = "None"
        author = "balala"
        refer = "84b8026b3f5e6dcfb29e82e0b0b0f386"
		comment = "None"
        date = "2018-07-25"
        description = "Detects an APT malware related to PutterPanda"
    strings:
        $x0 = "app.stream-media.net" fullword ascii /* score: '12.03' */
        $x1 = "File %s does'nt exist or is forbidden to acess!" fullword ascii /* PEStudio Blacklist: strings */ /* score: '16.035' */
        $s6 = "GetProcessAddresss of pHttpQueryInfoA Failed!" fullword ascii /* PEStudio Blacklist: strings */ /* score: '32.02' */
        $s7 = "Connect %s error!" fullword ascii /* PEStudio Blacklist: strings */ /* score: '16.04' */
        $s9 = "Download file %s successfully!" fullword ascii /* PEStudio Blacklist: strings */ /* score: '14.03' */
        $s10 = "index.tmp" fullword ascii /* score: '14.03' */
        $s11 = "Execute PE Successfully" fullword ascii /* PEStudio Blacklist: strings */ /* score: '13.03' */
        $s13 = "aa/22/success.xml" fullword ascii /* score: '12.005' */
        $s16 = "aa/22/index.asp" fullword ascii /* score: '11.02' */
        $s18 = "File %s a Non-Pe File" fullword ascii /* score: '8.04' */
        $s19 = "SendRequset error!" fullword ascii /* score: '8.04' */
        $s20 = "filelist[%d]=%s" fullword ascii /* score: '7.015' */

    condition:
        ( uint16(0) == 0x5a4d and 1 of ($x*) ) or ( 4 of ($s*) )
}