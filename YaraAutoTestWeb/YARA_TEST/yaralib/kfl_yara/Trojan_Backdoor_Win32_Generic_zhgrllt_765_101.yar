rule Trojan_Backdoor_Win32_Generic_zhgrllt_765_101
{
    meta:
        judge = "black"
        threatname = "Trojan[Backdoor]/Win32.Generic.zhgrllt"
        threattype = "Backdoor"
        family = "Generic"
        hacker = "None"
        author = "balala"
        refer = "92861d0a999591aeb72988b56d458040,b35f2de87343a674f5c1d809a5666349,def6e8ad26337890eb262b8f8dd39c17,e645e619856fc2e8101a4e7902120ac3,a2378fd84cebe4b58c372d1c9b923542,7890eda704de4fe3f0af555c0be6ccba"
        comment = "None"
        date = "2018-10-11"
        description = "None"
	strings:
        $x1 = "greensky27.vicp.net" fullword wide
        $x2 = "POST http://%s:%d/aspxabcdefg.asp?%s HTTP/1.1" fullword ascii
        $x3 = "GET http://%s:%d/aspxabcdef.asp?%s HTTP/1.1" fullword ascii
        /* additional strings based on PDF report - not found in samples */
        $x4 = "serch.vicp.net" fullword wide
        $x5 = "greensky27.vicp.net" fullword wide
        $x6 = "greensky27.vicp.net.as" fullword wide
        $x7 = "greensky27.vcip.net" fullword wide
        $x8 = "pnoc-ec.vicp.net" fullword wide
        $x9 = "aseanph.vicp.net" fullword wide
        $x10 = "pnoc.vicp.net" fullword wide
        $a1 = "dMozilla/4.0 (compatible; MSIE 6.0;Windows NT 5.0; .NET CLR 1.1.4322)" fullword wide /* typo */
        $a2 = "User-Agent: Netscape" fullword ascii /* ;) */
        $a3 = "Accept-Language:En-us/r/n" fullword wide /* typo */
        $a4 = "\\Office Start.lnk" fullword wide
        $a5 = "\\MSN Talk Start.lnk" fullword wide
        $s1 = "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.0; .NET CLR 1.1.4322)" fullword wide
        $s2 = "User-Agent: Mozilla/5.0 (Windows; U; Windows NT 5.1; zh-EN; rv:1.7.12) Gecko/20100719 Firefox/1.0.7" fullword ascii
        $s3 = "%USERPROFILE%\\Application Data\\Mozilla\\Firefox\\Profiles" fullword wide
        $s4 = "Content-Type:application/x-www-form-urlencoded/r/n" fullword wide
        $s5 = "Hello World!" fullword wide
        $s6 = "Accept-Encoding:gzip,deflate/r/n" fullword wide
        $s7 = "/%d%s%d" fullword ascii
        $s8 = "%02d-%02d-%02d %02d:%02d" fullword wide
        $s9 = "WininetMM Version 1.0" fullword wide
        $s10 = "WININETMM" fullword wide
        $s11 = "GET %dHTTP/1.1" fullword ascii
        $s12 = "POST http://%ws:%d/%d%s%dHTTP/1.1" fullword ascii
        $s13 = "PeekNamePipe" fullword ascii
        $s14 = "Normal.dot" fullword ascii
        $s15 = "R_eOR_eOR_eO)CiOS_eO" fullword ascii
        $s16 = "DRIVE_RAMDISK" fullword wide
        $s17 = "%s %s %s %s %d %d %d %d " fullword ascii
    
    condition:
        ( uint16(0) == 0x5a4d and filesize < 250KB and 1 of ($x*) ) or 2 of ($a*) or 6 of ($s*) 
}