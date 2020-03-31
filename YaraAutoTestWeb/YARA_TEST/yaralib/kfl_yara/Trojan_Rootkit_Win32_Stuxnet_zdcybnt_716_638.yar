rule Trojan_Rootkit_Win32_Stuxnet_zdcybnt_716_638
{
    meta:
        judge = "black"
        threatname = "Trojan[Rootkit]/Win32.Stuxnet.zdcybnt"
        threattype = "Rootkit"
        family = "Stuxnet"
        hacker = "None"
        author = "balala"
        refer = "1e17d81979271cfa44d471430fe123a5"
        comment = "None"
        date = "2018-09-05"
        description = "None"
	strings:
        $s1 = "\\SystemRoot\\System32\\hal.dll" fullword wide
        $s2 = "http://www.jmicron.co.tw0" fullword ascii
   
    condition:
        uint16(0) == 0x5a4d and filesize < 70KB and all of them

}