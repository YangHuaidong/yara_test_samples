rule Trojan_Backdoor_Win32_Graftor_kpshzyybslb_766_103
{
    meta:
        judge = "black"
        threatname = "Trojan[Backdoor]/Win32.Graftor.kpshzyybslb"
        threattype = "Backdoor"
        family = "Graftor"
        hacker = "None"
        author = "balala"
        refer = "def6e8ad26337890eb262b8f8dd39c17,e645e619856fc2e8101a4e7902120ac3"
        comment = "None"
        date = "2018-10-11"
        description = "None"
	strings:
        $x1 = "GET http://%ws:%d/%d%s%dHTTP/1.1" fullword ascii
        $x2 = "POST http://%ws:%d/%d%s%dHTTP/1.1" fullword ascii
        $x3 = "J:\\chong\\" ascii
        $s1 = "User-Agent: Netscape" fullword ascii
        $s2 = "User-Agent: Mozilla/5.0 (Windows; U; Windows NT 5.1; zh-EN; rv:1.7.12) Gecko/20100719 Firefox/1.0.7" fullword ascii
        $s3 = "Software\\Microsoft\\Windows\\CurrentVersion\\explorer\\User Shell Folders" fullword wide
        $s4 = "J:\\chong\\nod\\Release\\SslMM.exe" fullword ascii
        $s5 = "MM.exe" fullword ascii
        $s6 = "network.proxy.ssl" fullword wide
        $s7 = "PeekNamePipe" fullword ascii
        $s8 = "Host: %ws:%d" fullword ascii
        $s9 = "GET %dHTTP/1.1" fullword ascii
        $s10 = "SCHANNEL.DLL" fullword ascii /* Goodware String - occured 6 times */
    
    condition:
        ( uint16(0) == 0x5a4d and filesize < 300KB and 1 of ($x*) ) or 4 of ($s*)
}