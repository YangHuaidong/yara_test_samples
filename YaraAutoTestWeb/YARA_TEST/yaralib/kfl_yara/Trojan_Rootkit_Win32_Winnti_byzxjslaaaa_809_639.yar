rule Trojan_Rootkit_Win32_Winnti_byzxjslaaaa_809_639
{
    meta:
        judge = "black"
        threatname = "Trojan[Rootkit]/Win32.Winnti.byzxjslaaaa"
        threattype = "Rootkit"
        family = "Winnti"
        hacker = "None"
        author = "balala"
        refer = "68fd2aa16f3b4597cbd446676fade3eb,326cbe7a0eed991ef7fc3d59d7728c6f,ecc7f180d438663185466a9783bd0790"
        comment = "None"
        date = "2018-10-22"
        description = "None"
	strings:
        $s0 = "Proxies destination address/port for TCP" fullword wide
        $s3 = "\\Device\\StreamPortal" fullword wide
        $s4 = "Transport-Data Proxy Sub-Layer" fullword wide
        $s5 = "Cookie: SN=" fullword ascii
        $s6 = "\\BaseNamedObjects\\_transmition_synchronization_" fullword wide
        $s17 = "NTOSKRNL.EXE" fullword wide /* Goodware String - occured 4 times */
        $s19 = "FwpsReferenceNetBufferList0" fullword ascii /* Goodware String - occured 5 times */
  
    condition:
        uint16(0) == 0x5a4d and filesize < 275KB and all of them
}