rule Trojan_Rootkit_Win32_Winnti_wdgrmlznl_812_642
{
    meta:
        judge = "black"
        threatname = "Trojan[Rootkit]/Win32.Winnti.wdgrmlznl"
        threattype = "Rootkit"
        family = "Winnti"
        hacker = "None"
        author = "balala"
        refer = "5d5b5dd068c341034cb3cc6225927399,1a54dfe8a5de2a3d99584c2516a7b525,6a43df6cfc2d603f6529a5de00c9f1f6"
        comment = "None"
        date = "2018-10-22"
        description = "None"
	strings:
        $s0 = "\\Registry\\Machine\\System\\CurrentControlSet\\Control\\Class\\{4D36E972-E325-11CE-BFC1-08002BE10318}\\" fullword wide
        $s1 = "%x:%d->%x:%d, Flag %s%s%s%s%s, seq %u, ackseq %u, datalen %u" fullword ascii
        $s2 = "FWPKCLNT.SYS" fullword ascii
        $s3 = "Port Layer" fullword wide
        $s4 = "%x->%x, icmp type %d, code %d" fullword ascii
        $s5 = "\\BaseNamedObjects\\{93144EB0-8E3E-4591-B307-8EEBFE7DB28E}" fullword wide
        $s6 = "\\Ndi\\Interfaces" fullword wide
        $s7 = "\\Device\\{93144EB0-8E3E-4591-B307-8EEBFE7DB28F}" fullword wide
        $s8 = "Bad packet" fullword ascii
        $s9 = "\\BaseNamedObjects\\EKV0000000000" fullword wide
        $s10 = "%x->%x" fullword ascii
        $s11 = "IPInjectPkt" fullword ascii /* Goodware String - occured 6 times */
 
    condition:
        uint16(0) == 0x5a4d and filesize < 642KB and all of them
}