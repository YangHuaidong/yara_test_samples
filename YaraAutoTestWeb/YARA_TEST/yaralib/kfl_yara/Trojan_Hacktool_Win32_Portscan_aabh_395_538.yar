rule Trojan_Hacktool_Win32_Portscan_aabh_395_538
{
    meta:
        judge = "black"
        threatname = "Trojan[Hacktool]/Win32.Portscan.aabh"
        threattype = "Hacktool"
        family = "Portscan"
        hacker = "None"
        author = "Florian Roth-copy"
        refer = "3a97d9b6f17754dcd38ca7fc89caab04"
        comment = "None"
        date = "2018-06-20"
        description = "Anthem Hack Deep Panda - ScanLine sl-txt-packed"
    strings:
        $s0 = "Command line port scanner" fullword wide
        $s1 = "sl.exe" fullword wide
        $s2 = "CPports.txt" fullword ascii
        $s3 = ",GET / HTTP/.}" fullword ascii
        $s4 = "Foundstone Inc." fullword wide
        $s9 = " 2002 Foundstone Inc." fullword wide
        $s15 = ", Inc. 2002" fullword ascii
        $s20 = "ICMP Time" fullword ascii
    condition:
        all of them
}