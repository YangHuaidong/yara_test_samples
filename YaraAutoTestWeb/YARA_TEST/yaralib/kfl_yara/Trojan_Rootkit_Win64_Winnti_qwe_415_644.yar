rule Trojan_Rootkit_Win64_Winnti_qwe_415_644
{
    meta:
        judge = "black"
        threatname = "Trojan[Rootkit]/Win64.Winnti.qwe"
        threattype = "Rootkit"
        family = "Winnti"
        hacker = "None"
        author = "Florian Roth-copy"
        refer = "6668e339d1f11a724aa286593c192472"
        comment = "APT"
        date = "2018-06-20"
        description = "http://blog.airbuscybersecurity.com/post/2015/11/Newcomers-in-the-Derusbi-family"
    strings:
        $x1 = "\\\\.\\pipe\\usbpcex%d" fullword wide
        $x2 = "\\\\.\\pipe\\usbpcg%d" fullword wide
        $x3 = "\\??\\pipe\\usbpcex%d" fullword wide
        $x4 = "\\??\\pipe\\usbpcg%d" fullword wide
        $x5 = "$$$--Hello" fullword ascii
        $x6 = "Wrod--$$$" fullword ascii
        $s1 = "\\Registry\\User\\%s\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings" fullword wide
        $s2 = "Update.dll" fullword ascii
        $s3 = "\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\WMI" fullword wide
        $s4 = "\\Driver\\nsiproxy" fullword wide
        $s5 = "HOST: %s" fullword ascii

	condition:
        uint16(0) == 0x5a4d and filesize < 800KB and (2 of ($x*) or all of ($s*))
}