rule Trojan_Rootkit_Win32_Winnti_ttpztmfsa_811_641
{
    meta:
        judge = "black"
        threatname = "Trojan[Rootkit]/Win32.Winnti.ttpztmfsa"
        threattype = "Rootkit"
        family = "Winnti"
        hacker = "None"
        author = "balala"
        refer = "6668e339d1f11a724aa286593c192472,24e9870973cea42e6faf705b14208e52,422f3353164aae7afa7429e6721703cc"
        comment = "None"
        date = "2018-10-22"
        description = "None"
	strings:
        $c1 = "'Wymajtec$Tima Stempijg Sarviges GA -$G2" fullword ascii
        $c2 = "AHDNEAFE1.sys" fullword ascii
        $c3 = "SOTEFEHJ3.sys" fullword ascii
        $c4 = "MainSYS64.sys" fullword ascii
        $s1 = "\\Registry\\User\\%s\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings" fullword wide
        $s2 = "Update.dll" fullword ascii
        $s3 = "\\\\.\\pipe\\usbpcex%d" fullword wide
        $s4 = "\\\\.\\pipe\\usbpcg%d" fullword wide
        $s5 = "\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\WMI" fullword wide
        $s6 = "\\??\\pipe\\usbpcg%d" fullword wide
        $s7 = "\\??\\pipe\\usbpcex%d" fullword wide
        $s8 = "HOST: %s" fullword ascii
        $s9 = "$$$--Hello" fullword ascii
    
    condition:
        uint16(0) == 0x5a4d and filesize < 1000KB and ( ( 1 of ($c*) and 3 of ($s*) ) or all of ($s*) )
}