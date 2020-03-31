rule Trojan_Backdoor_Win32_KeyLogger_abc_379_120
{
    meta:
        judge = "black"
        threatname = "Trojan[Backdoor]/Win32.KeyLogger.abc"
        threattype = "backdoor"
        family = "KeyLogger"
        hacker = "None"
        author = "Florian Roth-copy"
        refer = "40451f20371329b992fb1b85c754d062"
        comment = "http://www.spiegel.de/media/media-35668.pdf"
        date = "2018-06-20"
        description = "FiveEyes QUERTY Malware - file 20121.dll.bin"
    strings:
        $s0 = "WarriorPride\\production2.0\\package\\E_Wzowski" ascii
        $s1 = "20121.dll" fullword ascii
    condition:
        all of them

}