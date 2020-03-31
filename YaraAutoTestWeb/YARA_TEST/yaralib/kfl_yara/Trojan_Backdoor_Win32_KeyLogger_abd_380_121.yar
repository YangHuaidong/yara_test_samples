rule Trojan_Backdoor_Win32_KeyLogger_abd_380_121
{
    meta:
        judge = "black"
        threatname = "Trojan[Backdoor]/Win32.KeyLogger.abd"
        threattype = "backdoor"
        family = "KeyLogger"
        hacker = "None"
        author = "Florian Roth-copy"
        refer = "0ed11a73694999bc45d18b4189f41ac2"
        comment = "http://www.spiegel.de/media/media-35668.pdf"
        date = "2018-06-20"
        description = "FiveEyes QUERTY Malware - file 20123.sys.bin"
    strings:
        $s0 = "20123.dll" fullword ascii
        $s1 = "kbdclass.sys" fullword wide
        $s2 = "IoFreeMdl" fullword ascii
        $s3 = "ntoskrnl.exe" fullword ascii
        $s4 = "KfReleaseSpinLock" fullword ascii
    condition:
        all of them

}