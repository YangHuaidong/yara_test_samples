rule Trojan_Hacktool_Win32_PWDump_aabj_396_540
{
    meta:
        judge = "black"
        threatname = "Trojan[Hacktool]/Win32.PWDump.aabj"
        threattype = "Hacktool"
        family = "PWDump"
        hacker = "None"
        author = "Florian Roth-copy"
        refer = "3d16542d4ee5c8f77e6c0281d283c7bc"
        comment = "None"
        date = "2018-06-20"
        description = "Anthem Hack Deep Panda - lot1.tmp-pwdump"
    strings:
        $s0 = "Unable to open target process: %d, pid %d" fullword ascii
        $s1 = "Couldn't delete target executable from remote machine: %d" fullword ascii
        $s2 = "Target: Failed to load SAM functions." fullword ascii
        $s5 = "Error writing the test file %s, skipping this share" fullword ascii
        $s6 = "Failed to create service (%s/%s), error %d" fullword ascii
        $s8 = "Service start failed: %d (%s/%s)" fullword ascii
        $s12 = "PwDump.exe" fullword ascii
        $s13 = "GetAvailableWriteableShare returned an error of %ld" fullword ascii
        $s14 = ":\\\\.\\pipe\\%s" fullword ascii
        $s15 = "Couldn't copy %s to destination %s. (Error %d)" fullword ascii
        $s16 = "dump logon session" fullword ascii
        $s17 = "Timed out waiting to get our pipe back" fullword ascii
        $s19 = "SetNamedPipeHandleState failed, error %d" fullword ascii
        $s20 = "%s\\%s.exe" fullword ascii
    condition:
        10 of them
}