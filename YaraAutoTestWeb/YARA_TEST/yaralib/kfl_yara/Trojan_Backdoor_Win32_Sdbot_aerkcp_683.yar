rule Trojan_Backdoor_Win32_Sdbot_aerkcp_683
{
    meta:
        judge = "black"
        threatname = "Trojan[Backdoor]/Win32.Sdbot.aerkcp"
        threattype = "Backdoor"
        family = "Sdbot"
        hacker = "None"
        author = "copy"
        refer = "1aa8049840f7ea8911b78b937c5ee78e"
        comment = "None"
        date = "2017-09-14"
        description = "None"
    strings:
        $s0 = "SeBackupPrivilege" nocase wide ascii
        $s1 = "COMMAND_DDOS_GET" nocase wide ascii
        $s2 = "config.ini" nocase wide ascii
    condition:
        all of them
}