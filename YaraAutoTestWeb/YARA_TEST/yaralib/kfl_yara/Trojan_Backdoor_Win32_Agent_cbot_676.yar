rule Trojan_Backdoor_Win32_Agent_cbot_676
{
    meta:
        judge = "black"
        threatname = "Trojan[Backdoor]/Win32.Agent.cbot"
        threattype = "Backdoor"
        family = "Agent"
        hacker = "None"
        author = "copy"
        refer = "8a0a5af0eb1b1605fabf54df9a299169"
        comment = "None"
        date = "2017-09-21"
        description = "None"
    strings:
        $s0 = "fMJ9V" nocase wide ascii
        $s1 = "pv:f7b" nocase wide ascii
    condition:
        all of them
}