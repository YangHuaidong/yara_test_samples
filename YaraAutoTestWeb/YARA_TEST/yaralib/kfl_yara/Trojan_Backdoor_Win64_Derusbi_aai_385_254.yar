rule Trojan_Backdoor_Win64_Derusbi_aai_385_254
{
    meta:
        judge = "black"
        threatname = "Trojan[Backdoor]/Win64.Derusbi.aai"
        threattype = "Backdoor"
        family = "Derusbi"
        hacker = "None"
        author = "Florian Roth-copy"
        refer = "a35b22e2743bf9206b06cbd8f80fe29a"
        comment = "https://www.proofpoint.com/us/exploring-bergard-old-malware-new-tricks"
        date = "2018-06-13"
        description = "Codoso CustomTCP Malware"
    strings:
        $s4 = "wnyglw" fullword ascii
        $s5 = "WorkerRun" fullword ascii
        $s7 = "boazdcd" fullword ascii
        $s8 = "wayflw" fullword ascii
        $s9 = "CODETABL" fullword ascii
    condition:
        uint16(0) == 0x5a4d and filesize < 405KB and all of them
}