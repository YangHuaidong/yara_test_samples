rule Trojan_Backdoor_Win32_Finfish_dkc_680
{
    meta:
        judge = "black"
        threatname = "Trojan[Backdoor]/Win32.Finfish.dkc"
        threattype = "Backdoor"
        family = "Finfish"
        hacker = "None"
        author = "copy"
        refer = "A7B990D5F57B244DD17E9A937A41E7F5"
        comment = "None"
        date = "2017-10-10"
        description = "None"
    strings:
        $s0 = "rFsDd" nocase wide ascii
        $s1 = "xMyKuP?" nocase wide ascii
        $s2 = "tfudu" nocase wide ascii
        $s3 = "zc%C1" nocase wide ascii
    condition:
        all of them
}