rule Trojan_Ransomware_Win32_BadRabbit_a_700
{
    meta:
        judge = "black"
        threatname = "Trojan[Ransomware]/Win32.BadRabbit.a"
        threattype = "Ransomware"
        family = "BadRabbit"
        hacker = "None"
        author = "copy"
        refer = "fbbdc39af1139aebba4da004475e8839"
        comment = "None"
        date = "2017-11-02"
        description = "None"
    strings:
        $s0 = "R1h58" nocase wide ascii
        $s1 = "Qkkbal" nocase wide ascii
        $s2 = "w+OQvr" nocase wide ascii
        $s3 = "x1B1A26b" nocase wide ascii
    condition:
        all of them
}