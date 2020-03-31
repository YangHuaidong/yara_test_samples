rule Trojan_RAT_Win32_Scar_Oc_717
{
    meta:
        judge = "black"
        threatname = "Trojan[RAT]/Win32.Scar.Oc"
        threattype = "RAT"
        family = "Scar"
        hacker = "None"
        author = "copy"
        refer = "11dd7da7faa0130dac2560930e90c8b1"
        comment = "None"
        date = "2017-09-28"
        description = "None"
    strings:
        $s0 = "zc%C1" nocase wide ascii
        $s1 = "ZwQuerySystemInformation" nocase wide ascii
        $s2 = "brbconfig.tmp" nocase wide ascii
        $s3 = "YnJiYm90" nocase wide ascii
    condition:
        all of them
}