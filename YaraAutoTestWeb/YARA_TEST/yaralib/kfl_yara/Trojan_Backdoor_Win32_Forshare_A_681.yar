rule Trojan_Backdoor_Win32_Forshare_A_681
{
    meta:
        judge = "black"
        threatname = "Trojan[Backdoor]/Win32.Forshare.A"
        threattype = "Backdoor"
        family = "Forshare"
        hacker = "None"
        author = "copy"
        refer = "b6b68faa706f7740dafd8941c4c5e35a"
        comment = "None"
        date = "2017-09-26"
        description = "None"
    strings:
        $s0 = "inWMI" nocase wide ascii
        $s1 = "http://down.mysking.info:8888/ok.txt" nocase wide ascii
        $s2 = "down10.pdb" nocase wide ascii
    condition:
        all of them
}