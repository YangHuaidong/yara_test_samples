rule Trojan_RAT_Win32_Generic_705
{
    meta:
        judge = "black"
        threatname = "Trojan[RAT]/Win32.Generic"
        threattype = "RAT"
        family = "Generic"
        hacker = "None"
        author = "copy"
        refer = "4936e38a73ce07eccf0bb0f0cad2afe9"
        comment = "None"
        date = "2017-07-27"
        description = "None"
    strings:
        $s0 = "9PT0vef" nocase wide ascii
        $s1 = "sa+utJ8" nocase wide ascii
        $s2 = "tyrij" nocase wide ascii
    condition:
        all of them
}