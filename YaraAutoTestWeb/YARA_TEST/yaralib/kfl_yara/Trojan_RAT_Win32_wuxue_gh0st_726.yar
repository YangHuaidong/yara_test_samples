rule Trojan_RAT_Win32_wuxue_gh0st_726
{
    meta:
        judge = "black"
        threatname = "Trojan[RAT]/Win32.wuxue.gh0st"
        threattype = "RAT"
        family = "wuxue"
        hacker = "None"
        author = "copy"
        refer = "c03016e216f408a8e9f7b18f1c7842fe"
        comment = "None"
        date = "2017-08-05"
        description = "None"
    strings:
        $s0 = "hhctrl.ocx" nocase wide ascii
        $s1 = "Apartment" nocase wide ascii
        $s2 = "wSh]h6" nocase wide ascii
    condition:
        all of them
}