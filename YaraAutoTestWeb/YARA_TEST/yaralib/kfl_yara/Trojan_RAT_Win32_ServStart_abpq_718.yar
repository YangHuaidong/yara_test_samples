rule Trojan_RAT_Win32_ServStart_abpq_718
{
    meta:
        judge = "black"
        threatname = "Trojan[RAT]/Win32.ServStart.abpq"
        threattype = "RAT"
        family = "ServStart"
        hacker = "None"
        author = "copy"
        refer = "2d5509cffc232392ee99706a22dbb9f9"
        comment = "None"
        date = "2017-09-14"
        description = "None"
    strings:
        $s0 = "CWaveDoc" nocase wide ascii
        $s1 = "losYA" nocase wide ascii
    condition:
        all of them
}