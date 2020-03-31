rule Trojan_RAT_Win32__Tepfer_ah_728
{
    meta:
        judge = "black"
        threatname = "Trojan[RAT]/Win32.Tepfer.ah"
        threattype = "RAT"
        family = "Tepfer"
        hacker = "None"
        author = "copy"
        refer = "bef104beac03466e3c73761223941c65"
        comment = "None"
        date = "2017-08-23"
        description = "None"
    strings:
        $s0 = "stafftest.ru" nocase wide ascii
        $s1 = "hrtests.ru" nocase wide ascii
        $s2 = "libgcj-13.dll" nocase wide ascii
        $s3 = "Photo.scr" nocase wide ascii
    condition:
        all of them
}