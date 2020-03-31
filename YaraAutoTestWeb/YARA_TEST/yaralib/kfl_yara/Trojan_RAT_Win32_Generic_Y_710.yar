rule Trojan_RAT_Win32_Generic_710
{
    meta:
        judge = "black"
        threatname = "Trojan[RAT]/Win32.Generic"
        threattype = "RAT"
        family = "Generic"
        hacker = "None"
        author = "copy"
        refer = "14d996266926bf59ae3d99ff79d3c717"
        comment = "None"
        date = "2017-07-26"
        description = "None"
    strings:
        $s0 = "C:\\Yuemingl.txt" nocase wide ascii
        $s1 = "Hotkey" nocase wide ascii
        $s2 = "%.f|%d%%" nocase wide ascii
        $s3 = "D:\\hackshen.exe" nocase wide ascii
    condition:
        all of them
}