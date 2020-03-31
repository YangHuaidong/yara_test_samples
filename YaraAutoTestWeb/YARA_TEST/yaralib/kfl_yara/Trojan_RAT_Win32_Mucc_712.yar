rule Trojan_RAT_Win32_Mucc_712
{
    meta:
        judge = "black"
        threatname = "Trojan[RAT]/Win32.Mucc"
        threattype = "RAT"
        family = "Mucc"
        hacker = "None"
        author = "copy"
        refer = "19697676f886485b02b62ac3eeb29a26"
        comment = "None"
        date = "2017-07-26"
        description = "None"
    strings:
        $s0 = "NewTest.dat" nocase wide ascii
        $s1 = "tyrij" nocase wide ascii
        $s2 = "9O7mtbWvr70FsLCxsb39AvOf" nocase wide ascii
        $s3 = "3gEAAwIFv9f2" nocase wide ascii
        $s4 = "8wLw870C5wKf" nocase wide ascii
    condition:
        all of them
}