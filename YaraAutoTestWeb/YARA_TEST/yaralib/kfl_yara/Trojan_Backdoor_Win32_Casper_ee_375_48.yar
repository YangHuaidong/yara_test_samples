rule Trojan_Backdoor_Win32_Casper_ee_375_48
{
    meta:
        judge = "black"
        threatname = "Trojan[Backdoor]/Win32.Casper.ee"
        threattype = "Backdoor"
        family = "Casper"
        hacker = "None"
        author = "Florian Roth-copy"
        refer = "cc87d090a1607b4dde18730b79b78632"
        comment = "None"
        date = "2018-06-13"
        description = "None"
    strings:
        $s1 = "\"svchost.exe\"" fullword wide
        $s2 = "firefox.exe" fullword ascii
        $s3 = "\"Host Process for Windows Services\"" fullword wide
        $x1 = "\\Users\\*" fullword ascii
        $x2 = "\\Roaming\\Mozilla\\Firefox\\Profiles\\*" fullword ascii
        $x3 = "\\Mozilla\\Firefox\\Profiles\\*" fullword ascii
        $x4 = "\\Documents and Settings\\*" fullword ascii
        $y1 = "%s; %S=%S" fullword wide
        $y2 = "%s; %s=%s" fullword ascii
        $y3 = "Cookie: %s=%s" fullword ascii
        $y4 = "http://%S:%d" fullword wide
        $z1 = "http://google.com/" fullword ascii
        $z2 = "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; WOW64; Trident/5.0; MALC)" fullword ascii
        $z3 = "Operating System\"" fullword wide
    condition:
        ( all of ($s*) ) or ( 3 of ($x*) and 2 of ($y*) and 2 of ($z*) )
}