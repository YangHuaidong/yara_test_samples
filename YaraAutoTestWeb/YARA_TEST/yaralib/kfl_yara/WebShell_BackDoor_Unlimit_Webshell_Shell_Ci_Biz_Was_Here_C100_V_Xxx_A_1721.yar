rule WebShell_BackDoor_Unlimit_Webshell_Shell_Ci_Biz_Was_Here_C100_V_Xxx_A_1721 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2014/01/28"
    description = "Web Shell - from files Shell [ci] .Biz was here.php, c100 v. 777shell v. Undetectable #18a Modded by 777 - Don.php, c99-shadows-mod.php"
    family = "Webshell"
    hacker = "None"
    hash0 = "f2fa878de03732fbf5c86d656467ff50"
    hash1 = "27786d1e0b1046a1a7f67ee41c64bf4c"
    hash2 = "68c0629d08b1664f5bcce7d7f5f71d22"
    judge = "unknown"
    reference = "None"
    score = 70
    super_rule = 1
    threatname = "WebShell[BackDoor]/Unlimit.Webshell.Shell.Ci.Biz.Was.Here.C100.V.Xxx.A"
    threattype = "BackDoor"
  strings:
    $s2 = "if ($data{0} == \"\\x99\" and $data{1} == \"\\x01\") {return \"Error: \".$stri"
    $s3 = "<OPTION VALUE=\"find /etc/ -type f -perm -o+w 2> /dev/null\""
    $s4 = "<OPTION VALUE=\"cat /proc/version /proc/cpuinfo\">CPUINFO" fullword
    $s7 = "<OPTION VALUE=\"wget http://ftp.powernet.com.tr/supermail/de"
    $s9 = "<OPTION VALUE=\"cut -d: -f1,2,3 /etc/passwd | grep ::\">USER"
  condition:
    2 of them
}