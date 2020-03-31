rule WebShell_BackDoor_Unlimit_Webshell_C99Madshell_V__2_0_Madnet_Edition_A_1541 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "PHP Webshells Github Archive - file C99madShell v. 2.0 madnet edition.php"
    family = "Webshell"
    hacker = "None"
    hash = "f99f8228eb12746847f54bad45084f19d1a7e111"
    judge = "unknown"
    reference = "None"
    threatname = "WebShell[BackDoor]/Unlimit.Webshell.C99Madshell.V..2.0.Madnet.Edition.A"
    threattype = "BackDoor"
  strings:
    $s0 = "$md5_pass = \"\"; //If no pass then hash" fullword
    $s1 = "eval(gzinflate(base64_decode('"
    $s2 = "$pass = \"\";  //Pass" fullword
    $s3 = "$login = \"\"; //Login" fullword
    $s4 = "//Authentication" fullword
  condition:
    all of them
}