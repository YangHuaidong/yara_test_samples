rule WebShell_BackDoor_Unlimit_Webshell_Webshell_123_A_1739 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2014/03/28"
    description = "Web shells - generated from file webshell-123.php"
    family = "Webshell"
    hacker = "None"
    hash = "2782bb170acaed3829ea9a04f0ac7218"
    judge = "unknown"
    reference = "None"
    score = 70
    threatname = "WebShell[BackDoor]/Unlimit.Webshell.Webshell.123.A"
    threattype = "BackDoor"
  strings:
    $s0 = "// Web Shell!!" fullword
    $s1 = "@preg_replace(\"/.*/e\",\"\\x65\\x76\\x61\\x6C\\x28\\x67\\x7A\\x69\\x6E\\x66\\x6"
    $s3 = "$default_charset = \"UTF-8\";" fullword
    $s4 = "// url:http://www.weigongkai.com/shell/" fullword
  condition:
    2 of them
}