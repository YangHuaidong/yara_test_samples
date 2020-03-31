rule WebShell_BackDoor_Unlimit_C99Madshell_V2_0_Php_Php_A_1203 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Semi-Auto-generated  - file c99madshell_v2.0.php.php.txt"
    family = "C99Madshell"
    hacker = "None"
    hash = "d27292895da9afa5b60b9d3014f39294"
    judge = "unknown"
    reference = "None"
    threatname = "WebShell[BackDoor]/Unlimit.C99Madshell.V2.0.Php.Php.A"
    threattype = "BackDoor"
  strings:
    $s2 = "eval(gzinflate(base64_decode('HJ3HkqNQEkU/ZzqCBd4t8V4YAQI2E3jvPV8/1Gw6orsVFLyXef"
  condition:
    all of them
}