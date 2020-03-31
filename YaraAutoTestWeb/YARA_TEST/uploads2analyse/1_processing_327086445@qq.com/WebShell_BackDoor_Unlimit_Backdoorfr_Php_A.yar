rule WebShell_BackDoor_Unlimit_Backdoorfr_Php_A {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Semi-Auto-generated  - file backdoorfr.php.txt"
    family = "Backdoorfr"
    hacker = "None"
    hash = "91e4afc7444ed258640e85bcaf0fecfc"
    judge = "unknown"
    reference = "None"
    threatname = "WebShell[BackDoor]/Unlimit.Backdoorfr.Php.A"
    threattype = "BackDoor"
  strings:
    $s1 = "www.victime.com/index.php?page=http://emplacement_de_la_backdoor.php , ou en tan"
    $s2 = "print(\"<br>Provenance du mail : <input type=\\\"text\\\" name=\\\"provenanc"
  condition:
    1 of them
}